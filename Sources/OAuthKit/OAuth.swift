//
//  OAuth.swift
//
//
//  Created by Kevin McKee
//
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
import Observation

/// The default file name that holds the list of providers.
private let defaultResourceName = "oauth"
/// The default file extension.
private let defaultExtension = "json"
/// The reason displayed when the OS authenticates a protected Keychain read.
private let defaultKeychainAuthenticationReason = "Unlock OAuth credentials"

/// Provides an enum of oauth errors.
public enum OAError: Error {
    /// An error occurred while building a request url
    case malformedURL
    /// An error occurred while loading data from a request
    case badResponse
    /// Unable to decode a response from a provider into an expected type.
    case decoding
    /// Unable to write data to the keychain
    case keychain
    /// The client classification or authentication policy does not permit the request.
    case invalidClientConfiguration
}

/// Provides an `Observable` OAuth 2.0 implementation that emits ``OAuth/state`` changes when
/// an authorization flow is started by calling ``OAuth/authorize(provider:grantType:)``.
@MainActor
@Observable
public final class OAuth: Sendable {

    /// An observable list of available OAuth providers to choose from.
    public var providers = [Provider]()

    /// An observable oauth state.
    public var state: State = .empty

    /// The url session to use for communicating with providers.
    @ObservationIgnored
    public var urlSession: URLSession = .init(configuration: .ephemeral)

    @ObservationIgnored
    var keychain: Keychain = .default

    #if os(macOS) || os(iOS) || os(visionOS)
    @ObservationIgnored
    var context: LAContext = .init()


    #endif

    private var tasks = [UUID: Task<Void, Never>]()

    @ObservationIgnored
    var generation: UInt64 = 0

    @ObservationIgnored
    var refreshTasks = [String: Task<Void, Never>]()
    @ObservationIgnored
    private var refreshIDs = [String: UUID]()

    @ObservationIgnored
    private let networkMonitor: NetworkMonitor = .shared

    /// Configuration option determining if tokens should be auto refreshed or not.
    @ObservationIgnored
    private var autoRefresh: Bool = false

    /// Configuration option determining if the WKWebsiteDataStore used during authorization flows should use an ephemeral datastore.
    /// Set to true if you wish to implement private browsing and force a new login attempt every time an authorization flow is started.
    @ObservationIgnored
    var useNonPersistentWebDataStore: Bool = false


    /// The json decoder
    @ObservationIgnored
    private let decoder: JSONDecoder = .init()

    /// Initializes the OAuth service with the specified providers and configuration options.
    /// - Parameters:
    ///   - providers: the list of oauth providers
    ///   - options: the configuration options to apply
    public init(providers: [Provider] = [Provider](), options: [Option: Any]? = nil) {
        self.providers = providers
        configure(options)
    }

    /// Uses an explicit storage dependency without changing the public configuration API.
    init(providers: [Provider], keychain: Keychain, options: [Option: Any]? = nil) {
        self.providers = providers
        self.keychain = keychain
        configure(options)
    }

    /// Common Initializer that attempts to load an `oauth.json` file from the specified bundle.
    /// - Parameters:
    ///   - bundle: the bundle to load the oauth provider configuration information from.
    ///   - options: the configuration options to apply
    public init(_ bundle: Bundle, options: [Option: Any]? = nil) {
        self.providers = loadProviders(bundle)
        configure(options)
    }
}

public extension OAuth {

    /// Generates a cryptographically secure random Base 64 URL encoded string.
    /// - Parameter count: the byte count
    /// - Returns: a cryptographically secure random Base 64 URL encoded string
    static func secureRandom(count: Int = 32) -> String {
        .secureRandom(count: count)
    }

    /// Starts the authorization process for the specified provider.
    /// - Parameters:
    ///   - provider: the provider to begin authorization for
    ///   - grantType: the grant type to execute
    func authorize(provider: Provider, grantType: GrantType = .pkce(.init())) {
        supersedeTasks()
        switch grantType {
        case .authorizationCode:
            state = .authorizing(provider, grantType)
        case .pkce:
            state = .authorizing(provider, grantType)
        case .deviceCode:
            state = .requestingDeviceCode(provider)
            task { [self] in
                await requestDeviceCode(provider: provider)
            }
        case .clientCredentials:
            guard provider.clientType == .confidential else {
                return publish(state: .error(provider, .invalidClientConfiguration))
            }
            task { [self] in
                await requestClientCredentials(provider: provider)
            }
        case .refreshToken:
            task { [self] in
                await refreshToken(provider: provider)
            }
        }
    }

    /// Requests to exchange a code for an access token.
    /// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    /// - Parameters:
    ///   - provider: the provider the access token is being requested from
    ///   - code: the code to exchange
    ///   - pkce: the pkce data
    func token(provider: Provider, code: String, pkce: PKCE? = nil) {
        task { [self] in
            await requestToken(provider: provider, code: code, pkce: pkce)
        }
    }

    /// Removes this client's stored tokens. State becomes empty only after confirmed deletion.
    /// - Throws: The storage error when deletion fails, leaving the current state unchanged.
    func clear() throws {
        supersedeTasks()
        guard try keychain.clear() else { throw OAError.keychain }
        state = .empty
    }

    /// Invalidates asynchronous work started by an earlier authorization flow.
    func supersedeTasks() {
        generation &+= 1
        for task in tasks.values { task.cancel() }
        tasks.removeAll()
        for task in refreshTasks.values { task.cancel() }
        refreshTasks.removeAll()
        refreshIDs.removeAll()
    }
}

// MARK: Private

private extension OAuth {

    /// Loads providers from the specified bundle.
    /// - Parameter bundle: the bundle to load the oauth provider configuration information from.
    /// - Returns: found providers in the specifed bundle or an empty list if not found
    func loadProviders(_ bundle: Bundle) -> [Provider] {
        guard let url = bundle.url(forResource: defaultResourceName, withExtension: defaultExtension),
              let data = try? Data(contentsOf: url),
              let providers = try? decoder.decode([Provider].self, from: data) else {
            return []
        }
        return providers
    }

    /// Loads authorizations from the keychain.
    func loadAuthorizations() {
        for provider in providers {
            do {
                if let authorization: OAuth.Authorization = try keychain.get(key: provider.id) {
                    publish(state: .authorized(provider, authorization))
                }
            } catch {
                publish(state: .error(provider, .keychain))
            }
        }
    }

    /// Configures the oauth client from options.
    /// - Parameter options: the options to apply to this oauth client
    func configure(_ options: [Option: Any]?) {
        // Override from options
        if let options {

            // Override token auto refresh
            if let autoRefresh = options[.autoRefresh] as? Bool {
                self.autoRefresh = autoRefresh
            }

            // Ephemeral web data store
            if let useNonPersistentWebDataStore = options[.useNonPersistentWebDataStore] as? Bool {
                self.useNonPersistentWebDataStore = useNonPersistentWebDataStore
            }


            // Override the local authentication context
            #if os(macOS) || os(iOS) || os(visionOS)
            if let context = options[.localAuthentication] as? LAContext {
                self.context = context
            }
            #endif

            // Override the url session
            if let urlSession = options[.urlSession] as? URLSession {
                self.urlSession = urlSession
            }

            // Override the keychain to use the custom application tag
            if let applicationTag = options[.applicationTag] as? String, applicationTag.isNotEmpty {
                self.keychain = .init(applicationTag)
            }
        }
        #if canImport(Security)
        keychain.requiresAuthentication = options?[.requireBiometricAuthentication] as? Bool ?? false
        #if os(macOS) || os(iOS) || os(visionOS)
        if context.localizedReason.isEmpty {
            context.localizedReason = defaultKeychainAuthenticationReason
        }
        keychain.authenticationContext = context
        #endif
        #else
        if options?[.requireBiometricAuthentication] as? Bool == true {
            for provider in providers {
                publish(state: .error(provider, .keychain))
            }
            return
        }
        #endif
        monitor()
        loadAuthorizations()
    }


    /// Starts the network monitor.
    func monitor() {
        task { [self] in
            await networkMonitor.start()
        }
    }

    /// Publishes state on the main thread.
    /// - Parameter state: the new state information to publish out on the main thread.
    func publish(state: State) {
        switch state {
        case .authorized(let provider, let auth):
            schedule(provider: provider, auth: auth)
        case .receivedDeviceCode(let provider, let deviceCode):
            schedule(provider: provider, deviceCode: deviceCode)
        case .empty, .error, .authorizing, .requestingAccessToken, .requestingDeviceCode:
            break
        }
        self.state = state
    }

    /// Schedules the provider to be polled for authorization with the specified device token.
    /// - Parameters:
    ///   - provider: the oauth provider
    ///   - deviceCode: the device code issued by the provider
    func schedule(provider: Provider, deviceCode: DeviceCode) {
        let timeInterval = TimeInterval(deviceCode.interval)
        let id = UUID()
        let handle = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(timeInterval))
            guard let self, !Task.isCancelled else { return }
            await poll(provider: provider, deviceCode: deviceCode)
            tasks.removeValue(forKey: id)
        }
        tasks[id] = handle
    }

    /// Schedules refresh tasks for the specified authorization.
    /// - Parameters:
    ///   - provider: the oauth provider
    ///   - auth: the authentication to schedule a future tasks for
    func schedule(provider: Provider, auth: Authorization) {
        // Don't bother scheduling a task for tokens that can't refresh
        guard let _ = auth.token.refreshToken else { return }

        if autoRefresh {
            if let expiration = auth.expiration {
                let timeInterval = expiration - Date.now
                if timeInterval > 0 {
                    // Schedule the auto refresh task
                    let id = UUID()
                    let task = Task { @MainActor [weak self] in
                        try? await Task.sleep(for: .seconds(timeInterval))
                        guard let self, !Task.isCancelled else { return }
                        await refreshToken(provider: provider)
                        tasks.removeValue(forKey: id)
                    }
                    tasks[id] = task
                } else {
                    // Execute the task immediately
                    task { [self] in
                        await refreshToken(provider: provider)
                    }
                }
            }
        }
    }

    /// Create and immediately start running a new detached task in the context of this actor.
    /// - Parameters:
    ///   - priority: the task priority
    func task(priority: TaskPriority = .high, operation: @escaping @MainActor () async -> Void) {
        let id = UUID()
        let taskGeneration = generation
        let handle = Task { @MainActor [weak self] in
            guard let self, generation == taskGeneration, !Task.isCancelled else { return }
            await operation()
            tasks.removeValue(forKey: id)
        }
        tasks[id] = handle
    }
}

// MARK: URLRequests

extension OAuth {

    /// Requests to exchange a code for an access token.
    /// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    /// - Parameters:
    ///   - provider: the provider the access token is being requested from
    ///   - code: the code to exchange
    ///   - pkce: the PKCE data to pass along with the request
    func requestToken(provider: Provider, code: String, pkce: PKCE? = nil) async {
        let transaction = generation
        // Publish the state
        publish(state: .requestingAccessToken(provider))

        guard let request = Request.token(provider: provider, code: code, pkce: pkce) else {
            return publish(state: .error(provider, .malformedURL))
        }

        guard let (data, response) = try? await urlSession.data(for: request, delegate: OAuthRedirectDelegate.shared) else {
            guard transaction == generation, !Task.isCancelled else { return }
            return publish(state: .error(provider, .badResponse))
        }
        guard transaction == generation, !Task.isCancelled else { return }

        if provider.debug {
            let statusCode = response.statusCode() ?? -1
            let rawData = String(data: data, encoding: .utf8) ?? .empty
            debugPrint("Response: [\(statusCode))]", "Data: [\(rawData)]")
        }

        // Decode the token
        guard response.isOK, let token = try? decoder.decode(Token.self, from: data) else {
            return publish(state: .error(provider, .decoding))
        }

        // Store the authorization
        let authorization = Authorization(issuer: provider.id, token: token)
        guard let stored = try? keychain.set(authorization, for: authorization.issuer), stored else {
            return publish(state: .error(provider, .keychain))
        }

        publish(state: .authorized(provider, authorization))
    }

    /// Refreshes the token for the specified provider.
    /// See: https://datatracker.ietf.org/doc/html/rfc6749#section-6
    /// - Parameters:
    ///   - provider: the provider to request a refresh token for
    func refreshToken(provider: Provider) async {
        let key = provider.id
        if let active = refreshTasks[key] {
            await active.value
            return
        }
        let id = UUID()
        let expectedGeneration = generation
        refreshIDs[key] = id
        let active = Task { @MainActor [weak self] in
            await self?.performRefreshToken(provider: provider, expectedGeneration: expectedGeneration)
        }
        refreshTasks[key] = active
        await active.value
        if refreshIDs[key] == id {
            refreshIDs.removeValue(forKey: key)
            refreshTasks.removeValue(forKey: key)
        }
    }

    private func performRefreshToken(provider: Provider, expectedGeneration: UInt64) async {
        let storedAuthorization: Authorization?
        do {
            storedAuthorization = try keychain.get(key: provider.id)
        } catch {
            return publish(state: .error(provider, .keychain))
        }
        guard let auth = storedAuthorization else { return }

        // If we can't build a refresh request simply bail as no refresh token
        // was returned in the original auth request
        guard let request = Request.refresh(provider: provider, token: auth.token) else {
            if auth.isExpired {
                do { try clear() }
                catch { publish(state: .error(provider, .keychain)) }
            }
            return
        }

        guard let (data, response) = try? await urlSession.data(for: request, delegate: OAuthRedirectDelegate.shared) else {
            guard expectedGeneration == generation, !Task.isCancelled else { return }
            return publish(state: .error(provider, .badResponse))
        }
        guard expectedGeneration == generation, !Task.isCancelled else { return }

        if provider.debug {
            let statusCode = response.statusCode() ?? -1
            let rawData = String(data: data, encoding: .utf8) ?? .empty
            debugPrint("Response: [\(statusCode))]", "Data: [\(rawData)]")
        }

        // Decode the token
        guard response.isOK, let token = try? decoder.decode(Token.self, from: data) else {
            return publish(state: .error(provider, .decoding))
        }

        // Store the authorization
        let authorization = Authorization(issuer: provider.id, token: token)
        guard let stored = try? keychain.set(authorization, for: authorization.issuer), stored else {
            return publish(state: .error(provider, .keychain))
        }
        publish(state: .authorized(provider, authorization))
    }

    /// Requests a device code from the specified provider.
    /// - Parameters:
    ///   - provider: the provider the device code is being requested from
    func requestDeviceCode(provider: Provider) async {
        let transaction = generation
        guard let request = Request.device(provider: provider) else {
            return publish(state: .error(provider, .malformedURL))
        }
        guard let (data, response) = try? await urlSession.data(for: request, delegate: OAuthRedirectDelegate.shared) else {
            return publish(state: .error(provider, .badResponse))
        }
        guard transaction == generation, !Task.isCancelled else { return }

        if provider.debug {
            let statusCode = response.statusCode() ?? -1
            let rawData = String(data: data, encoding: .utf8) ?? .empty
            debugPrint("Response: [\(statusCode))]", "Data: [\(rawData)]")
        }

        // Decode the device code
        guard response.isOK, let deviceCode = try? decoder.decode(DeviceCode.self, from: data) else {
            return publish(state: .error(provider, .decoding))
        }

        // Publish the state
        publish(state: .receivedDeviceCode(provider, deviceCode))
    }

    /// Makes a client credentials request grant request from the specified provider.
    /// - Parameters:
    ///   - provider: the provider the device code is being requested from
    func requestClientCredentials(provider: Provider) async {
        let transaction = generation
        guard let request = Request.token(provider: provider) else {
            return publish(state: .error(provider, .invalidClientConfiguration))
        }
        guard let (data, response) = try? await urlSession.data(for: request, delegate: OAuthRedirectDelegate.shared) else {
            return publish(state: .error(provider, .badResponse))
        }
        guard transaction == generation, !Task.isCancelled else { return }

        if provider.debug {
            let statusCode = response.statusCode() ?? -1
            let rawData = String(data: data, encoding: .utf8) ?? .empty
            debugPrint("Response: [\(statusCode))]", "Data: [\(rawData)]")
        }

        // Decode the token
        guard response.isOK, let token = try? decoder.decode(Token.self, from: data) else {
            return publish(state: .error(provider, .decoding))
        }

        // Store the authorization
        let authorization = Authorization(issuer: provider.id, token: token)
        guard let stored = try? keychain.set(authorization, for: authorization.issuer), stored else {
            return publish(state: .error(provider, .keychain))
        }
        publish(state: .authorized(provider, authorization))
    }

    /// Polls the oauth provider's access token endpoint until the device code has expired or we've successfully received an auth token.
    /// See: https://oauth.net/2/grant-types/device-code/
    /// - Parameters:
    ///   - provider: the provider to poll
    ///   - deviceCode: the device code to use
    func poll(provider: Provider, deviceCode: DeviceCode) async {
        let transaction = generation

        guard !deviceCode.isExpired, let request = Request.token(provider: provider, deviceCode: deviceCode) else {
            return publish(state: .error(provider, .malformedURL))
        }

        guard let (data, response) = try? await urlSession.data(for: request, delegate: OAuthRedirectDelegate.shared) else {
            return publish(state: .error(provider, .badResponse))
        }
        guard transaction == generation, !Task.isCancelled else { return }

        if provider.debug {
            let statusCode = response.statusCode() ?? -1
            let rawData = String(data: data, encoding: .utf8) ?? .empty
            debugPrint("Response: [\(statusCode))]", "Data: [\(rawData)]")
        }

        /// If we received something other than a 200 response or we can't decode the token then restart the polling
        guard response.isOK, let token = try? decoder.decode(Token.self, from: data) else {
            // Reschedule the polling task
            return schedule(provider: provider, deviceCode: deviceCode)
        }

        // Store the authorization
        let authorization = Authorization(issuer: provider.id, token: token)
        guard let stored = try? keychain.set(authorization, for: authorization.issuer), stored else {
            return publish(state: .error(provider, .keychain))
        }
        publish(state: .authorized(provider, authorization))
    }
}
