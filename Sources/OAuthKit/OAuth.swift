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
private struct OAuthErrorResponse: Decodable {
    let error: String
}

/// Provides an enum of oauth errors.
public enum OAError: Error, Equatable, Sendable {
    /// An error occurred while building a request url
    case malformedURL
    /// An error occurred while loading data from a request
    case badResponse
    /// Unable to decode a response from a provider into an expected type.
    case decoding
    /// The device code has expired.
    case expiredDeviceCode
    /// The authorization server returned an OAuth error.
    case oauth(String)
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
    @ObservationIgnored
    private var monitorTask: Task<Void, Never>?

    /// Configuration option determining if tokens should be auto refreshed or not.
    @ObservationIgnored
    private var autoRefresh: Bool = false

    /// Explicit opt-in to persistent cookies in the system browser session.
    @ObservationIgnored
    var persistBrowserSession: Bool = false


    @ObservationIgnored
    private var pendingAuthorization: OAuthPendingAuthorization?
    internal var authorizationGeneration: UInt64 = 0

    /// The json decoder
    @ObservationIgnored
    private let decoder: JSONDecoder = .init()
    @ObservationIgnored
    var diagnosticOutput: (String) -> Void = { debugPrint($0) }

    /// Injectable device-poll delay for deterministic polling tests.
    @ObservationIgnored
    var devicePollingSleep: @MainActor (Duration) async throws -> Void = { duration in
        try await Task.sleep(for: duration)
    }

    @ObservationIgnored
    var devicePollingNow: @MainActor () -> ContinuousClock.Instant = { ContinuousClock().now }

    @ObservationIgnored
    var devicePollingDate: @MainActor () -> Date = { Date.now }

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
private struct OAuthPendingAuthorization {
    let provider: OAuth.Provider
    let pkce: OAuth.PKCE
    let generation: UInt64

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
    func authorize(provider: Provider, grantType: GrantType = .authorizationCode) {
        switch grantType {
        case .authorizationCode:
            supersedeTasks()
            pendingAuthorization = nil
            authorizationGeneration &+= 1
            guard provider.redirectURI != nil,
                  isValidRegisteredRedirect(provider.redirectURI),
                  (provider.issuer == nil || isCanonicalIssuer(provider.issuer!)),
                  provider.issuer != nil || providers.allSatisfy({ candidate in
                      candidate.id == provider.id ||
                      (candidate.authorizationURL.absoluteString == provider.authorizationURL.absoluteString &&
                       candidate.accessTokenURL.absoluteString == provider.accessTokenURL.absoluteString) ||
                      !redirectURIsEquivalent(candidate.redirectURI, provider.redirectURI)
                  }) else {
                state = .error(provider, .malformedURL)
                return
            }
            let pkce = PKCE()
            pendingAuthorization = OAuthPendingAuthorization(
                provider: provider,
                pkce: pkce,
                generation: authorizationGeneration
            )
            state = .authorizing(provider, .authorizationCode)
        case .deviceCode:
            supersedeTasks()
            pendingAuthorization = nil
            authorizationGeneration &+= 1
            state = .requestingDeviceCode(provider)
            task { [self] in
                await requestDeviceCode(provider: provider)
            }
        case .clientCredentials:
            supersedeTasks()
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

    internal var activeAuthorizationURL: URL? {
        guard let pendingAuthorization else { return nil }
        return Request.auth(provider: pendingAuthorization.provider, pkce: pendingAuthorization.pkce)?.url
    }

    internal var activeAuthorizationProvider: Provider? {
        pendingAuthorization?.provider
    }

    internal var activeAuthorizationGeneration: UInt64? {
        pendingAuthorization?.generation
    }

    internal func failDeviceAuthorization(provider: Provider) {
        state = .error(provider, .badResponse)
    }
    internal func cancelAuthorization() {
        guard let pendingAuthorization else { return }
        cancelAuthorization(generation: pendingAuthorization.generation)
    }

    internal func cancelAuthorization(generation: UInt64) {
        guard pendingAuthorization?.generation == generation else { return }
        pendingAuthorization = nil
        authorizationGeneration &+= 1
        supersedeTasks()
        state = .empty
    }

    /// Validates and consumes the active authorization callback before exchanging its code.
    @discardableResult
    func handleAuthorizationCallback(_ url: URL, generation: UInt64? = nil) -> Bool {
        guard let transaction = pendingAuthorization,
              generation == nil || generation == transaction.generation,
              let redirectURI = transaction.provider.redirectURI,
              let redirect = URLComponents(string: redirectURI),
              let callback = URLComponents(url: url, resolvingAgainstBaseURL: false),
              redirectComponentsMatch(callback, redirect),
              let callbackItems = formQueryItems(callback.percentEncodedQuery),
              let redirectItems = formQueryItems(redirect.percentEncodedQuery) else { return false }
        let provider = transaction.provider
        let pkce = transaction.pkce
        let names = callbackItems.map(\.name)
        let stateItems = callbackItems.filter { $0.name == "state" }
        let codeItems = callbackItems.filter { $0.name == "code" }
        let errorItems = callbackItems.filter { $0.name == "error" }
        let issuerItems = callbackItems.filter { $0.name == "iss" }
        let hasCode = codeItems.count == 1 && codeItems[0].value?.isEmpty == false && errorItems.isEmpty
        let hasError = errorItems.count == 1 && errorItems[0].value?.isEmpty == false && codeItems.isEmpty
        guard Set(names).count == names.count,
              stateItems.count == 1,
              stateItems[0].value == pkce.state,
              hasCode || hasError,
              issuerItems.count <= 1 else { return false }
        if let issuer = provider.issuer {
            guard isCanonicalIssuer(issuer), issuerItems.count == 1, issuerItems[0].value == issuer else { return false }
        } else if !issuerItems.isEmpty {
            return false
        }
        for item in redirectItems {
            let matches = callbackItems.filter { $0.name == item.name }
            guard matches.count == 1, matches[0].value == item.value else { return false }
        }
        supersedeTasks()
        pendingAuthorization = nil
        if hasCode, let code = codeItems.first?.value {
            state = .requestingAccessToken(provider)
            task { [self] in
                await requestToken(provider: provider, code: code, pkce: pkce)
            }
        } else {
            state = .error(provider, .badResponse)
        }
        return true
    }

    private func formQueryItems(_ rawQuery: String?) -> [URLQueryItem]? {
        guard let rawQuery else { return [] }
        var items = [URLQueryItem]()
        for pair in rawQuery.split(separator: "&", omittingEmptySubsequences: false) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let rawName = String(parts[0]).replacingOccurrences(of: "+", with: " ")
            let rawValue = parts.count == 2 ? String(parts[1]).replacingOccurrences(of: "+", with: " ") : ""
            guard let name = rawName.removingPercentEncoding,
                  let value = rawValue.removingPercentEncoding else { return nil }
            items.append(URLQueryItem(name: name, value: value))
        }
        return items
    }
    private func isValidRegisteredRedirect(_ value: String?) -> Bool {
        guard let value,
              let components = URLComponents(string: value),
              components.scheme?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              let items = formQueryItems(components.percentEncodedQuery) else { return false }
        let names = items.map(\.name)
        let reserved = Set(["state", "code", "iss", "error", "error_description", "error_uri"])
        return Set(names).count == names.count && names.allSatisfy { !reserved.contains($0) }
    }

    private func normalizedRedirectPort(_ components: URLComponents) -> Int? {
        if let port = components.port { return port }
        switch components.scheme?.lowercased() {
        case "http": return 80
        case "https": return 443
        default: return nil
        }
    }

    private func redirectComponentsMatch(_ left: URLComponents, _ right: URLComponents) -> Bool {
        left.scheme?.lowercased() == right.scheme?.lowercased() &&
            left.host?.lowercased() == right.host?.lowercased() &&
            normalizedRedirectPort(left) == normalizedRedirectPort(right) &&
            left.percentEncodedPath == right.percentEncodedPath &&
            left.user == nil && left.password == nil && left.fragment == nil &&
            right.user == nil && right.password == nil && right.fragment == nil
    }

    private func redirectURIsEquivalent(_ lhs: String?, _ rhs: String?) -> Bool {
        guard let lhs, let rhs,
              let left = URLComponents(string: lhs),
              let right = URLComponents(string: rhs),
              redirectComponentsMatch(left, right),
              let leftItems = formQueryItems(left.percentEncodedQuery),
              let rightItems = formQueryItems(right.percentEncodedQuery) else { return lhs == rhs }
        guard leftItems.count == rightItems.count,
              Set(leftItems.map(\.name)).count == leftItems.count,
              Set(rightItems.map(\.name)).count == rightItems.count else { return false }
        return leftItems.allSatisfy { item in
            rightItems.first(where: { $0.name == item.name })?.value == item.value
        }
    }
    private func isCanonicalIssuer(_ issuer: String) -> Bool {
        guard let components = URLComponents(string: issuer),
              components.scheme == "https",
              components.host?.isEmpty == false,
              components.query == nil,
              components.fragment == nil,
              components.user == nil,
              components.password == nil else { return false }
        return true
    }

    private func logResponse(_ operation: String, response: URLResponse, provider: Provider) {
        guard provider.debug else { return }
        diagnosticOutput("OAuth \(operation) response status: \(response.statusCode() ?? -1), provider: \(provider.id)")
    }
    /// Requests to exchange a code for an access token.
    /// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    /// - Parameters:
    ///   - provider: the provider the access token is being requested from
    ///   - code: the code to exchange
    ///   - pkce: the pkce data
    internal func token(provider: Provider, code: String, pkce: PKCE? = nil) {
        task { [self] in
            await requestToken(provider: provider, code: code, pkce: pkce)
        }
    }

    /// Removes this client's stored tokens. State becomes empty only after confirmed deletion.
    /// - Throws: The storage error when deletion fails, leaving the current state unchanged.
    func clear() throws {
        pendingAuthorization = nil
        authorizationGeneration &+= 1
        supersedeTasks()
        guard try keychain.clear() else { throw OAError.keychain }
        state = .empty
    }

}

extension OAuth {
    /// Invalidates asynchronous work started by an earlier authorization flow.
    func supersedeTasks() {
        generation &+= 1
        for task in tasks.values { task.cancel() }
        tasks.removeAll()
        for task in refreshTasks.values { task.cancel() }
        refreshTasks.removeAll()
        refreshIDs.removeAll()
    }
    var activeTaskCount: Int { tasks.count }
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

            if let persistBrowserSession = options[.persistBrowserSession] as? Bool {
                self.persistBrowserSession = persistBrowserSession
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
        monitorTask = Task { @MainActor [networkMonitor] in
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
        let id = UUID()
        let handle = Task { @MainActor [weak self] in
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

    /// Starts and retains an asynchronous operation until it completes.
    /// - Parameters:
    ///   - priority: the task priority
    ///   - operation: the main-actor operation to run.
    func task(priority: TaskPriority = .high, operation: @escaping @MainActor () async -> Void) {
        let id = UUID()
        let taskGeneration = generation
        let handle = Task(priority: priority) { @MainActor [weak self] in
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

        logResponse("token", response: response, provider: provider)

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
        let active = Task<Void, Never> { @MainActor [weak self] in
            guard let self, generation == expectedGeneration, !Task.isCancelled else { return }
            await performRefreshToken(provider: provider, expectedGeneration: expectedGeneration)
        }
        refreshTasks[key] = active
        await active.value
        if refreshIDs[key] == id {
            refreshIDs.removeValue(forKey: key)
            refreshTasks.removeValue(forKey: key)
        }
    }

    private func performRefreshToken(provider: Provider, expectedGeneration: UInt64) async {
        guard expectedGeneration == generation, !Task.isCancelled else { return }
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

        logResponse("refresh", response: response, provider: provider)

        guard response.isOK else {
            if let error = try? decoder.decode(OAuthErrorResponse.self, from: data) {
                if error.error == "invalid_grant" {
                    do {
                        try keychain.delete(key: provider.id)
                    } catch {
                        return publish(state: .error(provider, .keychain))
                    }
                }
                return publish(state: .error(provider, .oauth(error.error)))
            }
            return publish(state: .error(provider, .decoding))
        }

        // Decode the token and retain the current refresh token when the server
        // does not rotate it.
        guard let responseToken = try? decoder.decode(Token.self, from: data) else {
            return publish(state: .error(provider, .decoding))
        }
        let token = Token(
            accessToken: responseToken.accessToken,
            refreshToken: responseToken.refreshToken ?? auth.token.refreshToken,
            expiresIn: responseToken.expiresIn,
            scope: responseToken.scope,
            type: responseToken.type,
            openIDToken: responseToken.openIDToken
        )

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
            guard transaction == generation, !Task.isCancelled else { return }
            return publish(state: .error(provider, .badResponse))
        }
        guard transaction == generation, !Task.isCancelled else { return }

        logResponse("device-code", response: response, provider: provider)

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
            guard transaction == generation, !Task.isCancelled else { return }
            return publish(state: .error(provider, .badResponse))
        }
        guard transaction == generation, !Task.isCancelled else { return }

        logResponse("client-credentials", response: response, provider: provider)

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
        guard deviceCode.expiresIn > 0, deviceCode.expiresIn <= DeviceCode.maximumTiming,
              deviceCode.interval > 0, deviceCode.interval <= DeviceCode.maximumTiming else {
            return publish(state: .error(provider, .decoding))
        }
        guard let request = Request.token(provider: provider, deviceCode: deviceCode) else {
            return publish(state: .error(provider, .malformedURL))
        }

        guard let expiration = deviceCode.expiration else {
            return publish(state: .error(provider, .decoding))
        }
        guard transaction == generation, !Task.isCancelled else { return }
        let remainingLifetime = expiration.timeIntervalSince(devicePollingDate())
        guard remainingLifetime > 0, remainingLifetime.isFinite else {
            return publish(state: .error(provider, .expiredDeviceCode))
        }
        let deadline = devicePollingNow().advanced(by: .seconds(remainingLifetime))
        var interval = deviceCode.interval
        while !Task.isCancelled {
            guard transaction == generation else { return }
            let remaining = devicePollingNow().duration(to: deadline)
            guard remaining > .zero else {
                publish(state: .error(provider, .expiredDeviceCode))
                return
            }

            do {
                try await devicePollingSleep(min(.seconds(Int64(interval)), remaining))
            } catch {
                return
            }
            guard transaction == generation, !Task.isCancelled else { return }
            guard devicePollingNow() < deadline else {
                publish(state: .error(provider, .expiredDeviceCode))
                return
            }

            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await urlSession.data(for: request, delegate: OAuthRedirectDelegate.shared)
            } catch {
                guard transaction == generation, !Task.isCancelled else { return }
                guard let urlError = error as? URLError, urlError.code == .timedOut else {
                    publish(state: .error(provider, .badResponse))
                    return
                }
                interval = interval > DeviceCode.maximumTiming / 2
                    ? DeviceCode.maximumTiming
                    : interval * 2
                continue
            }
            guard transaction == generation, !Task.isCancelled else { return }
            guard devicePollingNow() < deadline else {
                publish(state: .error(provider, .expiredDeviceCode))
                return
            }

            logResponse("device-token", response: response, provider: provider)
            guard response.isOK else {
                guard let error = Self.oauthError(from: data) else {
                    publish(state: .error(provider, .decoding))
                    return
                }
                switch error {
                case "authorization_pending":
                    continue
                case "slow_down":
                    interval = interval > DeviceCode.maximumTiming - 5
                        ? DeviceCode.maximumTiming
                        : interval + 5
                default:
                    publish(state: .error(provider, .oauth(error)))
                    return
                }
                continue
            }

            guard let token = try? decoder.decode(Token.self, from: data) else {
                publish(state: .error(provider, .decoding))
                return
            }
            let authorization = Authorization(issuer: provider.id, token: token)
            guard let stored = try? keychain.set(authorization, for: authorization.issuer), stored else {
                publish(state: .error(provider, .keychain))
                return
            }
            publish(state: .authorized(provider, authorization))
            return
        }
    }

    private static func oauthError(from data: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return object["error"] as? String
    }
}
