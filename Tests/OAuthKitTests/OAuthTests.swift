//
//  OAuthTests.swift
//
//
//  Created by Kevin McKee
//
import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
@testable import OAuthKit
import Testing

@MainActor
@Suite("OAuth Tests", .tags(.oauth))
final class OAuthTests {

    let oauth: OAuth
    let tag: String
    var keychain: Keychain {
        oauth.keychain
    }
    var provider: OAuth.Provider {
        oauth.providers.filter{ $0.id == "GitHub" }.first!
    }

    /// The mock url session that overrides the protocol classes with `OAuthTestURLProtocol`
    /// that will intercept all outbound requests and return mocked test data.
    private static let urlSession: URLSession = {
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestURLProtocol.self]
        return .init(configuration: configuration)
    }()

    /// Initializer.
    init() async throws {
        tag = "oauthkit.test." + .secureRandom()

        let options: [OAuth.Option: Any] = [
            .applicationTag: tag, .autoRefresh: true,
            .useNonPersistentWebDataStore: true,
            .urlSession: Self.urlSession,
        ]
        oauth = .init(.module, options: options)
        #expect(oauth.useNonPersistentWebDataStore == true)
        #expect(oauth.urlSession == Self.urlSession)
    }

    /// Tests the initialization with providers.
    @Test("When Initializing")
    func whenInitializing() async throws {
        let appTag: String = .secureRandom()
        let options: [OAuth.Option: Any] = [
            .applicationTag: appTag,
            .autoRefresh: true,
            .urlSession: Self.urlSession,
        ]
        let providers: [OAuth.Provider] = [
            .init(id: .secureRandom(),
                  authorizationURL: URL(string: "http://github.com/codefiesta/auth")!,
                  accessTokenURL: URL(string: "http://github.com/codefiesta/token")!,
                  clientID: .secureRandom(),
                  clientSecret: .secureRandom())
        ]
        let customOAuth: OAuth = .init(providers: providers, options: options)
        #expect(customOAuth.providers.count == 1)
        #expect(customOAuth.useNonPersistentWebDataStore == false)
        #expect(customOAuth.urlSession == Self.urlSession)
    }

    @Test("When Requiring Local Authentication")
    func whenRequiringAuthenticationWithBiometricsOrCompanion() async throws {
        let appTag: String = .secureRandom()
        var options: [OAuth.Option: Any] = [
            .applicationTag: appTag,
            .requireAuthenticationWithBiometricsOrCompanion: true,
            .autoRefresh: true
        ]
        #if !os(tvOS)
        options[.localAuthentication] = OAuthTestLAContext()
        #endif
        let customOAuth: OAuth = .init(.module, options: options)
        #expect(customOAuth.providers.isNotEmpty)
        #expect(customOAuth.requireAuthenticationWithBiometricsOrCompanion == true)
    }

    @Test("When Restoring Authorizations")
    func whenRestoringAuthorizations() async throws {
        let key = provider.id
        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 3600, scope: "email", type: "Bearer")
        let auth: OAuth.Authorization = .init(issuer: provider.id, token: token)
        let inserted = try keychain.set(auth, for: key)
        #expect(inserted == true)

        let options: [OAuth.Option: Any] = [
            .applicationTag: tag,
            .autoRefresh: false,
            .useNonPersistentWebDataStore: true,
            .urlSession: Self.urlSession
        ]
        let restoredOAuth: OAuth = .init(.module, options: options)
        #expect(restoredOAuth.state == .authorized(provider, auth))
        try keychain.clear()
    }

    /// Tests the custom date extension operator.
    @Test("Expiring tokens")
    func whenExpiring() async throws {
        let expiresIn = 60
        let now = Date.now
        let issued = now.addingTimeInterval(-TimeInterval(expiresIn * 10)) // 10 minutes ago
        let expiration = issued.addingTimeInterval(TimeInterval(expiresIn))
        let timeInterval = expiration - Date.now
        #expect(timeInterval < 0)
    }

    /// Tests the authorization request parameters.
    @Test("Building Authorization Request")
    func whenBuildingAuthorizationRequest() async throws {
        let state: String = .secureRandom(count: 16)
        let grantType: OAuth.GrantType = .authorizationCode(state)
        let request = OAuth.Request.auth(provider: provider, grantType: grantType)
        #expect(request != nil)
        #expect(request!.url!.absoluteString.contains("client_id=\(provider.clientID)"))
        #expect(request!.url!.absoluteString.contains("redirect_uri=\(provider.redirectURI!)"))
        #expect(request!.url!.absoluteString.contains("response_type=code"))
        #expect(request!.url!.absoluteString.contains("state=\(state)"))
    }

    /// Tests the building of client credential token requests.
    @Test("Building Client Credentials Token Requests")
    func whenBuildingClientCredentialsTokenRequests() async throws {
        let request = OAuth.Request.token(provider: provider)
        let data = request?.httpBody
        let stringData = String(data: data!, encoding: .utf8)
        #expect(request != nil)
        #expect(data != nil)
        #expect(request?.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Basic ") == true)
        #expect(stringData!.contains("grant_type=client_credentials"))
        oauth.authorize(provider: provider, grantType: .clientCredentials)
        let result = await waitForAuthorization(oauth)
        #expect(result == true)
    }

    /// Tests the `/device`code  request parameters.
    @Test("Building Device Code Request")
    func whenBuildingDeviceCodeRequest() async throws {
        let request = OAuth.Request.device(provider: provider)
        #expect(request != nil)
        let body = String(data: request!.httpBody!, encoding: .utf8)!
        #expect(request!.url!.query == nil)
        #expect(body.contains("client_id="))
        #expect(request!.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Basic ") == true)
        oauth.authorize(provider: provider, grantType: .deviceCode)
    }

    /// Tests the building of device code token requests.
    @Test("Building Device Code Token Requests")
    func whenBuildingDeviceCodeTokenRequests() async throws {
        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: "ABC-XYZ", verificationUri: "https://example.com/device", expiresIn: 1800, interval: 5)
        let request = OAuth.Request.token(provider: provider, deviceCode: deviceCode)
        #expect(request != nil)
        let body = String(data: request!.httpBody!, encoding: .utf8)!
        #expect(request!.url!.query == nil)
        #expect(body.contains("device_code=\(deviceCode.deviceCode)"))
        #expect(body.contains("grant_type=\(OAuth.DeviceCode.grantType)"))
    }

    /// Tests the building of token requests.
    @Test("Building Token Requests")
    func whenBuildingTokenRequests() async throws {
        let code: String = .secureRandom()
        let request = OAuth.Request.token(provider: provider, code: code, pkce: nil)
        let data = request?.httpBody
        let stringData = String(data: data!, encoding: .utf8)
        #expect(request != nil)
        #expect(data != nil)
        #expect(request?.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Basic ") == true)
        #expect(stringData!.contains("code=\(code)"))
        #expect(stringData!.contains("redirect_uri=https%3A%2F%2Fgithub.com%2Fcodefiesta%2F"))
        #expect(stringData!.contains("grant_type=authorization_code"))
        oauth.token(provider: provider, code: code, pkce: nil)
        let result = await waitForAuthorization(oauth)
        #expect(result == true)
    }

    /// Tests the building of PKCE token requests.
    @Test("Building PKCE Token Requests")
    func whenBuildingPKCETokenRequests() async throws {
        let code: String = .secureRandom()
        let pkce: OAuth.PKCE = .init()
        let request = OAuth.Request.token(provider: provider, code: code, pkce: pkce)
        let data = request?.httpBody
        let stringData = String(data: data!, encoding: .utf8)
        #expect(request != nil)
        #expect(data != nil)
        #expect(request?.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Basic ") == true)
        #expect(stringData!.contains("code=\(code)"))
        #expect(stringData!.contains("redirect_uri=https%3A%2F%2Fgithub.com%2Fcodefiesta%2F"))
        #expect(stringData!.contains("grant_type=authorization_code"))
        #expect(stringData!.contains("code_verifier=\(pkce.codeVerifier)"))
        oauth.token(provider: provider, code: code, pkce: pkce)
        let result = await waitForAuthorization(oauth)
        #expect(result == true)
    }

    /// Tests the refresh token request parameters.
    @Test("Building Refresh Token Request")
    func whenBuildingRefreshTokenRequest() async throws {
        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 3600, scope: nil, type: "Bearer")
        let request = OAuth.Request.refresh(provider: provider, token: token)
        #expect(request != nil)
        let body = String(data: request!.httpBody!, encoding: .utf8)!
        #expect(request!.url == provider.accessTokenURL)
        #expect(request!.url!.query == nil)
        #expect(body.contains("grant_type=refresh_token"))
        #expect(body.contains("refresh_token=\(token.refreshToken!)"))
        let auth: OAuth.Authorization = .init(issuer: provider.id, token: token)
        try keychain.set(auth, for: provider.id)
        oauth.authorize(provider: provider, grantType: .refreshToken)
        let result = await waitForAuthorization(oauth)
        #expect(result == true)
    }

    @Test("When Auto Refreshng Tokens")
    func whenAutoRefreshingTokens() async throws {
        let key = provider.id
        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 0, scope: "email", type: "Bearer")
        let auth: OAuth.Authorization = .init(issuer: provider.id, token: token)
        let inserted = try keychain.set(auth, for: key)
        #expect(inserted == true)

        let options: [OAuth.Option: Any] = [
            .applicationTag: tag,
            .autoRefresh: true,
            .useNonPersistentWebDataStore: true,
            .urlSession: Self.urlSession
        ]
        let restoredOAuth: OAuth = .init(.module, options: options)
        #expect(restoredOAuth.state == .authorized(provider, auth))
        restoredOAuth.state = .empty
        let result = await waitForAuthorization(restoredOAuth)
        #expect(result == true)
    }

    @Test("When Receiving bad response data")
    func whenReceivingBadResponseData() async throws {
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestClientErrorURLProtocol.self]
        let urlSession: URLSession = .init(configuration: configuration)

        let applicationTag = "oauthkit.test." + .secureRandom()
        let options: [OAuth.Option: Any] = [
            .applicationTag: applicationTag,
            .autoRefresh: true,
            .useNonPersistentWebDataStore: true,
            .urlSession: urlSession,
        ]

        // Token
        let oauth: OAuth = .init(.module, options: options)
        await oauth.requestToken(provider: provider, code: .secureRandom())
        #expect(oauth.state == .error(provider, .decoding))

        // Refresh Token
        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 0, scope: "email", type: "Bearer")
        let auth: OAuth.Authorization = .init(issuer: provider.id, token: token)
        try oauth.keychain.set(auth, for: provider.id)
        await oauth.refreshToken(provider: provider)
        #expect(oauth.state == .error(provider, .decoding))
        try oauth.clear()

        // Client Credentials
        await oauth.requestClientCredentials(provider: provider)
        #expect(oauth.state == .error(provider, .decoding))

        // Device Code
        await oauth.requestDeviceCode(provider: provider)
        #expect(oauth.state == .error(provider, .decoding))

        // Device Code Polling
        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: .secureRandom(), verificationUri: "https://example.com", expiresIn: 200, interval: 0)
        await oauth.poll(provider: provider, deviceCode: deviceCode)
        #expect(oauth.state == .error(provider, .decoding))
    }

    @Test("When Received server error")
    func whenReceivingServerError() async throws {
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestServerErrorURLProtocol.self]
        let urlSession: URLSession = .init(configuration: configuration)

        let applicationTag = "oauthkit.test." + .secureRandom()
        let options: [OAuth.Option: Any] = [
            .applicationTag: applicationTag,
            .autoRefresh: true,
            .useNonPersistentWebDataStore: true,
            .urlSession: urlSession,
        ]

        // Token
        let oauth: OAuth = .init(.module, options: options)
        await oauth.requestToken(provider: provider, code: .secureRandom())
        #expect(oauth.state == .error(provider, .badResponse))

        // Refresh Token
        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 0, scope: "email", type: "Bearer")
        let auth: OAuth.Authorization = .init(issuer: provider.id, token: token)
        try oauth.keychain.set(auth, for: provider.id)
        await oauth.refreshToken(provider: provider)
        #expect(oauth.state == .error(provider, .badResponse))
        try oauth.clear()

        // Client Credentials
        await oauth.requestClientCredentials(provider: provider)
        #expect(oauth.state == .error(provider, .badResponse))

        // Device Code
        await oauth.requestDeviceCode(provider: provider)
        #expect(oauth.state == .error(provider, .badResponse))

        // Device Code Polling
        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: .secureRandom(), verificationUri: "https://example.com", expiresIn: 200, interval: 0)
        await oauth.poll(provider: provider, deviceCode: deviceCode)
        #expect(oauth.state == .error(provider, .badResponse))
    }

    /// Tests the PKCE request parameters.
    @Test("Building PKCE Request")
    func whenBuildingPKCERequest() async throws {
        let pkce: OAuth.PKCE = .init()
        let grantType: OAuth.GrantType = .pkce(pkce)
        let request = OAuth.Request.auth(provider: provider, grantType: grantType)
        #expect(request != nil)
        #expect(request!.url!.absoluteString.contains("client_id="))
        #expect(request!.url!.absoluteString.contains("redirect_uri=\(provider.redirectURI!)"))
        #expect(request!.url!.absoluteString.contains("response_type=code"))
        #expect(request!.url!.absoluteString.contains("state=\(pkce.state)"))
        #expect(request!.url!.absoluteString.contains("code_challenge=\(pkce.codeChallenge)"))
        #expect(request!.url!.absoluteString.contains("code_challenge_method=\(pkce.codeChallengeMethod)"))
    }

    /// Tests OAuth Secure Random State Generation
    @Test("OAuth Polling for Device Code Authorization")
    private func whenPollingForDeviceCodeAuthorization() async throws {
        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: .secureRandom(), verificationUri: "https://example.com", expiresIn: 200, interval: 0)
        await oauth.poll(provider: provider, deviceCode: deviceCode)
        let result = await waitForAuthorization(oauth)
        #expect(result == true)
    }

    /// Tests to make sure the PKCE code verifier and challenge are correct.
    /// See: https://www.oauth.com/playground/authorization-code-with-pkce.html
    @Test("Generating PKCE Code Challenge")
    func whenGeneratingPKCECodeChallenge() async throws {
        let codeVerifier = "irYm7d4my6egZ-ea5jFnL9XM3CYshCdcbL3OlW0w7HMvcE5d"
        let codeChallenge = codeVerifier.sha256.base64URL
        let expectedResult = "W7BYCsNLCgzw-Kf5IZFjhwd-WdPZEhTNNJGQVgOq560"
        #expect(codeChallenge == expectedResult)
    }

    /// Tests to make sure the grant type raw values are frozen and haven't been changed during development.
    @Test("Grant Type Raw Value Checking")
    func whenCheckingGrantType() async throws {
        var grantType: OAuth.GrantType = .authorizationCode(.empty)
        #expect(grantType.rawValue == "authorization_code")
        grantType = .clientCredentials
        #expect(grantType.rawValue == "client_credentials")
        grantType = .deviceCode
        #expect(grantType.rawValue == "device_code")
        grantType = .pkce(.init())
        #expect(grantType.rawValue == "pkce")
        grantType = .refreshToken
        #expect(grantType.rawValue == "refresh_token")
    }

    /// Tests the adding of the Authorization header to an URLRequest.
    @Test("Adding Authorization Header to URLRequest")
    func whenAddingAuthHeader() async throws {
        let string = "https://github.com/codefiesta/OAuthKit"
        let url = URL(string: string)
        var urlRequest = URLRequest(url: url!)

        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: nil, expiresIn: 3600, scope: nil, type: "Bearer")
        let auth: OAuth.Authorization = .init(issuer: provider.id, token: token)
        #expect(auth.expiration != nil)
        #expect(auth.isExpired == false)
        urlRequest.addAuthorization(auth: auth)

        let header = urlRequest.value(forHTTPHeaderField: "Authorization")
        #expect(header != nil)
        #expect(header == "\(token.type) \(token.accessToken)")
    }

    /// Tests OAuth State changes
    @Test("OAuth State Changes")
    func whenOAuthState() async throws {
        let state: String = .secureRandom(count: 16)

        // Authorization Code
        var grantType: OAuth.GrantType = .authorizationCode(state)
        oauth.authorize(provider: provider, grantType: grantType)
        #expect(oauth.state == .authorizing(provider, grantType))

        // PKCE
        let pkce: OAuth.PKCE = .init()
        grantType = .pkce(pkce)
        oauth.authorize(provider: provider, grantType: grantType)
        #expect(oauth.state == .authorizing(provider, grantType))

        // Empty
        try oauth.clear()
        #expect(oauth.state == .empty)
    }

    /// Tests OAuth Secure Random State Generation
    @Test("OAuth Secure Random State")
    func whenGeneratingOAuthSecureRandomState() async throws {
        let random = OAuth.secureRandom()
        #expect(random.count >= 43)
    }

    /// Arrange a provider with a secret but no explicit confidential classification, act by building requests,
    /// and assert secret presence never silently promotes a distributed client or enables Client Credentials.
    @Test("Client Classification Is Explicit")
    func whenClassifyingClientsExplicitly() async throws {
        // Arrange
        let provider = OAuth.Provider(
            id: "unclassified",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            clientID: "native-client",
            clientSecret: "must-not-be-used"
        )
        // Act
        let tokenRequest = try #require(OAuth.Request.token(provider: provider, code: "code"))
        let clientCredentialsRequest = OAuth.Request.token(provider: provider)

        // Assert
        #expect(tokenRequest.value(forHTTPHeaderField: "Authorization") == nil)
        let body = try #require(tokenRequest.httpBody.flatMap { String(data: $0, encoding: .utf8) })
        #expect(!body.contains("client_secret"))
        #expect(clientCredentialsRequest == nil)
    }

    /// A distributed native application must receive an actionable error when
    /// it attempts a grant reserved for clients that can keep secrets confidential.
    @Test("Public clients cannot start the Client Credentials grant")
    func publicClientCredentialsFailsClosed() throws {
        // Arrange
        let publicProvider = OAuth.Provider(
            id: "native-public",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            clientID: "native-client"
        )
        let client = OAuth(providers: [publicProvider], options: [.applicationTag: "oauthkit.test.\(UUID().uuidString)"])

        // Act
        client.authorize(provider: publicProvider, grantType: .clientCredentials)

        // Assert
        #expect(client.state == .error(publicProvider, .invalidClientConfiguration))
        let stored: OAuth.Authorization? = try client.keychain.get(key: publicProvider.id)
        #expect(stored == nil)
    }

    /// Arrange a confidential client with reserved and Unicode credentials, act by building its token request,
    /// and assert the values remain distinct form fields in the body rather than appearing in the URL.
    @Test("Form Encoding Preserves Reserved and Unicode Values")
    func whenFormEncodingReservedValues() async throws {
        let provider = OAuth.Provider(
            id: "form",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            deviceCodeURL: URL(string: "https://example.com/device")!,
            clientID: "client &+% 雪",
            clientSecret: "secret +% 雪",
            clientType: .confidential,
            clientAuthentication: .clientSecretPost,
            redirectURI: "https://app.example/callback?a=1&b=2"
        )
        let request = OAuth.Request.token(provider: provider, code: "code&+% 雪")
        let body = String(data: request!.httpBody!, encoding: .utf8)!

        let deviceRequest = OAuth.Request.device(provider: provider)
        let deviceBody = String(data: deviceRequest!.httpBody!, encoding: .utf8)!
        #expect(deviceRequest?.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(deviceBody.contains("client_id=client+%26%2B%25+%E9%9B%AA"))
        #expect(deviceBody.contains("client_secret=secret+%2B%25+%E9%9B%AA"))
        #expect(request!.url?.query == nil)
        #expect(body.contains("client_id=client+%26%2B%25+%E9%9B%AA"))
        #expect(body.contains("client_secret=secret+%2B%25+%E9%9B%AA"))
        #expect(body.contains("code=code%26%2B%25+%E9%9B%AA"))
        #expect(body.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%3Fa%3D1%26b%3D2"))
        #expect(request?.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded")
        var basicProvider = provider
        basicProvider.clientAuthentication = .clientSecretBasic
        let basicDeviceRequest = OAuth.Request.device(provider: basicProvider)
        let basicDeviceBody = String(data: basicDeviceRequest!.httpBody!, encoding: .utf8)!
        let encodedClientID = "client+%26%2B%25+%E9%9B%AA"
        let encodedSecret = "secret+%2B%25+%E9%9B%AA"
        let expectedCredentials = Data("\(encodedClientID):\(encodedSecret)".utf8).base64EncodedString()
        #expect(basicDeviceRequest?.value(forHTTPHeaderField: "Authorization") == "Basic \(expectedCredentials)")
        #expect(basicDeviceBody.contains("client_id=\(encodedClientID)"))
        #expect(basicDeviceBody.contains("client_secret") == false)

        let basicTokenRequest = OAuth.Request.token(provider: basicProvider, code: "code&+% 雪")
        #expect(basicTokenRequest?.value(forHTTPHeaderField: "Authorization") == "Basic \(expectedCredentials)")
        #expect(String(data: basicTokenRequest!.httpBody!, encoding: .utf8)!.contains("client_id=") == false)
    }

    /// Arrange an insecure endpoint and protected-resource destination, act by building requests or attaching a token,
    /// and assert TLS failures return nil or omit the bearer credential.
    @Test("Insecure OAuth Destinations Fail Closed")
    func whenRejectingInsecureDestinations() async throws {
        let insecureProvider = OAuth.Provider(
            id: "insecure",
            authorizationURL: URL(string: "http://example.com/authorize")!,
            accessTokenURL: URL(string: "http://example.com/token")!,
            deviceCodeURL: URL(string: "http://example.com/device"),
            clientID: "client"
        )
        #expect(OAuth.Request.auth(provider: insecureProvider, grantType: .authorizationCode("state")) == nil)
        #expect(OAuth.Request.token(provider: insecureProvider, code: "code") == nil)
        #expect(OAuth.Request.device(provider: insecureProvider) == nil)
        var request = URLRequest(url: URL(string: "http://example.com/resource")!)
        let token = OAuth.Token(accessToken: "secret", refreshToken: nil, expiresIn: 3600, scope: nil, type: "Bearer")
        request.addAuthorization(auth: OAuth.Authorization(issuer: "insecure", token: token))
        #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
    }
    /// Arrange OAuth endpoint URLs containing credential-bearing query parameters, act by building requests,
    /// and assert the builders reject those endpoints rather than retaining secrets in URLs.
    @Test("Credential Parameters Are Rejected From Endpoint URLs")
    func whenRejectingCredentialBearingEndpointURLs() async throws {
        let provider = OAuth.Provider(
            id: "unsafe-query",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token?client_secret=leaked")!,
            deviceCodeURL: URL(string: "https://example.com/device?code=leaked")!,
            clientID: "public"
        )
        let token = OAuth.Token(accessToken: "access", refreshToken: "refresh", expiresIn: 3600, scope: nil, type: "Bearer")
        #expect(OAuth.Request.token(provider: provider, code: "code") == nil)
        #expect(OAuth.Request.refresh(provider: provider, token: token) == nil)
        #expect(OAuth.Request.token(provider: provider, deviceCode: .init(deviceCode: "device", userCode: "123", verificationUri: "https://example.com", expiresIn: 30, interval: 5)) == nil)
        #expect(OAuth.Request.device(provider: provider) == nil)
        let collisionProvider = OAuth.Provider(
            id: "collision",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token?grant_type=forged&tenant=one")!,
            clientID: "public"
        )
        #expect(OAuth.Request.token(provider: collisionProvider, code: "code") == nil)

        let safeQueryProvider = OAuth.Provider(
            id: "static-query",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token?tenant=one")!,
            clientID: "public"
        )
        #expect(OAuth.Request.token(provider: safeQueryProvider, code: "code")?.url?.query == "tenant=one")
        var staticAuthQueryProvider = safeQueryProvider
        staticAuthQueryProvider.authorizationURL = URL(string: "https://example.com/authorize?tenant=one")!
        let authRequest = OAuth.Request.auth(provider: staticAuthQueryProvider, grantType: .authorizationCode("state"))
        #expect(URLComponents(url: authRequest!.url!, resolvingAgainstBaseURL: false)?.queryItems?.first?.name == "tenant")
    }


    /// Arrange redirect URIs for browser and native applications, act by building authorization requests,
    /// and assert only HTTPS or loopback/custom-scheme redirects are accepted.
    @Test("Native Redirect URI Exceptions Are Narrow")
    func whenValidatingNativeRedirectURIs() async throws {
        let base = OAuth.Provider(
            id: "redirect",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            clientID: "public-client",
            redirectURI: "http://127.0.0.1:49152/callback"
        )
        #expect(OAuth.Request.auth(provider: base, grantType: .authorizationCode("state")) != nil)
        var ipv6Loopback = base
        ipv6Loopback.redirectURI = "http://[::1]:49152/callback"
        #expect(OAuth.Request.auth(provider: ipv6Loopback, grantType: .authorizationCode("state")) != nil)
        var invalid = base
        invalid.redirectURI = "http://example.com/callback"
        #expect(OAuth.Request.auth(provider: invalid, grantType: .authorizationCode("state")) == nil)
        var custom = base
        custom.redirectURI = "com.example.app:/oauth2redirect"
        #expect(OAuth.Request.auth(provider: custom, grantType: .authorizationCode("state")) != nil)
    }

    /// Arrange an unclassified client with no secret, act by requesting client credentials, and
    /// assert public clients cannot use the confidential-only grant.
    @Test("Public Clients Cannot Use Client Credentials")
    func whenRejectingPublicClientCredentialsGrant() async throws {
        let publicProvider = OAuth.Provider(
            id: "public",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            clientID: "public-client"
        )
        #expect(publicProvider.clientType == .public)
        #expect(publicProvider.clientAuthentication == .none)
        #expect(OAuth.Request.token(provider: publicProvider) == nil)
    }
    /// Streams the oauth status until we receive an authorization.
    /// This should only be used on test methods that expect an authorization to be inserted into the keychain.
    private func waitForAuthorization(_ oauth: OAuth) async -> Bool {
        let monitor: OAuth.Monitor = .init(oauth: oauth)
        for await state in monitor.stream {
            switch state {
            case .empty, .error, .authorizing, .requestingAccessToken, .requestingDeviceCode, .receivedDeviceCode:
                break
            case .authorized(_, _):
                do { try oauth.clear() }
                catch {
                    Issue.record("Failed to clear authorization: \(error)")
                    return false
                }
                return true
            }
        }
        return false
    }
}
