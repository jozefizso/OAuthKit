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
            .urlSession: Self.urlSession,
        ]
        oauth = .init(.module, options: options)
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
        #expect(customOAuth.urlSession == Self.urlSession)
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
        let pkce = OAuth.PKCE()
        let request = OAuth.Request.auth(provider: provider, pkce: pkce)
        #expect(request != nil)
        #expect(request!.url!.absoluteString.contains("client_id=\(provider.clientID)"))
        #expect(request!.url!.absoluteString.contains("redirect_uri=\(provider.redirectURI!)"))
        #expect(request!.url!.absoluteString.contains("response_type=code"))
        #expect(request!.url!.absoluteString.contains("state=\(pkce.state)"))
        #expect(request!.url!.absoluteString.contains("code_challenge_method=S256"))
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

    /// Verifies that a refresh response without `refresh_token` keeps the existing credential.
    @Test("Refresh preserves an omitted refresh token")
    func whenRefreshOmitsRefreshToken() async throws {
        // Arrange
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthRefreshTokenOmittedURLProtocol.self]
        let urlSession = URLSession(configuration: configuration)
        let applicationTag = "oauthkit.test." + .secureRandom()
        let oauth = OAuth(.module, options: [
            .applicationTag: applicationTag,
            .autoRefresh: false,
            .urlSession: urlSession,
        ])
        let original = OAuth.Token(accessToken: "access-old", refreshToken: "refresh-old", expiresIn: 3600, scope: "old-scope", type: "Bearer", openIDToken: "id-old")
        let authorization = OAuth.Authorization(issuer: provider.id, token: original)
        try #require(oauth.keychain.set(authorization, for: provider.id))

        // Act
        await oauth.refreshToken(provider: provider)

        // Assert
        let expected = OAuth.Token(accessToken: "access-new", refreshToken: "refresh-old", expiresIn: 1800, scope: "new-scope", type: "Bearer", openIDToken: "id-new")
        #expect(oauth.state == .authorized(provider, .init(issuer: provider.id, token: expected)))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored?.token == expected)
    }

    /// Verifies that a supplied refresh token replaces the existing credential.
    @Test("Refresh accepts a rotated refresh token")
    func whenRefreshRotatesRefreshToken() async throws {
        // Arrange
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthRefreshTokenRotatedURLProtocol.self]
        let urlSession = URLSession(configuration: configuration)
        let applicationTag = "oauthkit.test." + .secureRandom()
        let oauth = OAuth(.module, options: [
            .applicationTag: applicationTag,
            .autoRefresh: false,
            .urlSession: urlSession,
        ])
        let original = OAuth.Token(accessToken: "access-old", refreshToken: "refresh-old", expiresIn: 3600, scope: "old-scope", type: "Bearer")
        let authorization = OAuth.Authorization(issuer: provider.id, token: original)
        try #require(oauth.keychain.set(authorization, for: provider.id))

        // Act
        await oauth.refreshToken(provider: provider)

        // Assert
        let expected = OAuth.Token(accessToken: "access-new", refreshToken: "refresh-new", expiresIn: 1800, scope: "new-scope", type: "Bearer", openIDToken: "id-new")
        #expect(oauth.state == .authorized(provider, .init(issuer: provider.id, token: expected)))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored?.token == expected)
    }

    /// Verifies that invalid_grant is reported distinctly and removes the revoked credential.
    @Test("Refresh reports invalid_grant and removes the revoked credential")
    func whenRefreshReturnsInvalidGrant() async throws {
        // Arrange
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthInvalidGrantURLProtocol.self]
        let urlSession = URLSession(configuration: configuration)
        let applicationTag = "oauthkit.test." + .secureRandom()
        let oauth = OAuth(.module, options: [
            .applicationTag: applicationTag,
            .autoRefresh: false,
            .urlSession: urlSession,
        ])
        let token = OAuth.Token(accessToken: "access-old", refreshToken: "refresh-revoked", expiresIn: 3600, scope: nil, type: "Bearer")
        let authorization = OAuth.Authorization(issuer: provider.id, token: token)
        try #require(oauth.keychain.set(authorization, for: provider.id))

        // Act
        await oauth.refreshToken(provider: provider)

        // Assert
        #expect(oauth.state == .error(provider, .oauth("invalid_grant")))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored == nil)
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
        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: .secureRandom(), verificationUri: "https://example.com", expiresIn: 2, interval: 1)
        await oauth.poll(provider: provider, deviceCode: deviceCode)
        #expect(oauth.state == .error(provider, .badResponse))
    }

    /// Tests the PKCE request parameters.
    @Test("Building PKCE Request")
    func whenBuildingPKCERequest() async throws {
        let pkce = OAuth.PKCE()
        let request = OAuth.Request.auth(provider: provider, pkce: pkce)
        #expect(request != nil)
        #expect(request!.url!.absoluteString.contains("client_id="))
        #expect(request!.url!.absoluteString.contains("redirect_uri=\(provider.redirectURI!)"))
        #expect(request!.url!.absoluteString.contains("response_type=code"))
        #expect(request!.url!.absoluteString.contains("state=\(pkce.state)"))
        #expect(request!.url!.absoluteString.contains("code_challenge=\(pkce.codeChallenge)"))
        #expect(request!.url!.absoluteString.contains("code_challenge_method=S256"))
    }

    /// Tests OAuth Secure Random State Generation
    @Test("OAuth Polling for Device Code Authorization")
    private func whenPollingForDeviceCodeAuthorization() async throws {
        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: .secureRandom(), verificationUri: "https://example.com", expiresIn: 200, interval: 1)
        await oauth.poll(provider: provider, deviceCode: deviceCode)
        let result = await waitForAuthorization(oauth)
        #expect(result == true)
    }

    @Test("Device polling backs off on network failures and stops at expiry")
    func devicePollingBacksOffUntilExpiry() async throws {
        // Arrange
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestServerErrorURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let poller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: session
        ])
        let deviceCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                          verificationUri: "https://example.com/device",
                                          expiresIn: 2, interval: 1)

        // Act
        await poller.poll(provider: provider, deviceCode: deviceCode)

        // Assert
        #expect(poller.state == .error(provider, .expiredDeviceCode))
    }

    @Test("Device polling stops on terminal OAuth errors")
    func devicePollingStopsOnOAuthError() async throws {
        // Arrange
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestOAuthErrorURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let poller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: session
        ])
        let deviceCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                          verificationUri: "https://example.com/device",
                                          expiresIn: 10, interval: 1)

        // Act
        await poller.poll(provider: provider, deviceCode: deviceCode)

        // Assert
        #expect(poller.state == .error(provider, .oauth("access_denied")))
    }

    @Test("slow_down adds five seconds and pending keeps the longer interval")
    func devicePollingPersistsSlowDownInterval() async throws {
        // Arrange
        await OAuthTestSlowDownURLProtocol.reset()
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestSlowDownURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let poller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: session
        ])
        var delays = [Duration]()
        poller.devicePollingSleep = { delay in
            delays.append(delay)
        }
        let deviceCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                          verificationUri: "https://example.com/device",
                                          expiresIn: 60, interval: 1)

        // Act
        await poller.poll(provider: provider, deviceCode: deviceCode)

        // Assert
        #expect(poller.state == .error(provider, .oauth("access_denied")))
        #expect(delays == [.seconds(1), .seconds(1), .seconds(6), .seconds(6)])
        let requestCount = await OAuthTestSlowDownURLProtocol.requestsMade()
        #expect(requestCount == 4)
    }

    @Test("Fractional device expiry preserves success and prevents late requests")
    func fractionalDeviceExpiryBoundsRequests() async throws {
        // Arrange
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestCountingTokenURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let successfulPoller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: session
        ])
        await OAuthTestCountingTokenURLProtocol.reset()
        let successfulCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                               verificationUri: "https://example.com/device",
                                               expiresIn: 10, interval: 5)
        let successfulExpiration = successfulCode.expiration!
        var successfulInstant = ContinuousClock().now
        successfulPoller.devicePollingDate = { successfulExpiration.addingTimeInterval(-0.5) }
        successfulPoller.devicePollingNow = { successfulInstant }
        var successfulDelays = [Duration]()
        successfulPoller.devicePollingSleep = { delay in
            successfulDelays.append(delay)
            successfulInstant = successfulInstant.advanced(by: .milliseconds(250))
        }

        // Act
        await successfulPoller.poll(provider: provider, deviceCode: successfulCode)

        // Assert
        if case .authorized = successfulPoller.state {
            #expect(true)
        } else {
            #expect(Bool(false))
        }
        #expect(successfulDelays == [.milliseconds(500)])
        let successfulRequestCount = await OAuthTestCountingTokenURLProtocol.requestsMade()
        #expect(successfulRequestCount == 1)

        // Arrange another request whose wait reaches the fractional deadline exactly.
        await OAuthTestCountingTokenURLProtocol.reset()
        let expiredPoller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: session
        ])
        let expiredCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                           verificationUri: "https://example.com/device",
                                           expiresIn: 10, interval: 5)
        let expiredExpiration = expiredCode.expiration!
        var expiredInstant = ContinuousClock().now
        expiredPoller.devicePollingDate = { expiredExpiration.addingTimeInterval(-0.5) }
        expiredPoller.devicePollingNow = { expiredInstant }
        expiredPoller.devicePollingSleep = { delay in
            expiredInstant = expiredInstant.advanced(by: delay)
        }

        // Act
        await expiredPoller.poll(provider: provider, deviceCode: expiredCode)

        // Assert
        #expect(expiredPoller.state == .error(provider, .expiredDeviceCode))
        let expiredRequestCount = await OAuthTestCountingTokenURLProtocol.requestsMade()
        #expect(expiredRequestCount == 0)
    }

    @Test("A held token response arriving after expiry is discarded")
    func heldTokenResponseCannotOutliveDeviceExpiry() async throws {
        // Arrange
        await OAuthTestHeldResponseURLProtocol.reset()
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestHeldResponseURLProtocol.self]
        let poller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: URLSession(configuration: configuration)
        ])
        let deviceCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                          verificationUri: "https://example.com/device",
                                          expiresIn: 10, interval: 5)
        let expiration = deviceCode.expiration!
        var now = ContinuousClock().now
        poller.devicePollingDate = { expiration.addingTimeInterval(-0.5) }
        poller.devicePollingNow = { now }
        poller.devicePollingSleep = { _ in
            now = now.advanced(by: .milliseconds(250))
        }
        let polling = Task { await poller.poll(provider: provider, deviceCode: deviceCode) }

        // Act
        await OAuthTestHeldResponseURLProtocol.waitForRequest()
        now = now.advanced(by: .milliseconds(300))
        await OAuthTestHeldResponseURLProtocol.release(Data(#"{"access_token":"late-token","token_type":"Bearer"}"#.utf8))
        await polling.value

        // Assert
        #expect(poller.state == .error(provider, .expiredDeviceCode))
        let stored: OAuth.Authorization? = try poller.keychain.get(key: provider.id)
        #expect(stored == nil)
        let requestCount = await OAuthTestHeldResponseURLProtocol.requestsMade()
        #expect(requestCount == 1)
    }

    @Test("Only timed-out requests back off; TLS errors terminate")
    func pollingRetriesOnlyTimeouts() async throws {
        // Arrange timeout response sequence.
        await OAuthTestTimedOutURLProtocol.reset()
        let timeoutConfiguration: URLSessionConfiguration = .ephemeral
        timeoutConfiguration.protocolClasses = [OAuthTestTimedOutURLProtocol.self]
        let timeoutPoller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: URLSession(configuration: timeoutConfiguration)
        ])
        var timeoutNow = ContinuousClock().now
        timeoutPoller.devicePollingDate = { Date.now.addingTimeInterval(20) }
        timeoutPoller.devicePollingNow = { timeoutNow }
        var timeoutDelays = [Duration]()
        timeoutPoller.devicePollingSleep = { delay in
            timeoutDelays.append(delay)
            timeoutNow = timeoutNow.advanced(by: delay)
        }
        let timeoutCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                           verificationUri: "https://example.com/device",
                                           expiresIn: 30, interval: 1)

        // Act
        await timeoutPoller.poll(provider: provider, deviceCode: timeoutCode)

        // Assert
        #expect(timeoutPoller.state == .error(provider, .oauth("access_denied")))
        #expect(timeoutDelays == [.seconds(1), .seconds(2)])
        let timeoutRequestCount = await OAuthTestTimedOutURLProtocol.requestsMade()
        #expect(timeoutRequestCount == 2)

        // Arrange TLS failure response.
        await OAuthTestTLSFailureURLProtocol.reset()
        let tlsConfiguration: URLSessionConfiguration = .ephemeral
        tlsConfiguration.protocolClasses = [OAuthTestTLSFailureURLProtocol.self]
        let tlsPoller = OAuth(providers: [provider], options: [
            .applicationTag: "oauthkit.test." + .secureRandom(),
            .urlSession: URLSession(configuration: tlsConfiguration)
        ])
        var tlsNow = ContinuousClock().now
        tlsPoller.devicePollingDate = { Date.now.addingTimeInterval(20) }
        tlsPoller.devicePollingNow = { tlsNow }
        var tlsDelays = [Duration]()
        tlsPoller.devicePollingSleep = { delay in
            tlsDelays.append(delay)
            tlsNow = tlsNow.advanced(by: delay)
        }
        let tlsCode = OAuth.DeviceCode(deviceCode: .secureRandom(), userCode: "USER",
                                       verificationUri: "https://example.com/device",
                                       expiresIn: 30, interval: 1)

        // Act
        await tlsPoller.poll(provider: provider, deviceCode: tlsCode)

        // Assert
        #expect(tlsPoller.state == .error(provider, .badResponse))
        #expect(tlsDelays == [.seconds(1)])
        let tlsRequestCount = await OAuthTestTLSFailureURLProtocol.requestsMade()
        #expect(tlsRequestCount == 1)
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
        var grantType: OAuth.GrantType = .authorizationCode
        #expect(grantType.rawValue == "authorization_code")
        grantType = .clientCredentials
        #expect(grantType.rawValue == "client_credentials")
        grantType = .deviceCode
        #expect(grantType.rawValue == "device_code")
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
        oauth.providers = [provider]
        oauth.authorize(provider: provider)
        #expect(oauth.state == .authorizing(provider, .authorizationCode))
        let firstGeneration = oauth.authorizationGeneration
        let firstState = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!
            .queryItems!.first(where: { $0.name == "state" })?.value
        let firstChallenge = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!
            .queryItems!.first(where: { $0.name == "code_challenge" })?.value
        oauth.authorize(provider: provider)
        let secondGeneration = oauth.authorizationGeneration
        let secondState = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!
            .queryItems!.first(where: { $0.name == "state" })?.value
        let secondChallenge = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!
            .queryItems!.first(where: { $0.name == "code_challenge" })?.value
        #expect(firstState != secondState)
        #expect(firstChallenge != secondChallenge)
        #expect(firstGeneration != secondGeneration)
        oauth.clear()
        #expect(oauth.state == .empty)
    }
    @Test("Issuer-less servers require matcher-distinct redirects")
    func whenRequiringDistinctRedirectsWithoutIssuer() {
        let first = OAuth.Provider(
            id: "server-one",
            authorizationURL: URL(string: "https://one.example/authorize")!,
            accessTokenURL: URL(string: "https://one.example/token")!,
            clientID: "one",
            clientSecret: nil,
            redirectURI: "MYAPP://CALLBACK?tenant=a+b"
        )
        let second = OAuth.Provider(
            id: "server-two",
            authorizationURL: URL(string: "https://two.example/authorize")!,
            accessTokenURL: URL(string: "https://two.example/token")!,
            clientID: "two",
            clientSecret: nil,
            redirectURI: "myapp://callback?tenant=a%20b"
        )
        oauth.providers = [first, second]
        oauth.authorize(provider: first)
        #expect(oauth.state == .error(first, .malformedURL))
        #expect(oauth.activeAuthorizationURL == nil)
    }


    /// Tests the single-use callback transaction against issuer and redirect mix-up inputs.
    @Test("Authorization Callback Binding and Single Use")
    func whenBindingAuthorizationCallbacks() async throws {
        let testProvider = OAuth.Provider(
            id: "issuer-bound-test",
            authorizationURL: URL(string: "https://auth.example/authorize")!,
            accessTokenURL: URL(string: "https://auth.example/token")!,
            issuer: "https://auth.example/issuer+v1",
            clientID: "client",
            clientSecret: nil,
            redirectURI: "myapp://callback?tenant=one"
        )
        oauth.providers = [testProvider]
        oauth.authorize(provider: testProvider)
        let authorizationItems = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!.queryItems!
        let state = authorizationItems.first(where: { $0.name == "state" })!.value!
        let makeCallback: ([URLQueryItem], String) -> URL = { items, host in
            var components = URLComponents()
            components.scheme = "myapp"
            components.host = host.isEmpty ? "callback" : host
            components.queryItems = items
            components.percentEncodedQuery = components.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
            return components.url!
        }
        let validItems = [
            URLQueryItem(name: "tenant", value: "one"),
            URLQueryItem(name: "code", value: "test-code"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "iss", value: "https://auth.example/issuer+v1"),
            URLQueryItem(name: "scope", value: "openid")
        ]
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems.filter { $0.name != "iss" }, "")))
        let rawPlusCallback = URL(string: "myapp://callback?tenant=one&code=test-code&state=\(state)&iss=https%3A%2F%2Fauth.example%2Fissuer+v1")!
        #expect(!oauth.handleAuthorizationCallback(rawPlusCallback))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems.map {
            $0.name == "iss" ? URLQueryItem(name: "iss", value: "https://AUTH.example/issuer+v1") : $0
        }, "")))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems + [URLQueryItem(name: "iss", value: "https://auth.example/issuer+v1")], "")))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems, "callback.attacker")))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems.map {
            $0.name == "tenant" ? URLQueryItem(name: "tenant", value: "two") : $0
        }, "")))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems + [URLQueryItem(name: "tenant", value: "one")], "")))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems + [URLQueryItem(name: "state", value: state)], "")))
        #expect(!oauth.handleAuthorizationCallback(makeCallback(validItems + [URLQueryItem(name: "code", value: "duplicate")], "")))
        let callback = makeCallback(validItems, "")
        #expect(oauth.handleAuthorizationCallback(callback))
        #expect(!oauth.handleAuthorizationCallback(callback))
        #expect(await waitForAuthorization(oauth))
        oauth.authorize(provider: testProvider)
        let errorState = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!
            .queryItems!.first(where: { $0.name == "state" })!.value!
        let errorItems = [
            URLQueryItem(name: "tenant", value: "one"),
            URLQueryItem(name: "state", value: errorState),
            URLQueryItem(name: "error", value: "access_denied"),
            URLQueryItem(name: "iss", value: "https://auth.example/issuer+v1")
        ]
        #expect(!oauth.handleAuthorizationCallback(makeCallback(errorItems.filter { $0.name != "iss" }, "")))
        #expect(oauth.handleAuthorizationCallback(makeCallback(errorItems, "")))
        #expect(oauth.state == .error(testProvider, .badResponse))
        oauth.authorize(provider: testProvider)
        let clearedState = URLComponents(url: oauth.activeAuthorizationURL!, resolvingAgainstBaseURL: false)!
            .queryItems!.first(where: { $0.name == "state" })!.value!
        let callbackAfterClear = makeCallback([
            URLQueryItem(name: "tenant", value: "one"),
            URLQueryItem(name: "code", value: "must-not-be-exchanged"),
            URLQueryItem(name: "state", value: clearedState),
            URLQueryItem(name: "iss", value: "https://auth.example/issuer+v1")
        ], "")
        oauth.clear()
        #expect(!oauth.handleAuthorizationCallback(callbackAfterClear))
    }

    /// Captures every OAuth response diagnostic and verifies that no credential payload is emitted.
    @Test("Captured OAuth Diagnostics Contain No Credentials")
    func whenCapturingOAuthDiagnostics() async throws {
        var debugProvider = provider
        debugProvider.debug = true
        let options: [OAuth.Option: Any] = [
            .applicationTag: "oauthkit.diagnostics." + .secureRandom(),
            .urlSession: Self.urlSession
        ]
        let diagnosticOAuth = OAuth(providers: [debugProvider], options: options)
        var captured = [String]()
        diagnosticOAuth.diagnosticOutput = { captured.append($0) }
        var secrets = ["AUTH_CODE_SENTINEL", "CALLBACK_CODE_SENTINEL", "CALLBACK_STATE_SENTINEL", "DEVICE_CODE_SENTINEL"]

        await diagnosticOAuth.requestToken(provider: debugProvider, code: secrets[0])
        if case .authorized(_, let authorization) = diagnosticOAuth.state {
            secrets.append(authorization.token.accessToken)
            if let refreshToken = authorization.token.refreshToken { secrets.append(refreshToken) }
        }
        await diagnosticOAuth.refreshToken(provider: debugProvider)
        if case .authorized(_, let authorization) = diagnosticOAuth.state {
            secrets.append(authorization.token.accessToken)
            if let refreshToken = authorization.token.refreshToken { secrets.append(refreshToken) }
        }
        await diagnosticOAuth.requestDeviceCode(provider: debugProvider)
        if case .receivedDeviceCode(_, let deviceCode) = diagnosticOAuth.state {
            secrets.append(deviceCode.deviceCode)
            secrets.append(deviceCode.userCode)
        }
        await diagnosticOAuth.requestClientCredentials(provider: debugProvider)
        if case .authorized(_, let authorization) = diagnosticOAuth.state {
            secrets.append(authorization.token.accessToken)
            if let refreshToken = authorization.token.refreshToken { secrets.append(refreshToken) }
        }
        let deviceCode = OAuth.DeviceCode(
            deviceCode: secrets[3],
            userCode: "DEVICE_USER_CODE_SENTINEL",
            verificationUri: "https://example.com/device",
            expiresIn: 1800,
            interval: 5
        )
        secrets.append(deviceCode.userCode)
        await diagnosticOAuth.poll(provider: debugProvider, deviceCode: deviceCode)
        if case .authorized(_, let authorization) = diagnosticOAuth.state {
            secrets.append(authorization.token.accessToken)
            if let refreshToken = authorization.token.refreshToken { secrets.append(refreshToken) }
        }

        diagnosticOAuth.authorize(provider: debugProvider)
        if let redirect = debugProvider.redirectURI,
           var callback = URLComponents(string: redirect) {
            callback.queryItems = [
                URLQueryItem(name: "code", value: "CALLBACK_CODE_SENTINEL"),
                URLQueryItem(name: "state", value: "CALLBACK_STATE_SENTINEL")
            ]
            if let url = callback.url {
                #expect(!diagnosticOAuth.handleAuthorizationCallback(url))
            }
        }
        let output = captured.joined(separator: "\n")
        #expect(captured.count == 5)
        #expect(captured.allSatisfy { $0.contains("status: 200") && $0.contains(debugProvider.id) })
        #expect(secrets.allSatisfy { !output.contains($0) })
        #expect(!output.contains("access_token"))
        #expect(!output.contains("refresh_token"))
        #expect(!output.contains("id_token"))
        #expect(!output.contains("CALLBACK_STATE_SENTINEL"))
        diagnosticOAuth.clear()
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
    /// Arrange: initiate client credentials through the retained task registry.
    /// Act: wait for the mocked token response to be published and the task to finish.
    /// Assert: the completed task has been pruned from the registry.
    @Test("Completed asynchronous tasks are removed")
    func whenCompletedTaskIsPruned() async throws {
        oauth.authorize(provider: provider, grantType: .clientCredentials)
        let monitor = OAuth.Monitor(oauth: oauth)
        for await state in monitor.stream {
            if case .authorized = state { break }
        }
        for _ in 0..<10 where oauth.activeTaskCount > 0 {
            await Task.yield()
        }
        #expect(oauth.activeTaskCount == 0)
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
