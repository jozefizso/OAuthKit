import Foundation
@testable import OAuthKit
import Testing

@MainActor
@Suite("OAuth Lifecycle Race Tests")
struct OAuthLifecycleRaceTests {

    @Test("Clearing during a held refresh response cannot persist or publish stale authorization")
    func clearingDuringRefreshDoesNotAcceptStaleResponse() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let (oauth, _) = try Self.oauth(provider: provider)

        // Arrange: start a refresh and hold the successful network response before it can be processed.
        let refresh = Task { await oauth.refreshToken(provider: provider) }
        await gate.waitForRequest()

        // Act: clear authorization while the refresh response remains held, then release that response.
        try oauth.clear()
        await gate.release(withAccessToken: "stale-cleared-token")
        await refresh.value

        // Assert: the stale response neither restores keychain data nor publishes an authorization.
        #expect(oauth.state == .empty)
        let stored: OAuth.Authorization? = try? oauth.keychain.get(key: provider.id)
        #expect(stored == nil)
    }

    @Test("Superseding during a held refresh response cannot publish stale authorization")
    func supersedingDuringRefreshDoesNotPublishStaleResponse() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let (oauth, oldAuthorization) = try Self.oauth(provider: provider)

        // Arrange: start a refresh and wait until its network response is held by the protocol gate.
        let refresh = Task { await oauth.refreshToken(provider: provider) }
        await gate.waitForRequest()

        // Act: supersede the in-flight generation before releasing the response.
        oauth.supersedeTasks()
        await gate.release(withAccessToken: "stale-superseded-token")
        await refresh.value

        // Assert: superseded work leaves both the published authorization and stored value unchanged.
        #expect(oauth.state == .authorized(provider, oldAuthorization))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored == oldAuthorization)
    }

    @Test("Device-code responses cannot overwrite a newer flow")
    func deviceCodeResponseCannotOverwriteNewerFlow() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let (oauth, oldAuthorization) = try Self.oauth(provider: provider)

        // Arrange: hold a device-code response while a newer PKCE flow is pending.
        let request = Task { await oauth.requestDeviceCode(provider: provider) }
        await gate.waitForRequest()
        let pkce = OAuth.PKCE()

        // Act: supersede the device request and release its successful response.
        oauth.authorize(provider: provider, grantType: .pkce(pkce))
        await gate.release(withAccessToken: "stale-device-response")
        await request.value

        // Assert: the newer flow and stored credentials remain unchanged.
        #expect(oauth.state == .authorizing(provider, .pkce(pkce)))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored == oldAuthorization)
    }

    @Test("Client-credentials responses cannot overwrite a newer flow")
    func clientCredentialsResponseCannotOverwriteNewerFlow() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let (oauth, oldAuthorization) = try Self.oauth(provider: provider)

        // Arrange: hold a client-credentials response while a newer PKCE flow is pending.
        let request = Task { await oauth.requestClientCredentials(provider: provider) }
        await gate.waitForRequest()
        let pkce = OAuth.PKCE()

        // Act: supersede the request and release its successful response.
        oauth.authorize(provider: provider, grantType: .pkce(pkce))
        await gate.release(withAccessToken: "stale-client-response")
        await request.value

        // Assert: the newer flow and stored credentials remain unchanged.
        #expect(oauth.state == .authorizing(provider, .pkce(pkce)))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored == oldAuthorization)
    }

    @Test("Concurrent refreshes for the same provider send one request")
    func concurrentPublicRefreshesAreCoalesced() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let (oauth, _) = try Self.oauth(provider: provider)
        oauth.state = .empty

        // Arrange: start two public refresh authorizations while the first response is held.
        oauth.authorize(provider: provider, grantType: .refreshToken)
        oauth.authorize(provider: provider, grantType: .refreshToken)
        await gate.waitForRequest()

        // Act: release one response carrying a rotated refresh token.
        await gate.release(withAccessToken: "refreshed-token", refreshToken: "rotated-refresh-token")
        let monitor = OAuth.Monitor(oauth: oauth)
        for await state in monitor.stream {
            if case .authorized(_, let authorization) = state,
               authorization.token.accessToken == "refreshed-token" {
                break
            }
        }

        // Assert: one request updated both observable state and persisted credentials.
        #expect(await gate.requestCount == 1)
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored?.token.refreshToken == "rotated-refresh-token")
    }

    private static func provider(host: String) -> OAuth.Provider {
        .init(id: host,
              authorizationURL: URL(string: "https://\(host)/authorize")!,
              accessTokenURL: URL(string: "https://\(host)/token")!,
              deviceCodeURL: URL(string: "https://\(host)/device")!,
              clientID: "test-client",
              clientSecret: "test-secret",
              clientType: .confidential,
              redirectURI: "com.example.oauthkit:/oauth/callback")
    }

    private static func oauth(provider: OAuth.Provider) throws -> (OAuth, OAuth.Authorization) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthHeldResponseURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let tag = "oauthkit.lifecycle." + UUID().uuidString
        let oauth = OAuth(providers: [provider], options: [
            .applicationTag: tag,
            .autoRefresh: false,
            .urlSession: session,
        ])
        let token = OAuth.Token(accessToken: "original-token", refreshToken: "refresh-token", expiresIn: 3600, scope: nil, type: "Bearer")
        let authorization = OAuth.Authorization(issuer: provider.id, token: token)
        try #require(try oauth.keychain.set(authorization, for: provider.id))
        oauth.state = .authorized(provider, authorization)
        return (oauth, authorization)
    }
}
