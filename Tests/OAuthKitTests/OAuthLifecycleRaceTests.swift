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
        oauth.clear()
        await gate.release(withAccessToken: "stale-cleared-token")
        await refresh.value

        // Assert: the stale response neither restores keychain data nor publishes an authorization.
        #expect(oauth.state == .empty)
        #expect((try? oauth.keychain.get(key: provider.id)) == nil)
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
        #expect((try? oauth.keychain.get(key: provider.id)) == oldAuthorization)
    }

    @Test("Concurrent refreshes for the same provider send one request")
    func concurrentRefreshesAreCoalesced() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let (oauth, _) = try Self.oauth(provider: provider)

        // Arrange: hold the network response while two refresh operations overlap.
        async let first: Void = oauth.refreshToken(provider: provider)
        async let second: Void = oauth.refreshToken(provider: provider)
        await gate.waitForRequest()

        // Act: release the single held response after both callers have begun.
        await gate.release(withAccessToken: "refreshed-token")
        _ = await (first, second)

        // Assert: the same-provider refreshes shared one request and published its response.
        #expect(await gate.requestCount == 1)
        if case .authorized(let actualProvider, let authorization) = oauth.state {
            #expect(actualProvider == provider)
            #expect(authorization.token.accessToken == "refreshed-token")
        } else {
            #expect(Bool(false))
        }
    }

    private static func provider(host: String) -> OAuth.Provider {
        .init(id: host,
              authorizationURL: URL(string: "https://\(host)/authorize")!,
              accessTokenURL: URL(string: "https://\(host)/token")!,
              clientID: "test-client",
              clientSecret: "test-secret")
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
