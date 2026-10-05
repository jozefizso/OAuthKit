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
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
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

        // Act: supersede the device request and release its successful response.
        oauth.authorize(provider: provider)
        await gate.release(withAccessToken: "stale-device-response")
        await request.value

        // Assert: the newer flow and stored credentials remain unchanged.
        #expect(oauth.state == .authorizing(provider, .authorizationCode))
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

        // Act: supersede the request and release its successful response.
        oauth.authorize(provider: provider)
        await gate.release(withAccessToken: "stale-client-response")
        await request.value

        // Assert: the newer flow and stored credentials remain unchanged.
        #expect(oauth.state == .authorizing(provider, .authorizationCode))
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
        oauth.state = .empty
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

    @Test("A superseded browser callback cannot replace client credentials")
    func browserCallbackCannotReplaceClientCredentials() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let (oauth, _) = try Self.oauth(provider: provider)
        defer { _ = try? oauth.clear() }
        oauth.authorize(provider: provider)
        let generation = try #require(oauth.activeAuthorizationGeneration)
        let authorizationURL = try #require(oauth.activeAuthorizationURL)
        let state = try #require(URLComponents(url: authorizationURL, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "state" })?.value)
        var callback = try #require(URLComponents(string: provider.redirectURI!))
        callback.queryItems = [.init(name: "code", value: "old-browser-code"), .init(name: "state", value: state)]
        let callbackURL = try #require(callback.url)

        oauth.authorize(provider: provider, grantType: .clientCredentials)
        try #require(oauth.activeAuthorizationURL == nil)
        await gate.waitForRequest()
        #expect(!oauth.handleAuthorizationCallback(callbackURL, generation: generation))
        oauth.cancelAuthorization(generation: generation)
        await gate.release(withAccessToken: "client-credentials-token")
        let monitor = OAuth.Monitor(oauth: oauth)
        for await state in monitor.stream {
            if case .authorized = state { break }
        }
        #expect(await gate.requestCount == 1)
        guard case .authorized(_, let authorization) = oauth.state else {
            Issue.record("The replacement client-credentials flow must complete")
            return
        }
        #expect(authorization.token.accessToken == "client-credentials-token")
    }

    @Test("Device verification failure cannot be overwritten by a held token response")
    func deviceVerificationFailureRejectsLateToken() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let (oauth, original) = try Self.oauth(provider: provider)
        defer { _ = try? oauth.clear() }
        let code = OAuth.DeviceCode(deviceCode: "device", userCode: "user",
                                    verificationUri: "https://example.com/device", expiresIn: 30, interval: 1)
        oauth.state = .receivedDeviceCode(provider, code)
        oauth.devicePollingSleep = { _ in }
        let polling = Task { await oauth.poll(provider: provider, deviceCode: code) }
        await gate.waitForRequest()
        oauth.failDeviceAuthorization(provider: provider)
        await gate.release(withAccessToken: "must-not-be-stored")
        await polling.value
        #expect(oauth.state == .error(provider, .badResponse))
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored == original)
    }
    @Test("Device-code deadline cancels an in-flight token request")
    func deviceCodeDeadlineCancelsHeldRequest() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let (oauth, original) = try Self.oauth(provider: provider)
        let code = OAuth.DeviceCode(
            deviceCode: "device",
            userCode: "user",
            verificationUri: "https://example.com/device",
            expiresIn: 3,
            interval: 1
        )
        oauth.state = .receivedDeviceCode(provider, code)
        // Arrange: start polling and hold the token endpoint response.
        let started = ContinuousClock.now
        let polling = Task { await oauth.poll(provider: provider, deviceCode: code) }
        await gate.waitForRequest()
        let requestStarted = ContinuousClock.now

        // Act: keep the HTTP response held and wait for the absolute device-code expiry.
        await polling.value
        let elapsed = started.duration(to: ContinuousClock.now)
        let requestLifetime = requestStarted.duration(to: ContinuousClock.now)
        #expect(requestLifetime < .milliseconds(2800))
        #expect(elapsed < .milliseconds(3800))

        // Assert: expiry cancels the held request and leaves stored credentials untouched.
        #expect(oauth.state == .error(provider, .expiredDeviceCode))
        #expect(await gate.requestCount == 1)
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: provider.id)
        #expect(stored == original)
    }


    @Test("OAuth instances in one Keychain namespace share refresh flights")
    func refreshesAreCoalescedAcrossInstances() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let tag = "oauthkit.lifecycle.shared." + UUID().uuidString
        let (first, _) = try Self.oauth(provider: provider, tag: tag)
        let (second, _) = try Self.oauth(provider: provider, tag: tag)
        first.state = .empty
        second.state = .empty

        // Arrange: hold the first instance's refresh request, then start the same provider on another instance.
        let firstRefresh = Task { await first.refreshToken(provider: provider) }
        await gate.waitForRequest()
        let secondRefresh = Task { await second.refreshToken(provider: provider) }
        await Task.yield()

        // Act: release one response with a rotated refresh token.
        await gate.release(withAccessToken: "shared-refresh-token", refreshToken: "shared-rotated-token")
        await firstRefresh.value
        await secondRefresh.value

        // Assert: both callers share one network exchange and storage contains the rotated credential.
        #expect(await gate.requestCount == 1)
        let stored: OAuth.Authorization? = try second.keychain.get(key: provider.id)
        #expect(stored?.token.accessToken == "shared-refresh-token")
        #expect(stored?.token.refreshToken == "shared-rotated-token")
    }

    @Test("Clearing another OAuth instance cancels a shared refresh before persistence")
    func clearingAcrossInstancesRejectsHeldRefresh() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }

        let provider = Self.provider(host: host)
        let tag = "oauthkit.lifecycle.shared." + UUID().uuidString
        let (refreshing, _) = try Self.oauth(provider: provider, tag: tag)
        let (clearing, _) = try Self.oauth(provider: provider, tag: tag)
        refreshing.state = .empty
        clearing.state = .empty

        // Arrange: hold a response started by one instance.
        let refresh = Task { await refreshing.refreshToken(provider: provider) }
        await gate.waitForRequest()

        // Act: clear through another wrapper sharing the same Keychain namespace.
        try clearing.clear()
        await gate.release(withAccessToken: "must-not-be-restored")
        await refresh.value

        // Assert: the cancelled response cannot recreate the deleted credential.
        #expect(refreshing.state == .empty)
        let stored: OAuth.Authorization? = try clearing.keychain.get(key: provider.id)
        #expect(stored == nil)
    }

    @Test("An expired provider without a refresh token does not erase other providers")
    func expiredProviderDeletionIsScoped() async throws {
        let expiredHost = UUID().uuidString.lowercased() + ".oauthkit.test"
        let validHost = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: expiredHost)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: expiredHost) } }

        let expiredProvider = Self.provider(host: expiredHost)
        let validProvider = Self.provider(host: validHost)
        let tag = "oauthkit.lifecycle.scope." + UUID().uuidString
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthHeldResponseURLProtocol.self]
        let oauth = OAuth(providers: [expiredProvider, validProvider], options: [
            .applicationTag: tag,
            .autoRefresh: false,
            .urlSession: URLSession(configuration: configuration),
        ])
        defer { _ = try? oauth.clear() }
        let expired = OAuth.Authorization(
            issuer: expiredProvider.id,
            token: OAuth.Token(accessToken: "expired", refreshToken: nil, expiresIn: 0, scope: nil, type: "Bearer")
        )
        let valid = OAuth.Authorization(
            issuer: validProvider.id,
            token: OAuth.Token(accessToken: "valid", refreshToken: "valid-refresh", expiresIn: 3600, scope: nil, type: "Bearer")
        )
        try #require(try oauth.keychain.set(expired, for: expiredProvider.id))
        try #require(try oauth.keychain.set(valid, for: validProvider.id))

        // Act: refresh the expired credential that cannot be refreshed.
        await oauth.refreshToken(provider: expiredProvider)

        // Assert: only the expired provider record is deleted and no network request was sent.
        let expiredStored: OAuth.Authorization? = try oauth.keychain.get(key: expiredProvider.id)
        let validStored: OAuth.Authorization? = try oauth.keychain.get(key: validProvider.id)
        #expect(expiredStored == nil)
        #expect(validStored == valid)
        #expect(await gate.requestCount == 0)
    }

    @Test("Successful peer clear invalidates pending browser and authorized state")
    func crossInstanceClearInvalidatesPendingBrowserFlow() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let tag = "oauthkit.lifecycle.pending." + UUID().uuidString
        let (clearing, _) = try Self.oauth(provider: provider, tag: tag)
        let (pending, _) = try Self.oauth(provider: provider, tag: tag)
        let (authorizedPeer, _) = try Self.oauth(provider: provider, tag: tag)
        defer { _ = try? clearing.clear(); _ = try? pending.clear(); _ = try? authorizedPeer.clear() }
        pending.authorize(provider: provider)
        let generation = try #require(pending.activeAuthorizationGeneration)
        let authorizationURL = try #require(pending.activeAuthorizationURL)
        let state = try #require(URLComponents(url: authorizationURL, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "state" })?.value)
        var callback = try #require(URLComponents(string: provider.redirectURI!))
        callback.queryItems = [.init(name: "code", value: "late-code"), .init(name: "state", value: state)]
        let callbackURL = try #require(callback.url)

        // Act: clear the shared namespace while the second instance owns a pending browser transaction.
        try clearing.clear()

        // Assert: the browser transaction is invalidated and its callback cannot start a token request.
        #expect(pending.activeAuthorizationURL == nil)
        #expect(pending.activeAuthorizationProvider == nil)
        #expect(pending.activeAuthorizationGeneration == nil)
        #expect(pending.state == .empty)
        #expect(authorizedPeer.state == .empty)
        #expect(!pending.handleAuthorizationCallback(callbackURL, generation: generation))
        #expect(await gate.requestCount == 0)
    }

    @Test("A stale peer callback and cancellation cannot supersede a newer same-provider browser flow")
    func stalePeerBrowserFlowCannotCancelNewerFlow() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let tag = "oauthkit.lifecycle.pending." + UUID().uuidString
        let provider = Self.provider(host: host)
        let (first, _) = try Self.oauth(provider: provider, tag: tag)
        let (second, _) = try Self.oauth(provider: provider, tag: tag)
        defer { _ = try? first.clear(); _ = try? second.clear() }

        // Arrange: create a peer transaction and retain its callback details.
        second.authorize(provider: provider)
        let staleGeneration = try #require(second.activeAuthorizationGeneration)
        let staleURL = try #require(second.activeAuthorizationURL)
        let staleState = try #require(URLComponents(url: staleURL, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "state" })?.value)
        var staleCallback = try #require(URLComponents(string: provider.redirectURI!))
        staleCallback.queryItems = [.init(name: "code", value: "stale-code"), .init(name: "state", value: staleState)]
        let staleCallbackURL = try #require(staleCallback.url)

        // Act: the first instance supersedes that pending transaction with a newer transaction.
        first.authorize(provider: provider)
        let currentGeneration = try #require(first.activeAuthorizationGeneration)
        let currentURL = try #require(first.activeAuthorizationURL)
        second.cancelAuthorization(generation: staleGeneration)

        // Assert: the old callback/cancel operation cannot affect the new instance's transaction.
        #expect(second.activeAuthorizationURL == nil)
        #expect(!second.handleAuthorizationCallback(staleCallbackURL, generation: staleGeneration))
        #expect(first.activeAuthorizationGeneration == currentGeneration)
        #expect(first.activeAuthorizationURL == currentURL)
        #expect(first.activeAuthorizationProvider == provider)
    }

    @Test("A new provider flow cancels the same instance's older held refresh before success")
    func newProviderSuccessRejectsOldRefresh() async throws {
        try await Self.verifyCrossProviderSupersession(newFlowResponse: Data(
            #"{"access_token":"new-provider-token","refresh_token":"new-refresh","expires_in":3600,"token_type":"Bearer"}"#.utf8
        ), statusCode: 200, expectsSuccess: true)
    }

    @Test("A new provider error flow cannot be overwritten by an older held refresh")
    func newProviderFailureRejectsOldRefresh() async throws {
        try await Self.verifyCrossProviderSupersession(newFlowResponse: Data("invalid token response".utf8), statusCode: 200, expectsSuccess: false)
    }

    @Test("Shared refresh decoding failures reach every caller without restoring stale authorization")
    func sharedRefreshFailurePropagatesToJoiner() async throws {
        try await Self.verifySharedRefreshFailure(
            body: Data("invalid token response".utf8),
            statusCode: 200,
            expectedError: .decoding,
            credentialDeleted: false
        )
    }

    @Test("Shared invalid_grant deletes the credential and reaches every caller")
    func sharedInvalidGrantPropagatesToJoiner() async throws {
        try await Self.verifySharedRefreshFailure(
            body: Data(#"{"error":"invalid_grant"}"#.utf8),
            statusCode: 400,
            expectedError: .oauth("invalid_grant"),
            credentialDeleted: true
        )
    }

    @Test("Abandoned OAuth clients are not retained by delayed auto-refresh tasks")
    func delayedAutoRefreshDoesNotRetainClient() async throws {
        let provider = Self.provider(host: UUID().uuidString.lowercased() + ".oauthkit.test")
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthHeldResponseURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let tag = "oauthkit.lifecycle.auto-refresh." + UUID().uuidString
        let token = OAuth.Token(accessToken: "scheduled-token", refreshToken: "scheduled-refresh", expiresIn: 60, scope: nil, type: "Bearer")
        let authorization = OAuth.Authorization(issuer: provider.id, token: token)
        let keychain = Keychain(tag)
        try #require(try keychain.set(authorization, for: provider.id))
        defer { _ = try? keychain.clear() }
        var oauth: OAuth? = OAuth(providers: [provider], keychain: keychain, options: [
            .autoRefresh: true,
            .urlSession: session,
        ])
        weak var weakOAuth = oauth
        #expect(oauth?.activeTaskCount == 1)

        // Arrange: initialization restores a future-expiring authorization and starts its delayed refresh.
        for _ in 0..<10 {
            await Task.yield()
        }

        // Act: abandon the client while its refresh delay is still pending.
        oauth = nil

        // Assert: the scheduled task retains only a weak owner until it wakes.
        #expect(weakOAuth == nil)
    }

    @Test("An early-cancelled task is removed from its owner's local registry")
    func peerClearCleansQueuedTaskRegistry() async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let tag = "oauthkit.lifecycle.queued-task." + UUID().uuidString
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let (initiating, _) = try Self.oauth(provider: provider, tag: tag)
        let (clearing, _) = try Self.oauth(provider: provider, tag: tag)

        // Arrange: queue client-credentials work without yielding the main actor.
        initiating.authorize(provider: provider, grantType: .clientCredentials)
        #expect(initiating.activeTaskCount == 1)

        // Act: a peer clears the shared namespace before the queued task can begin.
        try clearing.clear()
        for _ in 0..<10 where initiating.activeTaskCount != 0 {
            await Task.yield()
        }

        // Assert: both the task and its local registry entry are gone.
        #expect(initiating.activeTaskCount == 0)
        #expect(await gate.requestCount == 0)
    }

    @Test("A still-current refresh joiner receives an error when its owner changes providers")
    func ownerProviderChangeTerminatesSharedRefreshJoiner() async throws {
        let oldHost = UUID().uuidString.lowercased() + ".oauthkit.test"
        let newHost = UUID().uuidString.lowercased() + ".oauthkit.test"
        let oldGate = OAuthHeldResponseGate()
        let newGate = OAuthHeldResponseGate()
        await newGate.release(
            response: Data(#"{"access_token":"new-provider-token","refresh_token":"new-refresh","expires_in":3600,"token_type":"Bearer"}"#.utf8),
            statusCode: 200
        )
        await OAuthHeldResponseRegistry.register(oldGate, for: oldHost)
        await OAuthHeldResponseRegistry.register(newGate, for: newHost)
        defer {
            Task { await OAuthHeldResponseRegistry.remove(for: oldHost) }
            Task { await OAuthHeldResponseRegistry.remove(for: newHost) }
        }

        var oldProvider = Self.provider(host: oldHost)
        var newProvider = Self.provider(host: newHost)
        oldProvider.issuer = "https://issuer-\(oldHost)"
        newProvider.issuer = "https://issuer-\(newHost)"
        let tag = "oauthkit.lifecycle.joiner-cancel." + UUID().uuidString
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthHeldResponseURLProtocol.self]
        let owner = OAuth(providers: [oldProvider, newProvider], options: [
            .applicationTag: tag,
            .autoRefresh: false,
            .urlSession: URLSession(configuration: configuration),
        ])
        let coordinator = OAuthLifecycleCoordinator.coordinator(for: owner.keychain.lifecycleNamespace)
        let original = OAuth.Authorization(
            issuer: oldProvider.id,
            token: .init(accessToken: "original-token", refreshToken: "refresh-token", expiresIn: 3600, scope: nil, type: "Bearer")
        )
        try #require(try owner.keychain.set(original, for: oldProvider.id))
        owner.state = .empty
        let (joiner, _) = try Self.oauth(provider: oldProvider, tag: tag)
        joiner.state = .empty
        defer { _ = try? owner.clear(); _ = try? joiner.clear() }

        // Arrange: the owner starts a held refresh and a peer joins the same flight.
        let ownerRefresh = Task { await owner.refreshToken(provider: oldProvider) }
        await oldGate.waitForRequest()
        let joinerRefresh = Task { await joiner.refreshToken(provider: oldProvider) }
        for _ in 0..<100 {
            if coordinator.refreshFlight(for: oldProvider.id)?.waiterCount == 2 {
                break
            }
            await Task.yield()
        }
        try #require(coordinator.refreshFlight(for: oldProvider.id)?.waiterCount == 2)

        let ownerMonitor = OAuth.Monitor(oauth: owner)
        let ownerCompleted = Task { @MainActor in
            for await state in ownerMonitor.stream {
                if case .authorized(let provider, _) = state, provider.id == newProvider.id {
                    return
                }
            }
        }

        // Act: changing the owner's provider cancels its shared P flight, but not the joiner's P ticket.
        owner.authorize(provider: newProvider, grantType: .clientCredentials)
        await newGate.waitForRequest()
        await ownerCompleted.value
        await ownerRefresh.value
        await joinerRefresh.value

        // Assert: the still-current joiner terminates in error without retrying P or restoring stale state.
        #expect(joiner.state == .error(oldProvider, .badResponse))
        let storedNewAuthorization: OAuth.Authorization = try #require(try owner.keychain.get(key: newProvider.id))
        let storedOldAuthorization: OAuth.Authorization? = try joiner.keychain.get(key: oldProvider.id)
        #expect(owner.state == .authorized(newProvider, storedNewAuthorization))
        #expect(await oldGate.requestCount == 1)
        #expect(await newGate.requestCount == 1)
        #expect(storedOldAuthorization == original)
    }

    private static func verifyCrossProviderSupersession(
        newFlowResponse: Data,
        statusCode: Int,
        expectsSuccess: Bool
    ) async throws {
        let oldHost = UUID().uuidString.lowercased() + ".oauthkit.test"
        let newHost = UUID().uuidString.lowercased() + ".oauthkit.test"
        let oldGate = OAuthHeldResponseGate()
        let newGate = OAuthHeldResponseGate()
        await oldGate.ignoreCancellation()
        await newGate.release(response: newFlowResponse, statusCode: statusCode)
        await OAuthHeldResponseRegistry.register(oldGate, for: oldHost)
        await OAuthHeldResponseRegistry.register(newGate, for: newHost)
        defer {
            Task { await OAuthHeldResponseRegistry.remove(for: oldHost) }
            Task { await OAuthHeldResponseRegistry.remove(for: newHost) }
        }

        var oldProvider = Self.provider(host: oldHost)
        var newProvider = Self.provider(host: newHost)
        oldProvider.issuer = "https://issuer-\(oldHost)"
        newProvider.issuer = "https://issuer-\(newHost)"
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthHeldResponseURLProtocol.self]
        let oauth = OAuth(providers: [oldProvider, newProvider], options: [
            .applicationTag: "oauthkit.lifecycle.owner." + UUID().uuidString,
            .autoRefresh: false,
            .urlSession: URLSession(configuration: configuration),
        ])
        defer { _ = try? oauth.clear() }
        let original = OAuth.Authorization(
            issuer: oldProvider.id,
            token: OAuth.Token(accessToken: "old-access", refreshToken: "old-refresh", expiresIn: 3600, scope: nil, type: "Bearer")
        )
        try #require(try oauth.keychain.set(original, for: oldProvider.id))
        oauth.state = .empty
        let monitor = OAuth.Monitor(oauth: oauth)
        let completed = Task { @MainActor in
            for await state in monitor.stream {
                switch state {
                case .authorized(let provider, _) where expectsSuccess && provider.id == newProvider.id:
                    return
                case .error(let provider, .decoding) where !expectsSuccess && provider.id == newProvider.id:
                    return
                default:
                    continue
                }
            }
        }

        // Arrange: hold provider A's refresh response, then start a new provider B flow on the same OAuth instance.
        let oldRefresh = Task { await oauth.refreshToken(provider: oldProvider) }
        await oldGate.waitForRequest()

        // Act: supersede A with B, wait for B to publish, then release A's deliberately late response.
        oauth.authorize(provider: newProvider, grantType: .clientCredentials)
        await newGate.waitForRequest()
        await completed.value
        await oldGate.release(withAccessToken: "stale-old-provider-token")
        await oldRefresh.value

        // Assert: A did not replace B's terminal state or alter its original stored credential.
        if expectsSuccess {
            guard case .authorized(let provider, let authorization) = oauth.state else {
                Issue.record("The new provider success must remain the final state")
                return
            }
            #expect(provider.id == newProvider.id)
            #expect(authorization.token.accessToken == "new-provider-token")
        } else {
            #expect(oauth.state == .error(newProvider, .decoding))
        }
        let stored: OAuth.Authorization? = try oauth.keychain.get(key: oldProvider.id)
        #expect(stored == original)
        #expect(await oldGate.requestCount == 1)
        #expect(await newGate.requestCount == 1)
    }

    private static func verifySharedRefreshFailure(
        body: Data,
        statusCode: Int,
        expectedError: OAError,
        credentialDeleted: Bool
    ) async throws {
        let host = UUID().uuidString.lowercased() + ".oauthkit.test"
        let gate = OAuthHeldResponseGate()
        await OAuthHeldResponseRegistry.register(gate, for: host)
        defer { Task { await OAuthHeldResponseRegistry.remove(for: host) } }
        let provider = Self.provider(host: host)
        let tag = "oauthkit.lifecycle.shared-error." + UUID().uuidString
        let (first, _) = try Self.oauth(provider: provider, tag: tag)
        let (second, _) = try Self.oauth(provider: provider, tag: tag)
        let original: OAuth.Authorization = try #require(try first.keychain.get(key: provider.id))
        defer { _ = try? first.clear(); _ = try? second.clear() }
        first.state = .empty
        second.state = .empty

        // Arrange: hold one refresh request while a second instance passes its own Keychain read and joins.
        let firstRefresh = Task { await first.refreshToken(provider: provider) }
        await gate.waitForRequest()
        let secondRefresh = Task { await second.refreshToken(provider: provider) }
        await Task.yield()

        // Act: return one terminal failure to the shared flight.
        await gate.release(response: body, statusCode: statusCode)
        await firstRefresh.value
        await secondRefresh.value

        // Assert: both callers get the same failure, with no stale authorization publication or retry.
        #expect(first.state == .error(provider, expectedError))
        #expect(second.state == .error(provider, expectedError))
        #expect(await gate.requestCount == 1)
        let stored: OAuth.Authorization? = try second.keychain.get(key: provider.id)
        #expect(credentialDeleted ? stored == nil : stored == original)
    }

    private static func provider(host: String) -> OAuth.Provider {
        .init(id: host,
              authorizationURL: URL(string: "https://\(host)/authorize")!,
              accessTokenURL: URL(string: "https://\(host)/token")!,
              deviceCodeURL: URL(string: "https://\(host)/device")!,
              clientID: "test-client",
              clientSecret: "test-secret",
              clientType: .confidential,
              redirectURI: "com.example.oauthkit.lifecycle:/callback")
    }

    private static func oauth(provider: OAuth.Provider, tag: String? = nil) throws -> (OAuth, OAuth.Authorization) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthHeldResponseURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let applicationTag = tag ?? "oauthkit.lifecycle." + UUID().uuidString
        let oauth = OAuth(providers: [provider], options: [
            .applicationTag: applicationTag,
            .autoRefresh: false,
            .urlSession: session,
        ])
        let authorization: OAuth.Authorization
        if let stored: OAuth.Authorization = try oauth.keychain.get(key: provider.id) {
            authorization = stored
        } else {
            let token = OAuth.Token(accessToken: "original-token", refreshToken: "refresh-token", expiresIn: 3600, scope: nil, type: "Bearer")
            authorization = OAuth.Authorization(issuer: provider.id, token: token)
            try #require(try oauth.keychain.set(authorization, for: provider.id))
        }
        oauth.state = .authorized(provider, authorization)
        return (oauth, authorization)
    }
}
