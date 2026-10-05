#if canImport(AuthenticationServices) && (os(iOS) || os(macOS) || os(visionOS))
import AuthenticationServices
import Foundation
@testable import OAuthKit
import Testing

@MainActor
private final class OAuthExternalAuthenticationSessionFake: OAuthExternalAuthenticationSession {
    var prefersEphemeralWebBrowserSession = false
    var presentationContextProvider: (any ASWebAuthenticationPresentationContextProviding)?
    var started = false
    var cancelled = false
    var startResult = true
    var completion: ((URL?, Error?) -> Void)?

    func start() -> Bool {
        started = true
        return startResult
    }

    func cancel() {
        cancelled = true
    }
}

@MainActor
@Suite("OAuth System Browser Session")
struct OAWebViewSessionTests {
    @Test("System session is ephemeral by default and dismissal cancels the transaction")
    func whenStartingAndDismissingExternalSession() {
        let provider = makeProvider()
        let oauth = makeOAuth(provider: provider)
        oauth.authorize(provider: provider)
        let fake = OAuthExternalAuthenticationSessionFake()
        let view = OAWebView(oauth: oauth, sessionFactory: { _, _, completion in
            fake.completion = completion
            return fake
        })

        view.start(provider: provider, anchor: makePresentationAnchor())
        #expect(fake.started)
        #expect(fake.prefersEphemeralWebBrowserSession)
        #expect(fake.presentationContextProvider != nil)
        view.cancel()
        #expect(fake.cancelled)
        #expect(oauth.state == .empty)
        #expect(oauth.activeAuthorizationURL == nil)
    }

    @Test("Persistent cookies require explicit opt-in")
    func whenPersistenceIsExplicitlyEnabled() {
        let provider = makeProvider()
        let oauth = makeOAuth(provider: provider, persistBrowserSession: true)
        oauth.authorize(provider: provider)
        let fake = OAuthExternalAuthenticationSessionFake()
        let view = OAWebView(oauth: oauth, sessionFactory: { _, _, _ in fake })

        view.start(provider: provider, anchor: makePresentationAnchor())
        #expect(fake.started)
        #expect(!fake.prefersEphemeralWebBrowserSession)
        view.cancel()
    }

    @Test("Failed system-session startup cancels only its pending transaction")
    func whenSystemSessionFailsToStart() {
        let provider = makeProvider()
        let oauth = makeOAuth(provider: provider)
        oauth.authorize(provider: provider)
        let fake = OAuthExternalAuthenticationSessionFake()
        fake.startResult = false
        let view = OAWebView(oauth: oauth, sessionFactory: { _, _, _ in fake })

        view.start(provider: provider, anchor: makePresentationAnchor())
        #expect(fake.started)
        #expect(fake.cancelled)
        #expect(oauth.state == .empty)
        #expect(oauth.activeAuthorizationURL == nil)
    }

    @Test("Replacing a transaction cancels its session and ignores its late completion")
    func whenReplacingExternalSessionTransaction() async {
        let provider = makeProvider()
        let oauth = makeOAuth(provider: provider)
        oauth.authorize(provider: provider)
        let first = OAuthExternalAuthenticationSessionFake()
        let second = OAuthExternalAuthenticationSessionFake()
        var sessions = [first, second]
        var index = 0
        let view = OAWebView(oauth: oauth, sessionFactory: { _, _, completion in
            let session = sessions[index]
            sessions[index].completion = completion
            index += 1
            return session
        })

        view.start(provider: provider, anchor: makePresentationAnchor())
        let firstGeneration = oauth.activeAuthorizationGeneration
        oauth.authorize(provider: provider)
        let replacementGeneration = oauth.activeAuthorizationGeneration
        view.start(provider: provider, anchor: makePresentationAnchor())
        #expect(first.cancelled)
        #expect(second.started)
        #expect(firstGeneration != replacementGeneration)

        first.completion?(nil, NSError(domain: "late session completion", code: 1))
        await Task.yield()
        #expect(oauth.activeAuthorizationGeneration == replacementGeneration)
        #expect(oauth.state == .authorizing(provider, .authorizationCode))
        view.cancel()
    }

    @Test("A rejected system callback ends its closed browser transaction")
    func whenSystemCallbackIsRejected() async {
        let provider = makeProvider()
        let oauth = makeOAuth(provider: provider)
        oauth.authorize(provider: provider)
        let fake = OAuthExternalAuthenticationSessionFake()
        let view = OAWebView(oauth: oauth, sessionFactory: { _, _, completion in
            fake.completion = completion
            return fake
        })
        view.start(provider: provider, anchor: makePresentationAnchor())

        fake.completion?(URL(string: "https://attacker.example/callback")!, nil)
        await Task.yield()
        #expect(oauth.state == .empty)
        #expect(oauth.activeAuthorizationURL == nil)
    }

    @Test("HTTPS redirects use the registered host and path callback")
    func whenUsingHTTPSCallback() {
        let provider = OAuth.Provider(
            id: "https-session-test",
            authorizationURL: URL(string: "https://auth.example/authorize")!,
            accessTokenURL: URL(string: "https://auth.example/token")!,
            clientID: "test-client",
            clientSecret: nil,
            redirectURI: "https://callback.example/oauth/return"
        )
        let oauth = makeOAuth(provider: provider)
        oauth.authorize(provider: provider)
        let fake = OAuthExternalAuthenticationSessionFake()
        var usedHTTPSCallback = false
        let view = OAWebView(oauth: oauth, sessionFactory: { _, callback, _ in
            if case .https(let host, let path) = callback {
                usedHTTPSCallback = host == "callback.example" && path == "/oauth/return"
            }
            return fake
        })

        view.start(provider: provider, anchor: makePresentationAnchor())
        #expect(usedHTTPSCallback)
        view.cancel()
    }

    private func makeOAuth(provider: OAuth.Provider, persistBrowserSession: Bool = false) -> OAuth {
        var options: [OAuth.Option: Any] = [.applicationTag: "oauthkit.session." + .secureRandom()]
        if persistBrowserSession {
            options[.persistBrowserSession] = true
        }
        return OAuth(providers: [provider], options: options)
    }

    private func makeProvider() -> OAuth.Provider {
        OAuth.Provider(
            id: "system-session-test",
            authorizationURL: URL(string: "https://auth.example/authorize")!,
            accessTokenURL: URL(string: "https://auth.example/token")!,
            clientID: "test-client",
            clientSecret: nil,
            redirectURI: "oauthkit-test://callback"
        )
    }

    private func makePresentationAnchor() -> ASPresentationAnchor {
        #if os(macOS)
        NSWindow()
        #else
        UIWindow()
        #endif
    }
}
#endif
