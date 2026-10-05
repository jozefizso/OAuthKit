//
//  OAWebViewTests.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

#if canImport(WebKit)
import Foundation
@testable import OAuthKit
import SwiftUI
import Testing
import WebKit

@MainActor
@Suite("OAuthWebView Tests", .tags(.views))
final class OAWebViewTests {

    /// The mock url session that overrides the protocol classes with `OAuthTestURLProtocol`
    /// that will intercept all outbound requests and return mocked test data.
    private static let urlSession: URLSession = {
        let configuration: URLSessionConfiguration = .ephemeral
        configuration.protocolClasses = [OAuthTestURLProtocol.self]
        return .init(configuration: configuration)
    }()

    let oauth: OAuth
    let tag: String
    let webView: OAWebView
    var provider: OAuth.Provider {
        oauth.providers.filter{ $0.id == "GitHub" }.first!
    }

    var keychain: Keychain {
        oauth.keychain
    }

    /// Initializer.
    init() async throws {
        tag = "oauthkit.test." + .secureRandom()
        let options: [OAuth.Option: Any] = [
            .applicationTag: tag,
            .autoRefresh: false,
            .useNonPersistentWebDataStore: true,
            .urlSession: Self.urlSession
        ]
        oauth = .init(.module, options: options)
        webView = .init(oauth: oauth)
        #expect(oauth.useNonPersistentWebDataStore == true)
    }

    /// Tests the oauth environment values are correct.
    /// This is kind of a lame test but but provides code coverage for that extension.
    @Test("OAuth EnvironmentValues")
    func testEnvironmentValues() async throws {
        var values: EnvironmentValues = .init()
        values.oauth = oauth
        let environmentOAuth = values.oauth
        #expect(environmentOAuth.providers == oauth.providers)
        #expect(environmentOAuth.state == oauth.state)
    }

    /// Tests the OAWebViewCoordinator coordinator policy decisions.
    @Test("Coordinator Policy Decisons")
    func whenCoordinatorDecidingPolicy() async throws {
        let coordinator = webView.makeCoordinator()
        let wkWebView = webView.view
        var request = URLRequest(url: URL(string: "https://github.com/codefiesta/OAuthKit")!)
        request.url = nil
        var action = OAuthTestWKNavigationAction(urlRequest: request)
        var policy = await coordinator.webView(wkWebView, decidePolicyFor: action)
        #expect(policy == .cancel)

        let code = String.secureRandom()
        oauth.authorize(provider: provider)
        guard case .authorizing(_, .pkce(let pkce)) = oauth.state else {
            Issue.record("Expected generated PKCE authorization")
            return
        }
        coordinator.update(state: oauth.state)
        request = URLRequest(url: URL(string: provider.redirectURI! + "?code=\(code)&state=\(pkce.state)")!)
        action = OAuthTestWKNavigationAction(urlRequest: request)
        policy = await coordinator.webView(wkWebView, decidePolicyFor: action)
        #expect(policy == .allow)
        #expect(await waitForAuthorization())
    }

    /// Tests to make sure the coordinator doesn't being requesting access tokens when we've detected state mismatches.
    @Test("Coordinator Detects Mismatched States")
    func whenCoordinatorDetectsMismatchedStates() async throws {

        // 1) Bad Request Expectations
        let coordinator: OAWebViewCoordinator = webView.makeCoordinator()
        #expect(coordinator.oauth.state == oauth.state)
        let wkWebView = webView.view

        var urlRequest: URLRequest = .init(url: URL(string: "https://github.com/codefiesta/OAuthKit")!)

        oauth.authorize(provider: provider)
        guard case .authorizing(_, .pkce(let pkce)) = oauth.state else {
            Issue.record("Expected generated PKCE authorization")
            return
        }
        let urlString = provider.redirectURI! + "?code=\(String.secureRandom())&state=ABC-123"
        urlRequest = URLRequest(url: URL(string: urlString)!)
        let navigationAction = OAuthTestWKNavigationAction(urlRequest: urlRequest)
        let policy = await coordinator.webView(wkWebView, decidePolicyFor: navigationAction)
        #expect(policy == .allow)
        #expect(oauth.state == .authorizing(provider, .pkce(pkce)))
    }

    /// Streams the oauth status until we receive an authorization.
    /// This should only be used on test methods that expect an authorization to be inserted into the keychain.
    private func waitForAuthorization() async -> Bool {
        let monitor: OAuth.Monitor = .init(oauth: oauth)
        for await state in monitor.stream {
            switch state {
            case .empty, .error, .authorizing, .requestingAccessToken, .requestingDeviceCode, .receivedDeviceCode:
                break
            case .authorized(_, _):
                do { try keychain.clear() }
                catch {
                    Issue.record("Failed to clear stored authorization: \(error)")
                    return false
                }
                return true
            }
        }
        return false
    }
}
#endif
