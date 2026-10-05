//
//  OAWebViewCoordinator.swift
//  
//
//  Created by Kevin McKee
//

#if canImport(WebKit)
import SwiftUI
import WebKit

/// Coordinates  ``OAuth/state-swift.property``   changes inside a ``OAWebView``.
@MainActor
public class OAWebViewCoordinator: NSObject {

    var webView: OAWebView

    /// The oauth reference.
    var oauth: OAuth {
        webView.oauth
    }

    /// Initializer
    /// - Parameter webView: the webview that is being coordinated.
    init(_ webView: OAWebView) {
        self.webView = webView
        super.init()
    }

    /// Handles the authorization url for the specified provider.
    /// - Parameters:
    ///   - url: the url to handle
    ///   - provider: the oauth provider
    ///   - grantType: the grant type to handle
    private func handle(url: URL, provider: OAuth.Provider, grantType: OAuth.GrantType) {
        _ = provider
        _ = grantType
        oauth.handleAuthorizationCallback(url)
    }

    /// Handles oauth state changes.
    /// - Parameter state: the published state change.
    func update(state: OAuth.State) {
        switch state {
        case .empty, .error, .authorized, .requestingAccessToken, .requestingDeviceCode:
            break
        case .authorizing(let provider, let grantType):
            // Override the custom user agent for the provider and tell the browser to load the request
            webView.view.customUserAgent = provider.customUserAgent
            // Tell the webView to load the authorization request
            guard let request = OAuth.Request.auth(provider: provider, grantType: grantType) else { return }
            webView.view.load(request)
        case .receivedDeviceCode(let provider, let deviceCode):
            // Override the custom user agent for the provider and tell the browser to load the request
            webView.view.customUserAgent = provider.customUserAgent
            // Tell the webView to load the device code verification request
            guard let url = URL(string: deviceCode.verificationUri) else { return }
            let request = URLRequest(url: url)
            webView.view.load(request)
        }
    }
}

extension OAWebViewCoordinator: WKNavigationDelegate {

    public func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction) async -> WKNavigationActionPolicy {
        guard let url = navigationAction.request.url else { return .cancel }
        switch oauth.state {
        case .empty, .error, .requestingAccessToken, .authorized, .requestingDeviceCode, .receivedDeviceCode:
            break
        case .authorizing(let provider, let grantType):
            handle(url: url, provider: provider, grantType: grantType)
        }
        return .allow
    }
}

#endif
