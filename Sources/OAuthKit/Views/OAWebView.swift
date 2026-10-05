//
//  OAWebView.swift
//
//
//  Created by Kevin McKee
//

#if canImport(AuthenticationServices) && canImport(SwiftUI) && (os(iOS) || os(macOS) || os(visionOS))
import AuthenticationServices
import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Presents OAuth authorization in the operating system's trusted external user agent.
@MainActor
public struct OAWebView: View {
    let oauth: OAuth
    @State private var session: ASWebAuthenticationSession?
    @Environment(\.openURL) private var openURL

    public init(oauth: OAuth) {
        self.oauth = oauth
    }

    public var body: some View {
        Color.clear
            .onChange(of: oauth.state, initial: true) { _, state in
                switch state {
                case .authorizing(let provider, _):
                    start(provider: provider)
                case .receivedDeviceCode(_, let code):
                    if let url = URL(string: code.verificationUri) {
                        openURL(url)
                    }
                default:
                    session?.cancel()
                    session = nil
                }
            }
            .onDisappear {
                if session != nil {
                    session?.cancel()
                    session = nil
                    oauth.cancelAuthorization()
                }
            }
    }
    private func start(provider: OAuth.Provider) {
        guard session == nil,
              let redirect = provider.redirectURI,
              let callbackScheme = URLComponents(string: redirect)?.scheme,
              let authorizationURL = oauth.activeAuthorizationURL else {
            oauth.cancelAuthorization()
            return
        }
        let authSession = ASWebAuthenticationSession(url: authorizationURL, callbackURLScheme: callbackScheme) { [weak oauth] callback, error in
            Task { @MainActor in
                guard let oauth else { return }
                if let callback {
                    _ = oauth.handleAuthorizationCallback(callback)
                } else if error != nil {
                    oauth.cancelAuthorization()
                }
            }
        }
        authSession.presentationContextProvider = AuthenticationPresentationAnchor.shared
        authSession.prefersEphemeralWebBrowserSession = !oauth.persistBrowserSession
        session = authSession
        guard authSession.start() else {
            session = nil
            oauth.cancelAuthorization()
            return
        }
    }
}

@MainActor
private final class AuthenticationPresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    static let shared = AuthenticationPresentationAnchor()

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if os(macOS)
        NSApplication.shared.keyWindow ?? NSWindow()
        #else
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? UIWindow()
        #endif
    }
}
#endif


