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

@MainActor
protocol OAuthExternalAuthenticationSession: AnyObject {
    var prefersEphemeralWebBrowserSession: Bool { get set }
    var presentationContextProvider: (any ASWebAuthenticationPresentationContextProviding)? { get set }
    func start() -> Bool
    func cancel()
}

extension ASWebAuthenticationSession: OAuthExternalAuthenticationSession {}

enum OAuthExternalAuthenticationCallback {
    case customScheme(String)
    case https(host: String, path: String)
}

typealias OAuthExternalAuthenticationSessionFactory =
    @MainActor (URL, OAuthExternalAuthenticationCallback, @escaping (URL?, Error?) -> Void) -> (any OAuthExternalAuthenticationSession)?


/// Presents OAuth authorization in the operating system's trusted external user agent.
@MainActor
public struct OAWebView: View {
    let oauth: OAuth
    @State private var presentation: AuthenticationPresentationAnchor
    @Environment(\.openURL) private var openURL
    private let sessionFactory: OAuthExternalAuthenticationSessionFactory

    public init(oauth: OAuth) {
        self.init(oauth: oauth, sessionFactory: { url, callback, completion in
            switch callback {
            case .https(let host, let path):
                if #available(iOS 17.4, macOS 14.4, visionOS 1.1, *) {
                    return ASWebAuthenticationSession(
                        url: url,
                        callback: .https(host: host, path: path),
                        completionHandler: completion
                    )
                }
                return nil
            case .customScheme(let scheme):
                if #available(iOS 17.4, macOS 14.4, visionOS 1.1, *) {
                    return ASWebAuthenticationSession(
                        url: url,
                        callback: .customScheme(scheme),
                        completionHandler: completion
                    )
                }
                return ASWebAuthenticationSession(
                    url: url,
                    callbackURLScheme: scheme,
                    completionHandler: completion
                )
            }
        })
    }

    init(oauth: OAuth, sessionFactory: @escaping OAuthExternalAuthenticationSessionFactory) {
        self.oauth = oauth
        self.sessionFactory = sessionFactory
        let presentation = AuthenticationPresentationAnchor()
        self._presentation = State(wrappedValue: presentation)
    }

    public var body: some View {
        Color.clear
            .background(WindowAnchorReader { anchor in
                guard let anchor else { return }
                presentation.anchor = anchor
                if let provider = oauth.activeAuthorizationProvider {
                    start(provider: provider)
                }
            })
            .onChange(of: oauth.authorizationGeneration, initial: true) { _, _ in
                if let provider = oauth.activeAuthorizationProvider {
                    start(provider: provider)
                } else {
                    cancelSession()
                }
            }
            .onChange(of: oauth.state, initial: true) { _, state in
                switch state {
                case .authorizing(let provider, _):
                    start(provider: provider)
                case .receivedDeviceCode(let provider, let code):
                    if code.isExpired {
                        oauth.failDeviceAuthorization(provider: provider)
                    } else if let url = URL(string: code.verificationUri) {
                        openURL(url)
                    } else {
                        oauth.failDeviceAuthorization(provider: provider)
                    }
                default:
                    cancelSession()
                }
            }
            .onDisappear(perform: cancel)
    }

    func start(provider: OAuth.Provider, anchor: ASPresentationAnchor? = nil) {
        guard let generation = oauth.activeAuthorizationGeneration,
              oauth.activeAuthorizationProvider?.id == provider.id else { return }
        if presentation.generation == generation, presentation.session != nil { return }
        cancelSession()
        guard let presentationAnchor = anchor ?? presentation.anchor,
              let redirect = provider.redirectURI,
              let redirectComponents = URLComponents(string: redirect),
              let scheme = redirectComponents.scheme,
              let authorizationURL = oauth.activeAuthorizationURL else { return }
        let callback: OAuthExternalAuthenticationCallback
        if scheme.lowercased() == "https" {
            guard #available(iOS 17.4, macOS 14.4, visionOS 1.1, *),
                  let host = redirectComponents.host else {
                oauth.cancelAuthorization(generation: generation)
                return
            }
            callback = .https(host: host, path: redirectComponents.path)
        } else if scheme.lowercased() == "http" {
            // ASWebAuthenticationSession has no HTTP callback matcher, including loopback URLs.
            oauth.cancelAuthorization(generation: generation)
            return
        } else {
            callback = .customScheme(scheme)
        }

        let completion: (URL?, Error?) -> Void = { [weak oauth] callbackURL, error in
            Task { @MainActor in
                guard let oauth, oauth.activeAuthorizationGeneration == generation else { return }
                if let callbackURL {
                    if !oauth.handleAuthorizationCallback(callbackURL, generation: generation) {
                        oauth.cancelAuthorization(generation: generation)
                    }
                } else if error != nil {
                    oauth.cancelAuthorization(generation: generation)
                }
            }
        }
        guard let authSession = sessionFactory(authorizationURL, callback, completion) else {
            oauth.cancelAuthorization(generation: generation)
            return
        }
        presentation.anchor = presentationAnchor
        authSession.presentationContextProvider = presentation
        authSession.prefersEphemeralWebBrowserSession = !oauth.persistBrowserSession
        presentation.session = authSession
        presentation.generation = generation
        guard authSession.start() else {
            cancelSession()
            oauth.cancelAuthorization(generation: generation)
            return
        }
    }

    func cancel() {
        let generation = presentation.generation
        cancelSession()
        if let generation {
            oauth.cancelAuthorization(generation: generation)
        }
    }

    private func cancelSession() {
        presentation.session?.cancel()
        presentation.session = nil
        presentation.generation = nil
    }
}


@MainActor
private final class AuthenticationPresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    weak var anchor: ASPresentationAnchor?
    var session: (any OAuthExternalAuthenticationSession)?
    var generation: UInt64?

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let anchor else {
            preconditionFailure("An authentication session requires its hosting window")
        }
        return anchor
    }
}

#if os(macOS)
@MainActor
private struct WindowAnchorReader: NSViewRepresentable {
    let onWindow: (NSWindow?) -> Void

    func makeNSView(context: Context) -> AnchorView {
        let view = AnchorView()
        view.onWindow = onWindow
        return view
    }

    func updateNSView(_ view: AnchorView, context: Context) {
        view.onWindow = onWindow
        onWindow(view.window)
    }
}

@MainActor
private final class AnchorView: NSView {
    var onWindow: ((NSWindow?) -> Void)?
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        onWindow?(window)
    }
}
#else
@MainActor
private struct WindowAnchorReader: UIViewRepresentable {
    let onWindow: (UIWindow?) -> Void

    func makeUIView(context: Context) -> AnchorView {
        let view = AnchorView()
        view.onWindow = onWindow
        return view
    }

    func updateUIView(_ view: AnchorView, context: Context) {
        view.onWindow = onWindow
        onWindow(view.window)
    }
}

@MainActor
private final class AnchorView: UIView {
    var onWindow: ((UIWindow?) -> Void)?
    override func didMoveToWindow() {
        super.didMoveToWindow()
        onWindow?(window)
    }
}
#endif


#endif
