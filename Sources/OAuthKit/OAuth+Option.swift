//
//  OAuth+Option.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation

extension OAuth {

    /// Keys and values used to specify loading or runtime options.
    public struct Option: Hashable, RawRepresentable, Sendable {

        /// The option raw value.
        public var rawValue: String

        /// Initializer
        /// - Parameter rawValue: the option raw value
        public init(rawValue: String) {
            self.rawValue = rawValue
        }
    }
}

public extension OAuth.Option {

    /// A key used for custom application identifiers to improve token tagging.
    static let applicationTag: OAuth.Option = .init(rawValue: "applicationTag")

    /// A key used to specify whether tokens should be automatically refreshed or not.
    static let autoRefresh: OAuth.Option = .init(rawValue: "autoRefresh")

    /// A key used for providing a custom local authentication object.
    static let localAuthentication: OAuth.Option = .init(rawValue: "localAuthentication")

    /// A key used to require biometric authentication for every protected keychain item access.
    /// Authentication is enforced by Keychain access control on every read and write.
    static let requireBiometricAuthentication: OAuth.Option = .init(rawValue: "requireBiometricAuthentication")

    /// A key used for providing a custom url session.
    static let urlSession: OAuth.Option = .init(rawValue: "urlSession")

    /// A key used for setting the WKWebsiteDataStore to `nonPersistent()` in the OAWebView.
    /// This is disabled by default, but this can be turned on to allow developers to use an ephemeral webkit datastore
    /// that effectively implements private browsing and forces a new login attempt every time an authorization flow is started.
    static let useNonPersistentWebDataStore: OAuth.Option = .init(rawValue: "useNonPersistentWebDataStore")
}

