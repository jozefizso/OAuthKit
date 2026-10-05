//
//  OAuth+Provider.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation

extension OAuth {

    /// Classifies whether the OAuth client can keep credentials confidential.
    public enum ClientType: String, Codable, Hashable, Sendable {
        case `public`
        case confidential
    }

    /// Selects exactly one authentication method for token endpoint requests.
    public enum ClientAuthentication: String, Codable, Hashable, Sendable {
        case none
        case clientSecretBasic
        case clientSecretPost
    }

    /// Provides configuration data for an OAuth 2.0 service provider.
    public struct Provider: Codable, Identifiable, Hashable, Sendable {

        /// The provider unique id.
        public var id: String
        /// The provider icon.
        public var icon: URL?
        /// The provider authorization url.
        public var authorizationURL: URL
        /// The provider access token url.
        public var accessTokenURL: URL
        /// The provider device code url that can be used for devices without browsers (like tvOS).
        public var deviceCodeURL: URL?
        /// The provider redirect uri.
        public var redirectURI: String?
        /// Whether this is a distributed public client or a confidential backend client.
        public var clientType: ClientType
        /// Token endpoint authentication method. Public clients must use `.none`.
        public var clientAuthentication: ClientAuthentication
        /// The unique client identifier for interacting with this providers oauth server.
        var clientID: String
        /// The confidential client secret.
        var clientSecret: String?
        /// The provider scopes.
        public var scope: [String]?
        /// The custom user agent to send with browser requests.
        public var customUserAgent: String?
        /// Enables provider debugging. Off by default.
        public var debug: Bool

        /// The coding keys.
        enum CodingKeys: String, CodingKey {
            case id, icon, authorizationURL, accessTokenURL, deviceCodeURL
            case clientID, clientSecret, clientType, clientAuthentication
            case redirectURI, scope, customUserAgent, debug
        }

        /// Creates provider configuration. Client classification is explicit and defaults to a public client.
        /// - Parameters:
        ///   - id: The provider unique id
        ///   - icon: The provider icon
        ///   - authorizationURL: The provider authorization URL
        ///   - accessTokenURL: The provider access-token URL
        ///   - deviceCodeURL: The optional device authorization URL
        ///   - clientID: The client identifier
        ///   - clientSecret: A secret for confidential clients
        ///   - clientType: Explicit client classification, public by default
        ///   - clientAuthentication: Token endpoint method; Basic by default for confidential clients
        ///   - redirectURI: The redirect URI
        ///   - scope: The requested scopes
        ///   - customUserAgent: A custom browser user agent
        ///   - debug: Whether provider debugging is enabled
        public init(id: String,
                    icon: URL? = nil,
                    authorizationURL: URL,
                    accessTokenURL: URL,
                    deviceCodeURL: URL? = nil,
                    clientID: String,
                    clientSecret: String? = nil,
                    clientType: ClientType = .public,
                    clientAuthentication: ClientAuthentication? = nil,
                    redirectURI: String? = nil,
                    scope: [String]? = nil,
                    customUserAgent: String? = nil,
                    debug: Bool = false) {
            self.id = id
            self.icon = icon
            self.authorizationURL = authorizationURL
            self.accessTokenURL = accessTokenURL
            self.deviceCodeURL = deviceCodeURL
            self.clientID = clientID
            self.clientSecret = clientSecret
            self.clientType = clientType
            self.clientAuthentication = clientAuthentication ?? (clientType == .confidential ? .clientSecretBasic : .none)
            self.redirectURI = redirectURI
            self.scope = scope
            self.customUserAgent = customUserAgent
            self.debug = debug
        }

        /// Decodes provider configuration, defaulting legacy configurations to public clients.
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(String.self, forKey: .id)
            icon = try container.decodeIfPresent(URL.self, forKey: .icon)
            authorizationURL = try container.decode(URL.self, forKey: .authorizationURL)
            accessTokenURL = try container.decode(URL.self, forKey: .accessTokenURL)
            deviceCodeURL = try container.decodeIfPresent(URL.self, forKey: .deviceCodeURL)
            clientID = try container.decode(String.self, forKey: .clientID)
            clientSecret = try container.decodeIfPresent(String.self, forKey: .clientSecret)
            clientType = try container.decodeIfPresent(ClientType.self, forKey: .clientType) ?? .public
            clientAuthentication = try container.decodeIfPresent(ClientAuthentication.self, forKey: .clientAuthentication) ?? (clientType == .confidential ? .clientSecretBasic : .none)
            redirectURI = try container.decodeIfPresent(String.self, forKey: .redirectURI)
            scope = try container.decodeIfPresent([String].self, forKey: .scope)
            customUserAgent = try container.decodeIfPresent(String.self, forKey: .customUserAgent)
            debug = try container.decodeIfPresent(Bool.self, forKey: .debug) ?? false
        }
    }
}
