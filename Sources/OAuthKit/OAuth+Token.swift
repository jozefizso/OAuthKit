//
//  OAuth+Token.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation

extension OAuth {

    /// A codable type that holds oauth token information.
    public struct Token: Codable, Equatable, Sendable {

        /// The access token string as issued by the authorization server.
        public let accessToken: String

        /// If the access token will expire, then this can be used to obtain another access token.
        public let refreshToken: String?

        /// If the access token expires, this is the duration of time the access token is granted for (in seconds).
        public let expiresIn: Int?

        /// If the scope the user granted is identical to the scope the app requested, this parameter is optional.
        /// If the granted scope is different from the requested scope, such as if the user modified the scope, then this parameter is required.
        public let scope: String?

        /// The type of token this is, typically just the string “Bearer”.
        public let type: String

        /// The opaque `id_token` returned by the authorization server, if present.
        /// OAuthKit does not validate its signature or claims. Never use this value as
        /// authenticated identity without independent OpenID Connect validation.
        public let rawIDToken: String?

        /// Common Initializer.
        /// - Parameters:
        ///   - accessToken: the access token string
        ///   - refreshToken: the refresh token
        ///   - expiresIn: the expiration time in secods
        ///   - scope: the scope returned from the authorization server
        ///   - type: the token type
        ///   - rawIDToken: an unvalidated, opaque ID token; not authenticated identity
        public init(accessToken: String, refreshToken: String?, expiresIn: Int?, scope: String?, type: String, rawIDToken: String? = nil) {
            self.accessToken = accessToken
            self.refreshToken = refreshToken
            self.expiresIn = expiresIn
            self.scope = scope
            self.type = type
            self.rawIDToken = rawIDToken
        }

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case expiresIn = "expires_in"
            case type = "token_type"
            case scope
            case rawIDToken = "id_token"
        }
    }
}
