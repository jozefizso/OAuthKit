//
//  OAuth+Request.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private let httpPost = "POST"
private let httpAcceptHeaderField = "Accept"
private let httpContentTypeHeaderField = "Content-Type"
private let formMimeType = "application/x-www-form-urlencoded"
private let jsonMimeType = "application/json"
private let responseTypeCode = "code"

extension OAuth {

    /// OAuth URL Request Builder
    struct Request {
        private static let formHexDigits = Array("0123456789ABCDEF".utf8)

        /// Provides constants for URLQueryItem keys.
        fileprivate enum Key: String {
            case code = "code"
            case clientID = "client_id"
            case clientSecret = "client_secret"
            case deviceCode = "device_code"
            case grantType = "grant_type"
            case redirectUri = "redirect_uri"
            case scope = "scope"
            case state = "state"
            case refreshToken = "refresh_token"
            case responseType = "response_type"
            case codeChallenge = "code_challenge"
            case codeChallengeMethod = "code_challenge_method"
            case codeVerifier = "code_verifier"
        }

        // MARK: URLRequest Builders

        /// Builds an `/authorization` request for the specified provider and grant type.
        /// - Parameters:
        ///   - provider: the oauth provider
        ///   - grantType: the grant type
        /// - Returns: an `/authorization` url request
        static func auth(provider: Provider, grantType: GrantType) -> URLRequest? {
            guard provider.authorizationURL.scheme?.lowercased() == "https",
                  provider.redirectURI.map(isAllowedRedirectURI) ?? true,
                  var urlComponents = URLComponents(string: provider.authorizationURL.absoluteString),
                  !hasOAuthReservedQueryParameters(provider.authorizationURL) else { return nil }
            guard let queryItems = buildQueryItems(provider: provider, grantType: grantType) else { return nil }
            urlComponents.queryItems = (urlComponents.queryItems ?? []) + queryItems
            guard let url = urlComponents.url else { return nil }
            return URLRequest(url: url)
        }

        static func refresh(provider: Provider, token: Token) -> URLRequest? {
            guard let queryItems = buildQueryItems(provider: provider, token: token) else { return nil }
            return tokenRequest(provider: provider, queryItems: queryItems)
        }

        /// Builds a `/token` request for exchanging the given code for a token.
        /// Parameters are always sent in an application/x-www-form-urlencoded request body.
        static func token(provider: Provider, code: String, pkce: PKCE? = nil) -> URLRequest? {
            let queryItems = buildQueryItems(provider: provider, code: code, pkce: pkce)
            return tokenRequest(provider: provider, queryItems: queryItems)
        }

        static func token(provider: Provider, deviceCode: DeviceCode) -> URLRequest? {
            let queryItems = buildQueryItems(provider: provider, deviceCode: deviceCode)
            return tokenRequest(provider: provider, queryItems: queryItems)
        }

        /// Builds a client credentials `/token` request.
        /// - Parameters:
        ///   - provider: the oauth provider
        /// - Returns: the url request
        static func token(provider: Provider) -> URLRequest? {
            guard provider.clientType == .confidential,
                  provider.clientAuthentication != .none,
                  let queryItems = buildQueryItems(provider: provider, grantType: .clientCredentials) else { return nil }
            return authenticatedFormRequest(
                url: provider.accessTokenURL,
                provider: provider,
                queryItems: queryItems,
                keepsClientIDInBodyForBasic: false
            )
        }

        /// Builds a `/device` code request.
        /// - Parameters:
        ///   - provider: the oauth provider
        /// - Returns: the url request
        static func device(provider: Provider) -> URLRequest? {
            guard let deviceCodeURL = provider.deviceCodeURL else { return nil }
            let queryItems = [
                URLQueryItem(key: .clientID, value: provider.clientID),
                URLQueryItem(key: .scope, value: provider.scope?.joined(separator: " "))
            ]
            return authenticatedFormRequest(
                url: deviceCodeURL,
                provider: provider,
                queryItems: queryItems,
                keepsClientIDInBodyForBasic: true
            )
        }

        // MARK: Query Items

        /// Builds default url query items for the specified provider and grant type.
        ///
        /// Important notes about the `grantType`:
        /// * When `.authorizationCode`,`.pkce`, or `.refreshToken` the items are built for  `/authorization` requests.
        /// * When `.deviceCode` the items are built for  `/device` requests.
        /// * When `.clientCredentials` the items are built for  `/token` requests.
        /// * When `.refreshToken` the items are nil
        /// - Parameters:
        ///   - provider: the oauth provider
        ///   - grantType: the grant type
        /// - Returns: the default url query items
        private static func buildQueryItems(provider: Provider, grantType: GrantType) -> [URLQueryItem]? {
            var queryItems = [URLQueryItem]()
            switch grantType {
            case .authorizationCode(let state):
                queryItems.append(URLQueryItem(key: .clientID, value: provider.clientID))
                queryItems.append(URLQueryItem(key: .redirectUri, value: provider.redirectURI))
                queryItems.append(URLQueryItem(key: .responseType, value: responseTypeCode))
                queryItems.append(URLQueryItem(key: .state, value: state))
            case .pkce(let pkce):
                queryItems.append(URLQueryItem(key: .clientID, value: provider.clientID))
                queryItems.append(URLQueryItem(key: .redirectUri, value: provider.redirectURI))
                queryItems.append(URLQueryItem(key: .responseType, value: responseTypeCode))
                queryItems.append(URLQueryItem(key: .state, value: pkce.state))
                queryItems.append(URLQueryItem(key: .codeChallenge, value: pkce.codeChallenge))
                queryItems.append(URLQueryItem(key: .codeChallengeMethod, value: pkce.codeChallengeMethod))
            case .deviceCode:
                queryItems.append(URLQueryItem(key: .clientID, value: provider.clientID))
                queryItems.append(URLQueryItem(key: .clientSecret, value: provider.clientSecret))
                queryItems.append(URLQueryItem(key: .grantType, value: grantType.rawValue))
            case .clientCredentials:
                queryItems.append(URLQueryItem(key: .clientID, value: provider.clientID))
                queryItems.append(URLQueryItem(key: .clientSecret, value: provider.clientSecret))
                queryItems.append(URLQueryItem(key: .grantType, value: grantType.rawValue))
            case .refreshToken:
                return nil
            }
            if let scope = provider.scope {
                queryItems.append(URLQueryItem(key: .scope, value: scope.joined(separator: " ")))
            }
            return queryItems
        }

        /// Builds default url query items for the `.refreshToken` grant type.
        /// - Parameters:
        ///   - provider: the oauth provider
        ///   - token: the token to refresh
        /// - Returns: the `/token` url query items
        private static func buildQueryItems(provider: Provider, token: Token) -> [URLQueryItem]? {
            var queryItems = [URLQueryItem]()
            guard let refreshToken = token.refreshToken else { return nil }
            queryItems.append(URLQueryItem(key: .clientID, value: provider.clientID))
            queryItems.append(URLQueryItem(key: .grantType, value: GrantType.refreshToken.rawValue))
            queryItems.append(URLQueryItem(key: .refreshToken, value: refreshToken))
            return queryItems
        }

        /// Builds `/token` url query parameters for the specified code and pkce data.
        /// - Parameters:
        ///   - provider: the oauth provider
        ///   - code: the code to exchange for a token
        ///   - pkce: the pkce data
        /// - Returns: the `/token` url query items
        private static func buildQueryItems(provider: Provider, code: String, pkce: PKCE? = nil) -> [URLQueryItem] {
            let grantType: GrantType = .authorizationCode(.empty)
            var queryItems: [URLQueryItem] = [
                URLQueryItem(key: .clientID, value: provider.clientID),
                URLQueryItem(key: .clientSecret, value: provider.clientSecret),
                URLQueryItem(key: .code, value: code),
                URLQueryItem(key: .redirectUri, value: provider.redirectURI),
                URLQueryItem(key: .grantType, value: grantType.rawValue)
            ]

            if let pkce {
                queryItems.append(URLQueryItem(key: .codeVerifier, value: pkce.codeVerifier))
            }

            if let scope = provider.scope {
                queryItems.append(URLQueryItem(key: .scope, value: scope.joined(separator: " ")))
            }
            return queryItems
        }

        /// Builds `/token` url query parameters for the specified provider and device code data.
        /// - Parameters:
        ///   - provider: the oauth provider
        ///   - deviceCode: the device code data
        /// - Returns: the `/token` url query items
        private static func buildQueryItems(provider: Provider, deviceCode: DeviceCode) -> [URLQueryItem] {
            var queryItems: [URLQueryItem] = [
                URLQueryItem(key: .clientID, value: provider.clientID),
                URLQueryItem(key: .grantType, value: DeviceCode.grantType),
                URLQueryItem(key: .deviceCode, value: deviceCode.deviceCode)
            ]

            if let scope = provider.scope {
                queryItems.append(URLQueryItem(key: .scope, value: scope.joined(separator: " ")))
            }
            return queryItems
        }
        /// Encodes query items into one UTF-8 application/x-www-form-urlencoded buffer.
        private static func formEncoded(_ queryItems: [URLQueryItem]) -> Data {
            var capacity = max(queryItems.count - 1, 0)
            for item in queryItems {
                guard let value = item.value else { continue }
                capacity += (item.name.utf8.count + value.utf8.count) * 3 + 1
            }
            var output = Data()
            output.reserveCapacity(capacity)
            var needsSeparator = false
            for item in queryItems {
                guard let value = item.value else { continue }
                if needsSeparator { output.append(0x26) }
                appendFormEncoded(item.name, to: &output)
                output.append(0x3D)
                appendFormEncoded(value, to: &output)
                needsSeparator = true
            }
            return output
        }

        private static func formEncode(_ value: String) -> String {
            var output = Data()
            output.reserveCapacity(value.utf8.count * 3)
            appendFormEncoded(value, to: &output)
            return String(decoding: output, as: UTF8.self)
        }

        private static func appendFormEncoded(_ value: String, to output: inout Data) {
            for byte in value.utf8 {
                switch byte {
                case 0x41...0x5A, 0x61...0x7A, 0x30...0x39, 0x2D, 0x2E, 0x5F, 0x7E:
                    output.append(byte)
                case 0x20:
                    output.append(0x2B)
                default:
                    output.append(0x25)
                    output.append(formHexDigits[Int(byte >> 4)])
                    output.append(formHexDigits[Int(byte & 0x0F)])
                }
            }
        }

        private static func tokenRequest(provider: Provider, queryItems: [URLQueryItem]) -> URLRequest? {
            authenticatedFormRequest(
                url: provider.accessTokenURL,
                provider: provider,
                queryItems: queryItems,
                keepsClientIDInBodyForBasic: false
            )
        }

        private static func authenticatedFormRequest(
            url: URL,
            provider: Provider,
            queryItems: [URLQueryItem],
            keepsClientIDInBodyForBasic: Bool
        ) -> URLRequest? {
            guard url.scheme?.lowercased() == "https",
                  !hasOAuthReservedQueryParameters(url) else { return nil }
            var items = queryItems
            var authorizationValue: String?
            switch (provider.clientType, provider.clientAuthentication) {
            case (.public, .none):
                items.removeAll { $0.name == Key.clientSecret.rawValue }
            case (.public, _), (.confidential, .none):
                return nil
            case (.confidential, .clientSecretBasic):
                guard let secret = provider.clientSecret else { return nil }
                items.removeAll {
                    $0.name == Key.clientSecret.rawValue ||
                    (!keepsClientIDInBodyForBasic && $0.name == Key.clientID.rawValue)
                }
                let credentials = "\(formEncode(provider.clientID)):\(formEncode(secret))"
                authorizationValue = "Basic \(Data(credentials.utf8).base64EncodedString())"
            case (.confidential, .clientSecretPost):
                guard let secret = provider.clientSecret else { return nil }
                if !items.contains(where: { $0.name == Key.clientSecret.rawValue }) {
                    items.append(URLQueryItem(key: .clientSecret, value: secret))
                }
            }
            var request = URLRequest(url: url)
            request.httpBody = formEncoded(items)
            request.httpMethod = httpPost
            request.setValue(jsonMimeType, forHTTPHeaderField: httpAcceptHeaderField)
            request.setValue(formMimeType, forHTTPHeaderField: httpContentTypeHeaderField)
            if let authorizationValue {
                request.setValue(authorizationValue, forHTTPHeaderField: "Authorization")
            }
            return request
        }
        private static func isAllowedRedirectURI(_ value: String) -> Bool {
            guard let components = URLComponents(string: value),
                  let scheme = components.scheme?.lowercased(),
                  components.user == nil,
                  components.password == nil,
                  components.fragment == nil else { return false }
            if scheme == "https" { return true }
            if scheme == "http" {
                return components.host == "127.0.0.1" || components.host == "::1"
            }
            return components.host == nil && scheme.contains(".")
        }


        private static func hasOAuthReservedQueryParameters(_ url: URL) -> Bool {
            guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return true }
            return components.queryItems?.contains { item in
                switch item.name.lowercased() {
                case "client_id", "client_secret", "grant_type", "redirect_uri", "code",
                     "refresh_token", "code_verifier", "device_code", "scope", "state",
                     "response_type", "code_challenge", "code_challenge_method":
                    return true
                default:
                    return false
                }
            } ?? false
        }

    }
}

fileprivate extension URLQueryItem {

    /// Initializes the URLQueryItem with the request key
    /// - Parameters:
    ///   - key: the request builder key
    ///   - value: the value
    init(key: OAuth.Request.Key, value: String?) {
        self.init(name: key.rawValue, value: value)
    }
}

