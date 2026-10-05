//
//  URLRequest+Extensions.swift
//
//
//  Created by Kevin McKee
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private let authHeader = "Authorization"

public extension URLRequest {

    /// Attaches a bearer token only to HTTPS protected-resource requests.
    /// - Parameter auth: the oauth authorization
    mutating func addAuthorization(auth: OAuth.Authorization) {
        guard url?.scheme?.lowercased() == "https" else { return }
        setValue("\(auth.token.type) \(auth.token.accessToken)", forHTTPHeaderField: authHeader)
    }
}
