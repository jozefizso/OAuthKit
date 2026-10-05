//
//  Keychain+Extensions.swift
//  OAuthKit
//
//  Created by Kevin McKee on 8/19/26.
//

import Foundation
#if canImport(Security)
import Security
#endif

/// The default account to use.
private let defaultAccount = "oauthkit"
/// The default token identifier suffix.
private let tokenIdentifier = "oauth-token"

extension Keychain {

    /// Storage operations used for sensitive data.
    protocol Storage {
        /// The owning account identifier.
        init(account: String)
        var account: String { get }
        /// Returns keys in this account; query failures are thrown.
        var keys: [String] { get throws }
        func set(_ data: Data, for key: String) throws -> Bool
        func get(key: String) throws -> Data?
        func delete(key: String) throws -> Bool
        func clear() throws -> Bool
        func accountKey(_ key: String) -> String
    }

    #if canImport(Security)
    /// The default token storage used by Apple ecosystems.
    struct DefaultStorage: Storage {
        var account: String = defaultAccount

        init(account: String) {
            self.account = account
        }

        var keys: [String] {
            get throws {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: account,
                    kSecReturnAttributes as String: true,
                    kSecMatchLimit as String: kSecMatchLimitAll
                ]
                var result: AnyObject?
                let status = withUnsafeMutablePointer(to: &result) { pointer in
                    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer(pointer))
                }
                if status == errSecItemNotFound { return [] }
                guard status == errSecSuccess else { throw KeychainError.securityStatus(status) }
                guard let items = result as? [[String: Any]] else { return [] }
                return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
            }
        }

        /// Stores data under an exact service and deterministic account key.
        @discardableResult
        func set(_ data: Data, for key: String) throws -> Bool {
            assert(key.isNotEmpty, "❌ The keychain key cannot be empty.")
            _ = try delete(key: accountKey(key))
            let item: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecAttrAccount as String: accountKey(key),
                kSecValueData as String: data
            ]
            let status = SecItemAdd(item as CFDictionary, nil)
            guard status == errSecSuccess else { throw KeychainError.securityStatus(status) }
            return true
        }

        /// Fetches data for one deterministic key in this exact service.
        func get(key: String) throws -> Data? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecAttrAccount as String: accountKey(key),
                kSecReturnData as String: true
            ]
            var result: AnyObject?
            let status = withUnsafeMutablePointer(to: &result) { pointer in
                SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer(pointer))
            }
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw KeychainError.securityStatus(status) }
            return result as? Data
        }

        /// Deletes all generic-password items in this exact service namespace.
        @discardableResult
        func clear() throws -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account
            ]
            let status = SecItemDelete(query as CFDictionary)
            if status == errSecSuccess || status == errSecItemNotFound { return true }
            throw KeychainError.securityStatus(status)
        }

        /// Deletes one item in this exact service namespace.
        @discardableResult
        func delete(key: String) throws -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecAttrAccount as String: key
            ]
            let status = SecItemDelete(query as CFDictionary)
            if status == errSecSuccess { return true }
            if status == errSecItemNotFound { return false }
            throw KeychainError.securityStatus(status)
        }
    }
    #endif
}

extension Keychain.Storage {
    /// Builds a deterministic account key for the specified OAuth key.
    func accountKey(_ key: String) -> String {
        account + "." + key + "." + tokenIdentifier
    }
}
