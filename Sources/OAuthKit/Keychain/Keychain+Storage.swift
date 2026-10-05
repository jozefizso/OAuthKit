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

#if canImport(Security)
enum KeychainSecurityOperation: Equatable {
    case copy, add, update, delete
}
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
        var statusOverride: ((KeychainSecurityOperation) -> OSStatus?)?

        init(account: String) { self.account = account }

        init(account: String, statusOverride: @escaping (KeychainSecurityOperation) -> OSStatus?) {
            self.account = account
            self.statusOverride = statusOverride
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
                let status = statusOverride?(.copy) ?? withUnsafeMutablePointer(to: &result) { pointer in
                    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer(pointer))
                }
                if status == errSecItemNotFound { return [] }
                guard status == errSecSuccess else { throw KeychainError.securityStatus(status) }
                guard let items = result as? [[String: Any]] else { throw KeychainError.securityStatus(errSecDecode) }
                return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
            }
        }

        /// Updates an existing item in place or adds a new one, preserving old data on failure.
        @discardableResult
        func set(_ data: Data, for key: String) throws -> Bool {
            assert(key.isNotEmpty, "❌ The keychain key cannot be empty.")
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecAttrAccount as String: accountKey(key)
            ]
            let attributes: [String: Any] = [kSecValueData as String: data]
            let updateStatus = statusOverride?(.update) ?? SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if updateStatus == errSecSuccess { return true }
            guard updateStatus == errSecItemNotFound else { throw KeychainError.securityStatus(updateStatus) }
            var item = query
            item[kSecValueData as String] = data
            let addStatus = statusOverride?(.add) ?? SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError.securityStatus(addStatus) }
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
            let status = statusOverride?(.copy) ?? withUnsafeMutablePointer(to: &result) { pointer in
                SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer(pointer))
            }
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw KeychainError.securityStatus(status) }
            guard let data = result as? Data else { throw KeychainError.securityStatus(errSecDecode) }
            return data
        }

        /// Deletes all generic-password items in this exact service namespace.
        @discardableResult
        func clear() throws -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account
            ]
            let status = statusOverride?(.delete) ?? SecItemDelete(query as CFDictionary)
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
            let status = statusOverride?(.delete) ?? SecItemDelete(query as CFDictionary)
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
