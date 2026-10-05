//
//  Keychain+Extensions.swift
//  OAuthKit
//
//  Created by Kevin McKee on 8/19/26.
//

import Foundation
#if canImport(Security)
import Security
#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication
#endif
#endif

#if canImport(Security)
enum KeychainSecurityOperation: Equatable {
    case copy, add, update, delete
}
#endif
/// The default account to use.
private let defaultAccount = "oauthkit"
private let tokenIdentifier = "oauth-token"

#if canImport(Security)
private func platformScopedKeychainQuery(_ query: [String: Any]) -> [String: Any] {
    #if os(macOS)
    var query = query
    query[kSecUseDataProtectionKeychain as String] = true
    return query
    #else
    return query
    #endif
}
#endif
extension Keychain {
    /// Storage operations used for sensitive data.
    protocol Storage {
        init(account: String)
        var account: String { get }
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
        var requiresAuthentication = false
        #if os(macOS) || os(iOS) || os(visionOS)
        var authenticationContext: LAContext?
        #endif

        init(account: String) { self.account = account }

        init(account: String, statusOverride: @escaping (KeychainSecurityOperation) -> OSStatus?) {
            self.account = account
            self.statusOverride = statusOverride
        }

        var keys: [String] {
            get throws {
                let query = platformScopedKeychainQuery([
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: account,
                    kSecReturnAttributes as String: true,
                    kSecMatchLimit as String: kSecMatchLimitAll
                ])
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
            let query = platformScopedKeychainQuery([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecAttrAccount as String: accountKey(key)
            ])
            var attributes: [String: Any] = [kSecValueData as String: data]
            if requiresAuthentication {
                var accessError: Unmanaged<CFError>?
                guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &accessError) else {
                    throw accessError?.takeRetainedValue() ?? KeychainError.securityStatus(errSecAuthFailed)
                }
                attributes[kSecAttrAccessControl as String] = access
            }
            let updateStatus = statusOverride?(.update) ?? SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if updateStatus == errSecSuccess { return true }
            guard updateStatus == errSecItemNotFound else { throw KeychainError.securityStatus(updateStatus) }
            var item = query
            item[kSecValueData as String] = data
            if let accessControl = attributes[kSecAttrAccessControl as String] {
                item[kSecAttrAccessControl as String] = accessControl
            }
            let addStatus = statusOverride?(.add) ?? SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError.securityStatus(addStatus) }
            return true
        }

        /// Reads each protected item only through its supplied authentication context.
        func get(key: String) throws -> Data? {
            var query = platformScopedKeychainQuery([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecAttrAccount as String: accountKey(key),
                kSecReturnData as String: true
            ])
            if requiresAuthentication {
                query[kSecReturnAttributes as String] = true
            }
            #if os(macOS) || os(iOS) || os(visionOS)
            if let authenticationContext {
                query[kSecUseAuthenticationContext as String] = authenticationContext
            } else if requiresAuthentication {
                throw KeychainError.securityStatus(errSecAuthFailed)
            }
            #else
            if requiresAuthentication { throw KeychainError.securityStatus(errSecAuthFailed) }
            #endif
            var result: AnyObject?
            let status = statusOverride?(.copy) ?? withUnsafeMutablePointer(to: &result) { pointer in
                SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer(pointer))
            }
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw KeychainError.securityStatus(status) }
            if requiresAuthentication {
                guard let item = result as? [String: Any],
                      item[kSecAttrAccessControl as String] != nil,
                      let data = item[kSecValueData as String] as? Data else {
                    throw KeychainError.securityStatus(errSecAuthFailed)
                }
                return data
            }
            guard let data = result as? Data else { throw KeychainError.securityStatus(errSecDecode) }
            return data
        }

        @discardableResult
        func clear() throws -> Bool {
            let query = platformScopedKeychainQuery([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account
            ])
            let status = statusOverride?(.delete) ?? SecItemDelete(query as CFDictionary)
            if status == errSecSuccess || status == errSecItemNotFound { return true }
            throw KeychainError.securityStatus(status)
        }

        @discardableResult
        func delete(key: String) throws -> Bool {
            let query = platformScopedKeychainQuery([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account,
                kSecAttrAccount as String: key
            ])
            let status = statusOverride?(.delete) ?? SecItemDelete(query as CFDictionary)
            if status == errSecSuccess { return true }
            if status == errSecItemNotFound { return false }
            throw KeychainError.securityStatus(status)
        }
    }
    #endif
}

extension Keychain.Storage {
    func accountKey(_ key: String) -> String {
        account + "." + key + "." + tokenIdentifier
    }
}
