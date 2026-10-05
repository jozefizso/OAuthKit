//
//  Keychain.swift
//
//
//  Created by Kevin McKee
//

import Foundation
#if canImport(Security)
import Security
#endif

#if canImport(Security)
/// Errors returned by Keychain storage operations.
enum KeychainError: Error {
    case securityStatus(OSStatus)
}
#endif
/// A helper class used to interact with Keychain storage access. Wraps all storage write operations with threadsafe locks.
class Keychain: @unchecked Sendable {

    static let `default`: Keychain = Keychain()
    private let lock = NSLock()
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var storage: Storage? = nil

    private init() {
        #if canImport(Security)
        storage = DefaultStorage(account: Bundle.main.bundleIdentifier ?? "oauthkit")
        #endif
    }

    /// Initializes the keychain with an overridden accound identifier.
    /// - Parameter account: a key indicating the account owner. Ideally, use the application identifier for this value.
    public init(_ account: String) {
        assert(account.isNotEmpty, "❌ The account identifier cannot be empty.")
        #if canImport(Security)
        self.storage = DefaultStorage(account: account)
        #elseif os(Android)
        // TODO: Android storage not implemented
        #elseif os(Linux)
        // TODO: Linux storage not implemented
        #endif
    }

    /// Queries the keychain for keys; errors are not converted into an empty result.
    var keys: [String] {
        get throws {
            guard let storage else { return [] }
            lock.lock()
            defer { lock.unlock() }
            return try storage.keys
        }
    }

    /// Sets the value for the specified key.
    /// - Parameters:
    ///   - value: the value to store
    ///   - key: the key to use
    /// - Returns: true if able to set the value, otherwise false
    @discardableResult
    func set(_ value: Codable, for key: String) throws -> Bool {
        assert(key.isNotEmpty, "❌ The keychain key cannot be empty.")
        lock.lock()
        defer { lock.unlock() }

        guard let storage else { return false }
        let data = try encoder.encode(value)
        return try storage.set(data, for: key)
    }

    /// Fetches a stored value from the keychain with the specified key and attempts to decode it from the implied generic.
    /// - Parameter key: the keychain key
    /// - Returns: the generic codeable for the specified key or nil if not found
    func get<T>(key: String) throws -> T? where T: Codable {

        lock.lock()
        defer { lock.unlock() }

        guard let storage else { return nil }
        guard let data = try storage.get(key: key) else { return nil }
        let value = try? decoder.decode(T.self, from: data)
        return value
    }

    /// Clears only this keychain's namespace.
    /// - Returns: true after confirmed deletion, false if storage is unavailable.
    @discardableResult
    func clear() throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return try storage?.clear() ?? false
    }

    /// Deletes the value for the specified key and propagates keychain failures.
    @discardableResult
    func delete(key: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let storage else { return false }
        return try storage.delete(key: storage.accountKey(key))
    }
}
