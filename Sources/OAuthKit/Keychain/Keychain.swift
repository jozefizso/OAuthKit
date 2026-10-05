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
#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication
#endif

#if canImport(Security)
/// Errors returned by Keychain storage operations.
enum KeychainError: Error {
    case securityStatus(OSStatus)
}
#endif
/// A helper class used to interact with Keychain storage access. Wraps all storage write operations with threadsafe locks.
class Keychain: @unchecked Sendable {

    static var `default`: Keychain { Keychain() }
    private let lock = NSLock()
    private let coordinationIdentifier: String
    #if canImport(Security)
    /// Whether keychain values require item-level biometric authentication.
    var requiresAuthentication: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return (storage as? DefaultStorage)?.requiresAuthentication ?? false
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            (storage as? DefaultStorage)?.requiresAuthentication = newValue
        }
    }

    #if os(macOS) || os(iOS) || os(visionOS)
    /// Context supplied to Security for every read of an authenticated item.
    var authenticationContext: LAContext? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return (storage as? DefaultStorage)?.authenticationContext
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            (storage as? DefaultStorage)?.authenticationContext = newValue
        }
    }
    #endif
    #endif
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var storage: Storage? = nil

    var lifecycleNamespace: String { coordinationIdentifier }
    private init() {
        coordinationIdentifier = Bundle.main.bundleIdentifier ?? "oauthkit"
        #if canImport(Security)
        storage = DefaultStorage(account: coordinationIdentifier)
        #endif
    }

    /// Initializes the keychain with an overridden accound identifier.
    /// - Parameter account: a key indicating the account owner. Ideally, use the application identifier for this value.
    public init(_ account: String) {
        assert(account.isNotEmpty, "❌ The account identifier cannot be empty.")
        coordinationIdentifier = account
        #if canImport(Security)
        self.storage = DefaultStorage(account: account)
        #elseif os(Android)
        // TODO: Android storage not implemented
        #elseif os(Linux)
        // TODO: Linux storage not implemented
        #endif
    }

    /// Initializes the wrapper with a storage implementation at the Security boundary.
    init(storage: any Storage) {
        coordinationIdentifier = storage.account
        self.storage = storage
    }

    /// Queries the keychain for keys; errors are not converted into an empty result.
    var keys: [String] {
        get throws {
            lock.lock()
            defer { lock.unlock() }
            guard let storage else { return [] }
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

    /// Fetches a stored value from the keychain and decodes it as the requested type.
    /// - Parameter key: the keychain key
    /// - Returns: the decoded value, or nil when the key is not found; decoding failures are thrown.
    func get<T>(key: String) throws -> T? where T: Codable {

        lock.lock()
        defer { lock.unlock() }

        guard let storage else { return nil }
        guard let data = try storage.get(key: key) else { return nil }
        return try decoder.decode(T.self, from: data)
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
