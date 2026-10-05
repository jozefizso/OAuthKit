//
//  KeychainTests.swift
//  
//
//  Created by Kevin McKee
//

import Foundation
@testable import OAuthKit
import Testing
#if canImport(Security)
import Security
#endif

@Suite("Keychain Tests", .tags(.keychain))
final class KeychainTests {

    let keychain: Keychain

    deinit {
        _ = try? keychain.clear()
    }

    /// Initializer.
    init() async throws {
        let tag: String = "oauthkit.test." + .secureRandom()
        keychain = .init(tag)
    }

    @Test("Storing keychain values")
    func whenStoring() async throws {
        let key = "Github"
        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 3600, scope: "email", type: "Bearer")

        let inserted = try! keychain.set(token, for: key)
        #expect(inserted == true)

        let found: OAuth.Token = try! keychain.get(key: key)!

        #expect(token.accessToken.isNotEmpty)
        #expect(token.accessToken == found.accessToken)
        #expect(token.expiresIn == found.expiresIn)
        #expect(token.scope == found.scope)
        #expect(token.type == found.type)

        let keys = try keychain.keys
        #expect(keys.count == 1)

        let deleted = try keychain.delete(key: key)
        #expect(deleted == true)
    }
    /// Arrange two application tags with an overlapping prefix, then clear one and assert the other remains readable.
    @Test("Clearing an exact service does not clear an overlapping service")
    func clearingOverlappingNamespace() throws {
        // Arrange
        let base = "oauthkit.test.\(String.secureRandom())"
        let first: Keychain = .init(base)
        let overlapping: Keychain = .init(base + ".child")
        try first.set("first", for: "token")
        try overlapping.set("child", for: "token")
        defer {
            _ = try? first.clear()
            _ = try? overlapping.clear()
        }

        // Act
        let cleared = try first.clear()

        // Assert
        #expect(cleared)
        let surviving: String? = try overlapping.get(key: "token")
        #expect(surviving == "child")
    }
#if canImport(Security)
    /// Distinguish an empty namespace from a failed Security query and ensure delete failures surface.
    @Test("Keychain query and deletion failures are actionable")
    func queryAndDeletionFailuresPropagate() throws {
        // Arrange: a not-found status is the sole empty-result condition.
        let missing = Keychain.DefaultStorage(account: "missing", statusOverride: { _ in errSecItemNotFound })

        // Act / Assert: no records return an empty list.
        #expect(try missing.keys.isEmpty)

        // Arrange: other Security errors must not masquerade as missing data.
        let queryFailure = Keychain.DefaultStorage(account: "failed", statusOverride: { _ in errSecParam })
        #expect(throws: (any Error).self) {
            _ = try queryFailure.keys
        }

        let deletionFailure = Keychain.DefaultStorage(account: "failed", statusOverride: { _ in errSecInteractionNotAllowed })
        // Assert deletion status is propagated instead of reporting success.
        #expect(throws: (any Error).self) {
            _ = try deletionFailure.clear()
        }
    }
    /// A failed in-place update must leave the old credential available.
    @Test("Failed replacement preserves the existing credential")
    func failedUpdatePreservesPreviousValue() throws {
        // Arrange
        let account = "oauthkit.test." + String.secureRandom()
        var storage = Keychain.DefaultStorage(account: account)
        let oldValue = Data("previous-token".utf8)
        try storage.set(oldValue, for: "provider")
        defer {
            _ = try? storage.clear()
        }
        storage.statusOverride = { operation in
            operation == .update ? errSecInteractionNotAllowed : nil
        }

        // Act
        #expect(throws: (any Error).self) {
            _ = try storage.set(Data("replacement-token".utf8), for: "provider")
        }

        // Assert
        storage.statusOverride = nil
        #expect(try storage.get(key: "provider") == oldValue)
    }
#endif
}
