//
//  KeychainTests.swift
//  
//
//  Created by Kevin McKee
//

import Foundation
#if os(macOS) || os(iOS) || os(visionOS)
import LocalAuthentication
#endif
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

        let inserted = try keychain.set(token, for: key)
        #expect(inserted == true)

        let found: OAuth.Token = try #require(try keychain.get(key: key))

        #expect(token.accessToken == found.accessToken)
        #expect(token.expiresIn == found.expiresIn)
        #expect(token.scope == found.scope)
        #expect(token.type == found.type)


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
        let storage = Keychain.DefaultStorage(account: account)
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
    /// Arrange a stored string and assert decoding it as another Codable type reports its decoding error.
    @Test("Malformed stored values propagate decoding errors")
    func decodingFailuresPropagate() throws {
        // Arrange
        try keychain.set("not-an-integer", for: "decode")

        // Act / Assert
        #expect(throws: (any Error).self) {
            let _: Int? = try keychain.get(key: "decode")
        }
    }
#if canImport(Security) && (os(macOS) || os(iOS) || os(visionOS))
    /// Arrange a protected store without an authentication context; reading must fail instead of returning an unprotected empty value.
    @Test("Protected reads fail closed without a context")
    func protectedReadsRequireAuthenticationContext() throws {
        // Arrange
        keychain.requiresAuthentication = true
        keychain.authenticationContext = nil

        // Act / Assert
        #expect(throws: (any Error).self) {
            let _: String? = try keychain.get(key: "missing")
        }
    }
    /// Arrange a genuinely biometric-protected item and a separate instance lacking its authentication context.
    @Test("Secondary protected instances cannot read without authentication")
    func secondaryInstanceCannotBypassProtection() throws {
        // Arrange
        let tag = "oauthkit.test." + String.secureRandom()
        let protectedWriter = Keychain(tag)
        protectedWriter.requiresAuthentication = true
        let secondary = Keychain(tag)
        secondary.requiresAuthentication = true
        secondary.authenticationContext = nil
        defer {
            _ = try? protectedWriter.clear()
        }
        try protectedWriter.set("secret", for: "token")

        // Act / Assert
        #expect(throws: (any Error).self) {
            let _: String? = try secondary.get(key: "token")
        }
    }

    /// A client with authentication disabled may not remove an existing item's
    /// biometric policy while replacing its token. An OS refusal is also safe.
    @Test("A nonprotected writer cannot downgrade biometric protection")
    func replacingProtectedItemPreservesItsGate() throws {
        // Arrange
        let namespace = "oauthkit.test." + String.secureRandom()
        let protected = Keychain(namespace)
        protected.requiresAuthentication = true
        try protected.set("original", for: "token")
        defer { _ = try? protected.clear() }
        let secondary = Keychain(namespace)

        // Act
        do {
            try secondary.set("replacement", for: "token")
        } catch KeychainError.securityStatus(let status) {
            #expect(status == errSecAuthFailed || status == errSecInteractionNotAllowed)
        }

        // Assert
        #expect(throws: (any Error).self) {
            let _: String? = try secondary.get(key: "token")
        }
    }
    /// Arrange a legacy unprotected item, enable biometric mode on another instance, and assert it is rejected.
    @Test("Enabling biometric mode rejects existing unprotected items")
    func unprotectedItemsAreNotReturnedAfterEnablingBiometrics() throws {
        // Arrange
        let tag = "oauthkit.test." + String.secureRandom()
        let unprotectedWriter = Keychain(tag)
        try unprotectedWriter.set("legacy-token", for: "provider")
        let protectedReader = Keychain(tag)
        protectedReader.requiresAuthentication = true
        let context = LAContext()
        context.interactionNotAllowed = true
        protectedReader.authenticationContext = context
        defer {
            _ = try? unprotectedWriter.clear()
        }

        // Act / Assert
        #expect(throws: (any Error).self) {
            let _: String? = try protectedReader.get(key: "provider")
        }
    }
#endif
}
