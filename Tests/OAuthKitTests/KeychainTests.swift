//
//  KeychainTests.swift
//  
//
//  Created by Kevin McKee
//

@testable import OAuthKit
import Testing

@Suite("Keychain Tests", .tags(.keychain))
final class KeychainTests {

    let keychain: Keychain

    deinit {
        try? keychain.clear()
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
        let base = "oauthkit.test.\(.secureRandom())"
        let first: Keychain = .init(base)
        let overlapping: Keychain = .init(base + ".child")
        try first.set("first", for: "token")
        try overlapping.set("child", for: "token")
        defer {
            try? first.clear()
            try? overlapping.clear()
        }

        // Act
        let cleared = try first.clear()

        // Assert
        #expect(cleared)
        let surviving: String? = try overlapping.get(key: "token")
        #expect(surviving == "child")
    }
}
