import Foundation
#if canImport(Security) && (os(macOS) || os(iOS) || os(visionOS))
@testable import OAuthKit
import Security
import Testing

@MainActor
@Suite("OAuth storage failure handling")
struct OAuthStorageFailureTests {
    /// Default storage must not share mutable protection settings across clients.
    @Test("Default Keychain authentication policies are instance-local")
    func defaultAuthenticationPoliciesAreIndependent() {
        // Arrange
        let protected = Keychain.default
        let unprotected = Keychain.default

        // Act
        protected.requiresAuthentication = true

        // Assert
        #expect(unprotected.requiresAuthentication == false)
    }

    /// A new client without the biometric option must not restore a token whose
    /// protection is enforced by the OS, even when it uses the same namespace.
    @Test("A secondary OAuth client cannot restore a biometric-protected item")
    func secondaryClientCannotBypassItemProtection() throws {
        // Arrange
        let provider = makeProvider()
        let namespace = "oauthkit.test.\(UUID().uuidString)"
        let protected = Keychain(namespace)
        protected.requiresAuthentication = true
        let token = OAuth.Token(
            accessToken: "protected-access-token", refreshToken: "protected-refresh-token",
            expiresIn: 3600, scope: nil, type: "Bearer"
        )
        try protected.set(OAuth.Authorization(issuer: provider.id, token: token), for: provider.id)
        defer { _ = try? protected.clear() }

        // Act
        let secondary = OAuth(providers: [provider], options: [.applicationTag: namespace])

        // Assert
        #expect(secondary.state == .error(provider, .keychain))
    }

    /// A missing authorization is normal; cancellation of a protected read is
    /// not. A secondary OAuth instance must not hide authentication failure as logout.
    @Test("Restoration distinguishes missing credentials from cancelled authentication")
    func restorationReportsAuthenticationCancellation() {
        // Arrange
        let provider = makeProvider()
        let namespace = "oauthkit.test.\(UUID().uuidString)"
        let missing = Keychain(storage: Keychain.DefaultStorage(account: namespace, statusOverride: { operation in
            operation == .copy ? errSecItemNotFound : nil
        }))
        let cancelled = Keychain(storage: Keychain.DefaultStorage(account: namespace, statusOverride: { operation in
            operation == .copy ? errSecUserCanceled : nil
        }))
        let options: [OAuth.Option: Any] = [.requireBiometricAuthentication: true]

        // Act
        let first = OAuth(providers: [provider], keychain: missing, options: options)
        let second = OAuth(providers: [provider], keychain: cancelled, options: options)

        // Assert
        #expect(first.state == .empty)
        #expect(second.state == .error(provider, .keychain))
    }

    /// Refresh reads the protected credential again. Cancelling that read must
    /// publish an error rather than reuse a token from an earlier authorization.
    @Test("Refresh cannot bypass a cancelled protected credential read")
    func refreshReportsAuthenticationCancellation() async {
        // Arrange
        let provider = makeProvider()
        let storage = Keychain.DefaultStorage(account: "oauthkit.test.\(UUID().uuidString)", statusOverride: { operation in
            operation == .copy ? errSecUserCanceled : nil
        })
        let client = OAuth(providers: [], keychain: Keychain(storage: storage), options: [.requireBiometricAuthentication: true])

        // Act
        await client.refreshToken(provider: provider)

        // Assert
        #expect(client.state == .error(provider, .keychain))
    }

    /// The OS can refuse deletion while credentials may still exist. The caller
    /// must receive the storage status and the observable client must not claim logout.
    @Test("Failed deletion preserves state and returns the Security error")
    func deletionFailureDoesNotPublishEmptyState() throws {
        // Arrange
        let provider = makeProvider()
        let storage = Keychain.DefaultStorage(account: "oauthkit.test.\(UUID().uuidString)", statusOverride: { operation in
            operation == .delete ? errSecInteractionNotAllowed : nil
        })
        let client = OAuth(providers: [], keychain: Keychain(storage: storage))
        client.state = .requestingDeviceCode(provider)

        // Act
        do {
            try client.clear()
            Issue.record("Deletion was expected to fail")
        } catch KeychainError.securityStatus(let status) {
            // Assert
            #expect(status == errSecInteractionNotAllowed)
        }
        #expect(client.state == .requestingDeviceCode(provider))
    }

    @Test("Revoked refresh credentials remain observable when deletion fails")
    func revokedRefreshReportsDeletionFailure() async throws {
        let provider = makeProvider()
        let namespace = "oauthkit.test.\(UUID().uuidString)"
        let storage = Keychain.DefaultStorage(account: namespace, statusOverride: { operation in
            operation == .delete ? errSecInteractionNotAllowed : nil
        })
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OAuthInvalidGrantURLProtocol.self]
        let client = OAuth(providers: [], keychain: Keychain(storage: storage), options: [
            .urlSession: URLSession(configuration: configuration),
            .autoRefresh: false,
        ])
        let authorization = OAuth.Authorization(issuer: provider.id, token: .init(
            accessToken: "old-access", refreshToken: "revoked-refresh",
            expiresIn: 3600, scope: nil, type: "Bearer"
        ))
        try client.keychain.set(authorization, for: provider.id)
        defer { try? Keychain(namespace).clear() }

        await client.refreshToken(provider: provider)

        #expect(client.state == .error(provider, .keychain))
        let preserved: OAuth.Authorization? = try client.keychain.get(key: provider.id)
        #expect(preserved == authorization)
    }

    private func makeProvider() -> OAuth.Provider {
        OAuth.Provider(
            id: "protected-provider",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            clientID: "native-client"
        )
    }
}
#endif
