import Foundation
#if canImport(Security) && (os(macOS) || os(iOS) || os(visionOS))
@testable import OAuthKit
import Security
import Testing

@MainActor
@Suite("OAuth storage failure handling")
struct OAuthStorageFailureTests {
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
