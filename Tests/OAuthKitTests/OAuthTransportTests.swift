import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import OAuthKit
import Testing

@MainActor
@Suite("OAuth transport boundaries", .serialized)
struct OAuthTransportTests {
    /// A confidential server redirect must not replay Basic credentials to HTTP,
    /// even if the redirected destination would return a valid-looking token.
    @Test("A token endpoint redirect cannot downgrade credential transport")
    func tokenRedirectIsNotFollowed() async throws {
        // Arrange
        RedirectProtocol.attempts.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RedirectProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let provider = OAuth.Provider(
            id: "redirect-test",
            authorizationURL: URL(string: "https://oauthkit-transport.invalid/authorize")!,
            accessTokenURL: URL(string: "https://oauthkit-transport.invalid/token")!,
            clientID: "backend-client",
            clientSecret: "backend-secret",
            clientType: .confidential
        )
        let client = OAuth(options: [
            .applicationTag: "oauthkit.test.\(UUID().uuidString)",
            .urlSession: session
        ])
        defer { _ = try? client.clear() }

        // Act
        await client.requestClientCredentials(provider: provider)

        // Assert
        #expect(RedirectProtocol.attempts.insecureRequests == 0)
        #expect(client.state == .error(provider, .decoding))
        let stored: OAuth.Authorization? = try client.keychain.get(key: provider.id)
        #expect(stored == nil)
    }

    /// Configuration errors must terminate the observable device flow instead of
    /// leaving an application permanently waiting for a device code.
    @Test("An insecure device endpoint publishes an observable failure")
    func insecureDeviceEndpointFailsClosed() async {
        // Arrange
        let provider = OAuth.Provider(
            id: "insecure-device",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            deviceCodeURL: URL(string: "http://example.com/device")!,
            clientID: "public-device"
        )
        let client = OAuth(options: [.applicationTag: "oauthkit.test.\(UUID().uuidString)"])

        // Act
        await client.requestDeviceCode(provider: provider)

        // Assert
        #expect(client.state == .error(provider, .malformedURL))
    }
}

private final class RedirectAttempts: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var insecureRequests: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        count = 0
    }

    func recordInsecureRequest() {
        lock.lock()
        defer { lock.unlock() }
        count += 1
    }
}

private final class RedirectProtocol: URLProtocol, @unchecked Sendable {
    static let attempts = RedirectAttempts()

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "oauthkit-transport.invalid"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let url = request.url!
        if url.scheme == "http" {
            Self.attempts.recordInsecureRequest()
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(#"{"access_token":"must-not-authorize","token_type":"Bearer"}"#.utf8))
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let destination = URL(string: "http://oauthkit-transport.invalid/token")!
        let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: ["Location": destination.absoluteString])!
        var redirected = request
        redirected.url = destination
        client?.urlProtocol(self, wasRedirectedTo: redirected, redirectResponse: response)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
