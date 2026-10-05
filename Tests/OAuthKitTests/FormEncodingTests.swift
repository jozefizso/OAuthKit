import Foundation
@testable import OAuthKit
import Testing

@Suite("OAuth form encoding")
struct FormEncodingTests {
    /// Authorization codes can contain reserved characters and Unicode. The token
    /// endpoint must receive one intact code, not extra injected form parameters.
    @Test("Authorization codes cannot inject or corrupt form parameters")
    func authorizationCodeRemainsOneFormValue() throws {
        // Arrange
        let provider = OAuth.Provider(
            id: "form-test",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            clientID: "public-client",
            clientSecret: nil
        )
        let code = "grant&admin=true+100% naïve"

        // Act
        let request = try #require(OAuth.Request.token(provider: provider, code: code))
        let body = try #require(request.httpBody.flatMap { String(data: $0, encoding: .utf8) })
        let fields = body.split(separator: "&").map(String.init)

        // Assert
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded")
        #expect(fields.filter { $0.hasPrefix("code=") } == ["code=grant%26admin%3Dtrue%2B100%25+na%C3%AFve"])
        #expect(!fields.contains { $0.hasPrefix("admin=") })
        #expect(request.url?.query == nil)
    }

    /// Device client IDs and space-delimited scopes must use the same UTF-8 form
    /// encoding as token requests, including literal plus signs and ampersands.
    @Test("Device authorization preserves client ID and Unicode scope values")
    func deviceParametersRemainIntact() throws {
        // Arrange
        let provider = OAuth.Provider(
            id: "device-form-test",
            authorizationURL: URL(string: "https://example.com/authorize")!,
            accessTokenURL: URL(string: "https://example.com/token")!,
            deviceCodeURL: URL(string: "https://example.com/device")!,
            clientID: "client&+% 名",
            clientSecret: nil,
            scope: ["read&write", "team+chat", "naïve"]
        )

        // Act
        let request = try #require(OAuth.Request.device(provider: provider))
        let body = try #require(request.httpBody.flatMap { String(data: $0, encoding: .utf8) })
        let fields = body.split(separator: "&").map(String.init)

        // Assert
        #expect(fields.contains("client_id=client%26%2B%25+%E5%90%8D"))
        #expect(fields.contains("scope=read%26write+team%2Bchat+na%C3%AFve"))
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/x-www-form-urlencoded")
        #expect(request.url?.query == nil)
    }
}
