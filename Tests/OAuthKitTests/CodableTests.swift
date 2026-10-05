//
//  CodeableTests.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation
@testable import OAuthKit
import Testing

@Suite("Codable Tests")
struct CodableTests {

    private let encoder: JSONEncoder = .init()
    private let decoder: JSONDecoder = .init()

    @Test("Encoding and Decoding Providers")
    func whenEncodingDecodingProviders() async throws {

        let provider: OAuth.Provider = .init(id: "GitHub",
                                             authorizationURL: URL(string: "https://github.com/login/oauth/authorize")!,
                                             accessTokenURL: URL(string: "https://github.com/login/oauth/access_token")!,
                                             clientID: "CLIENT_ID",
                                             clientSecret: "CLIENT_SECRET",
                                             scope: ["email"],
                                             customUserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
                                             debug: true)

        let data = try encoder.encode(provider)
        let decoded: OAuth.Provider = try decoder.decode(OAuth.Provider.self, from: data)
        #expect(provider == decoded)
    }

    @Test("Encoding and Decoding Tokens")
    func whenEncodingDecodingTokens() async throws {

        let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 3600, scope: "openid", type: "bearer")

        let data = try encoder.encode(token)
        let decoded: OAuth.Token = try decoder.decode(OAuth.Token.self, from: data)
        #expect(token == decoded)
    }

    @Test("Encoding and Decoding Device Codes")
    func whenDecodingDeviceCodes() async throws {

        let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: "ABC-XYZ", verificationUri: "https://example.com/device", expiresIn: 1800, interval: 5)

        let data = try encoder.encode(deviceCode)
        let decoded: OAuth.DeviceCode = try decoder.decode(OAuth.DeviceCode.self, from: data)
        #expect(deviceCode.deviceCode == decoded.deviceCode)
        #expect(deviceCode.userCode == decoded.userCode)
        #expect(deviceCode.verificationUri == decoded.verificationUri)
        #expect(deviceCode.verificationUriComplete == decoded.verificationUriComplete)
        #expect(deviceCode.expiresIn == decoded.expiresIn)
        #expect(deviceCode.isExpired == false)
        #expect(deviceCode.expiration != nil)
        #expect(deviceCode.interval == decoded.interval)
    }
    @Test("Device codes default to a five-second interval")
    func deviceCodeDefaultsPollingInterval() throws {
        // Arrange
        let data = Data(#"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":600}"#.utf8)

        // Act
        let deviceCode = try decoder.decode(OAuth.DeviceCode.self, from: data)

        // Assert
        #expect(deviceCode.interval == 5)
        #expect(deviceCode.expiresIn == 600)
    }

    @Test("Device codes reject missing and nonpositive expiry")
    func deviceCodeRequiresPositiveExpiry() {
        // Arrange
        let payloads = [
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device"}"#,
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":0}"#,
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":-1}"#
        ]

        // Act
        let decoded = payloads.map { try? decoder.decode(OAuth.DeviceCode.self, from: Data($0.utf8)) }

        // Assert
        #expect(decoded.allSatisfy { $0 == nil })
    }

    @Test("Device codes reject invalid and out-of-range timing values")
    func deviceCodeRejectsInvalidTiming() {
        // Arrange
        let payloads = [
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":10,"interval":0}"#,
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":10,"interval":-1}"#,
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":31536001}"#,
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":10,"interval":31536001}"#,
            #"{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":18446744073709551615}"#
        ]

        // Act
        let decoded = payloads.map { try? decoder.decode(OAuth.DeviceCode.self, from: Data($0.utf8)) }

        // Assert
        #expect(decoded.allSatisfy { $0 == nil })
    }
}
