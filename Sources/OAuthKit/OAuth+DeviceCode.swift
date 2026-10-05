//
//  OAuth+DeviceCode.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation

extension OAuth {

    /// A codable type returned from a server that holds device code information.
    /// - SeeAlso:
    /// [Requesting a Device Code](https://www.oauth.com/playground/device-code.html)
    public struct DeviceCode: Codable, Equatable, Sendable {

        /// Shared safe bound for provider-controlled timing in seconds (one year; Int32-safe).
        static let maximumTiming = 31_536_000

        /// A constant for the oauth grant type.
        static let grantType = "urn:ietf:params:oauth:grant-type:device_code"

        /// The server assigned device code.
        public let deviceCode: String
        /// The code the user should enter when visiting the `verificationUri`
        public let userCode: String
        /// The uri the user should visit to enter the `userCode`
        public let verificationUri: String
        /// Either a QR Code or shortened URL with embedded user code
        public let verificationUriComplete: String?
        /// The required lifetime in seconds for `deviceCode` and `userCode`.
        public let expiresIn: Int
        /// The polling interval in seconds. Omitted server values default to five seconds.
        public let interval: Int
        /// The issue date.
        public let issued: Date = .now

        /// Returns true if the device code is expired.
        public var isExpired: Bool {
            expiration.map { $0 <= Date.now } ?? true
        }

        /// Returns the expiration date of the device token.
        public var expiration: Date? {
            let value = issued.addingTimeInterval(TimeInterval(expiresIn))
            return value.timeIntervalSince1970.isFinite ? value : nil
        }

        enum CodingKeys: String, CodingKey {
            case deviceCode = "device_code"
            case userCode = "user_code"
            case verificationUri = "verification_uri"
            /// Google sends `verification_url` instead of `verification_uri` so we need to account for both.
            /// See: https://developers.google.com/identity/protocols/oauth2/limited-input-device
            case verificationUrl = "verification_url"
            case verificationUriComplete = "verification_uri_complete"
            case expiresIn = "expires_in"
            case interval
        }

        /// Public initializer
        /// - Parameters:
        ///   - deviceCode: the device code
        ///   - userCode: the user code
        ///   - verificationUri: the verification uri
        ///   - verificationUriComplete: the qr code or shortened url with embedded user code
        ///   - expiresIn: lifetime in seconds
        ///   - interval: the polling interval
        public init(deviceCode: String, userCode: String,
                    verificationUri: String, verificationUriComplete: String? = nil,
                    expiresIn: Int, interval: Int = 5) {
            self.deviceCode = deviceCode
            self.userCode = userCode
            self.verificationUri = verificationUri
            self.verificationUriComplete = verificationUriComplete
            self.expiresIn = expiresIn
            self.interval = interval
        }

        /// Custom initializer for handling different keys sent by different providers (Google)
        /// - Parameters:
        ///   - decoder: the decoder to use
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            deviceCode = try container.decode(String.self, forKey: .deviceCode)
            userCode = try container.decode(String.self, forKey: .userCode)
            expiresIn = try container.decode(Int.self, forKey: .expiresIn)
            interval = try container.decodeIfPresent(Int.self, forKey: .interval) ?? 5
            verificationUriComplete = try container.decodeIfPresent(String.self, forKey: .verificationUriComplete)

            let verification = try container.decodeIfPresent(String.self, forKey: .verificationUri)
            if let verification {
                verificationUri = verification
            } else {
                verificationUri = try container.decode(String.self, forKey: .verificationUrl)
            }
            guard expiresIn > 0, expiresIn <= Self.maximumTiming,
                  interval > 0, interval <= Self.maximumTiming,
                  expiration != nil else {
                throw DecodingError.dataCorruptedError(forKey: .expiresIn, in: container,
                                                       debugDescription: "Device code timing must be positive and within the supported range.")
            }
        }

        /// Encodes the device code.
        /// - Parameters:
        ///   - encoder: the encoder to use
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(deviceCode, forKey: .deviceCode)
            try container.encode(userCode, forKey: .userCode)
            try container.encode(verificationUri, forKey: .verificationUri)
            try container.encodeIfPresent(verificationUriComplete, forKey: .verificationUri)
            try container.encode(interval, forKey: .interval)
            try container.encodeIfPresent(expiresIn, forKey: .expiresIn)
        }
    }
}
