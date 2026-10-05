//
//  OAauthTestURLProtocol.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation
@testable import OAuthKit

/// The version of the http response
private let httpVersion = "HTTP/1.1"
/// A successful status code
private let statusCodeSuccess = 200
/// A status code that indicates the error seems to have been caused by the client
private let statusCodeBadRequest = 400
/// A status code that indicates the server has encountered an error or is otherwise incapable of performing the request
private let statusCodeServerError = 500

/// Builds and responds to mock test requests.
enum OAuthTestResponseStep: Sendable {
    case response(Data)
    case failure(URLError.Code)
}

actor OAuthTestRequestHandler {
    let encoder: JSONEncoder = .init()
    let statusCode: Int
    let responseData: Data?
    let responseSequence: [OAuthTestResponseStep]?
    private var requestCount = 0
    private var responseIndex = 0

    /// Initializer.
    /// - Parameters:
    ///   - statusCode: the status code to return
    ///   - responseData: optional fixed body to return
    ///   - responseSequence: optional sequence of response bodies and failures
    init(statusCode: Int = statusCodeSuccess, responseData: Data? = nil,
         responseSequence: [OAuthTestResponseStep]? = nil) {
        self.statusCode = statusCode
        self.responseData = responseData
        self.responseSequence = responseSequence
    }

    /// Returns a mocked URL response for the given request and status code
    /// - Parameters:
    ///   - request: the request
    ///   - statusCode: the status code to return
    /// - Returns: an url response
    private func response(request: URLRequest) -> HTTPURLResponse {
        HTTPURLResponse(url: request.url!, statusCode: statusCode, httpVersion: httpVersion, headerFields: nil)!
    }

    /// Returns mock test data for the given request.
    /// - Parameter request: the request
    /// - Returns: the data to respond with
    private func data(request: URLRequest) -> Data {

        if let responseData { return responseData }
        guard statusCode == statusCodeSuccess, let url = request.url else { return .init() }

        if url.path.hasSuffix("/device/code") {
            let deviceCode: OAuth.DeviceCode = .init(deviceCode: .secureRandom(), userCode: "0A17-B332", verificationUri: "https://github.com/codefiesta/OAuthKit", expiresIn: 2, interval: 1)
            return try! encoder.encode(deviceCode)
        }

        // Returns oauth access token data
        if url.absoluteString.contains("token") {
            let token: OAuth.Token = .init(accessToken: .secureRandom(), refreshToken: .secureRandom(), expiresIn: 3600, scope: nil, type: "Bearer")
            return try! encoder.encode(token)
        }

        return .init()
    }

    /// Returns a mocked test response for the given url request
    /// - Parameter request: the url request to return a mock test response for
    /// - Returns: a tuple of response and data
    func execute(_ request: URLRequest) async throws -> (HTTPURLResponse, Data) {
        let response = response(request: request)
        let data: Data
        requestCount += 1
        if let responseSequence, !responseSequence.isEmpty {
            let step = responseSequence[min(responseIndex, responseSequence.count - 1)]
            responseIndex += 1
            switch step {
            case .response(let payload):
                data = payload
            case .failure(let code):
                throw URLError(code)
            }
        } else if let responseData {
            data = responseData
        } else {
            data = self.data(request: request)
        }
        return (response, data)
    }

    func requestsMade() -> Int {
        requestCount
    }
    func reset() {
        requestCount = 0
        responseIndex = 0
    }
}

/// OAuth Test URL Protocol that intercepts test request and returns mocked response data.
class OAuthTestURLProtocol: URLProtocol, @unchecked Sendable {

    /// The handler responsible for returning mocked test response data
    var handler: OAuthTestRequestHandler {
        .init()
    }

    /// Determines whether this protocol can handle the given request.
    /// - Parameter request: the request to handle
    /// - Returns: always true
    override class func canInit(with request: URLRequest) -> Bool { true }

    /// Returns the canonical version of the given request.
    /// - Parameter request: the request
    /// - Returns: the canonical version of the given request.
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    /// Starts loading the given request.
    override func startLoading() {
        Task {
            // Client error
            guard handler.statusCode != 500 else {
                client?.urlProtocol(self, didFailWithError: OAError.badResponse)
                return
            }
            do {
                let (response, data) = try await handler.execute(request)
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: data)
                client?.urlProtocolDidFinishLoading(self)
            } catch {
                client?.urlProtocol(self, didFailWithError: error)
            }
        }
    }

    /// Stops the loading of a request.
    override func stopLoading() {}
}

/// An URLProtocol that returns 400 error response and empty data.
class OAuthTestClientErrorURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    override var handler: OAuthTestRequestHandler {
        .init(statusCode: statusCodeBadRequest)
    }
}

/// An URLProtocol that returns 500 error responses and indicates that data has failed to load successfully.
class OAuthTestServerErrorURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    override var handler: OAuthTestRequestHandler {
        .init(statusCode: statusCodeServerError)
    }
}

/// An URLProtocol that returns a terminal OAuth authorization error.
class OAuthTestOAuthErrorURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    override func startLoading() {
        let data = Data(#"{"error":"access_denied"}"#.utf8)
        let response = HTTPURLResponse(url: request.url!, statusCode: 400, httpVersion: httpVersion, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
}

/// An URLProtocol that returns pending, slow_down, pending, then a terminal error.
class OAuthTestSlowDownURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    private static let scriptedHandler = OAuthTestRequestHandler(
        statusCode: statusCodeBadRequest,
        responseSequence: [
            .response(Data(#"{"error":"authorization_pending"}"#.utf8)),
            .response(Data(#"{"error":"slow_down"}"#.utf8)),
            .response(Data(#"{"error":"authorization_pending"}"#.utf8)),
            .response(Data(#"{"error":"access_denied"}"#.utf8))
        ])

    override var handler: OAuthTestRequestHandler {
        Self.scriptedHandler
    }
    static func requestsMade() async -> Int {
        await scriptedHandler.requestsMade()
    }
    static func reset() async {
        await scriptedHandler.reset()
    }
}

/// An URLProtocol that times out once and then returns a terminal OAuth error.
class OAuthTestTimedOutURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    private static let scriptedHandler = OAuthTestRequestHandler(
        statusCode: statusCodeBadRequest,
        responseSequence: [
            .failure(.timedOut),
            .response(Data(#"{"error":"access_denied"}"#.utf8))
        ])

    override var handler: OAuthTestRequestHandler {
        Self.scriptedHandler
    }

    static func requestsMade() async -> Int {
        await scriptedHandler.requestsMade()
    }
    static func reset() async {
        await scriptedHandler.reset()
    }
}


/// Returns a successful token response and counts requests for deterministic tests.
class OAuthTestCountingTokenURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    private static let scriptedHandler = OAuthTestRequestHandler(
        responseData: Data(#"{"access_token":"access-token","token_type":"Bearer"}"#.utf8))

    override var handler: OAuthTestRequestHandler {
        Self.scriptedHandler
    }

    static func requestsMade() async -> Int {
        await scriptedHandler.requestsMade()
    }

    static func reset() async {
        await scriptedHandler.reset()
    }
}

/// An URLProtocol that returns TLS failures and counts requests.
class OAuthTestTLSFailureURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    private static let scriptedHandler = OAuthTestRequestHandler(
        responseSequence: [.failure(.secureConnectionFailed)])

    override var handler: OAuthTestRequestHandler {
        Self.scriptedHandler
    }

    static func requestsMade() async -> Int {
        await scriptedHandler.requestsMade()
    }
    static func reset() async {
        await scriptedHandler.reset()
    }
}

private actor OAuthTestHeldResponseGate {
    private var requestStarted = false
    private var requestCount = 0
    private var startWaiter: CheckedContinuation<Void, Never>?
    private var responseWaiter: CheckedContinuation<Data, Never>?
    private var releasedResponse: Data?

    func waitForRequest() async {
        guard !requestStarted else { return }
        await withCheckedContinuation { startWaiter = $0 }
    }

    func holdResponse() async -> Data {
        requestStarted = true
        requestCount += 1
        startWaiter?.resume()
        startWaiter = nil
        if let releasedResponse {
            self.releasedResponse = nil
            return releasedResponse
        }
        return await withCheckedContinuation { responseWaiter = $0 }
    }

    func release(_ data: Data) {
        if let responseWaiter {
            self.responseWaiter = nil
            responseWaiter.resume(returning: data)
        } else {
            releasedResponse = data
        }
    }

    func requestsMade() -> Int {
        requestCount
    }

    func reset() {
        requestStarted = false
        requestCount = 0
        startWaiter = nil
        responseWaiter = nil
        releasedResponse = nil
    }
}

/// An URLProtocol that withholds a successful token response until released by the test.
class OAuthTestHeldResponseURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {

    private static let gate = OAuthTestHeldResponseGate()

    override func startLoading() {
        Task {
            let data = await Self.gate.holdResponse()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: httpVersion, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    static func reset() async {
        await gate.reset()
    }

    static func waitForRequest() async {
        await gate.waitForRequest()
    }

    static func release(_ data: Data) async {
        await gate.release(data)
    }

    static func requestsMade() async -> Int {
        await gate.requestsMade()
    }
}

/// Returns a successful refresh response without a replacement refresh token.
final class OAuthRefreshTokenOmittedURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {
    override var handler: OAuthTestRequestHandler {
        .init(responseData: Data(#"{"access_token":"access-new","expires_in":1800,"token_type":"Bearer","scope":"new-scope","id_token":"id-new"}"#.utf8))
    }
}

/// Returns a successful refresh response with a rotated refresh token.
final class OAuthRefreshTokenRotatedURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {
    override var handler: OAuthTestRequestHandler {
        .init(responseData: Data(#"{"access_token":"access-new","refresh_token":"refresh-new","expires_in":1800,"token_type":"Bearer","scope":"new-scope","id_token":"id-new"}"#.utf8))
    }
}

/// Returns an invalid_grant error payload.
final class OAuthInvalidGrantURLProtocol: OAuthTestURLProtocol, @unchecked Sendable {
    override var handler: OAuthTestRequestHandler {
        .init(statusCode: statusCodeBadRequest, responseData: Data(#"{"error":"invalid_grant","error_description":"Refresh token was revoked"}"#.utf8))
    }
}
