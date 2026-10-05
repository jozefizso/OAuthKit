import Foundation

actor OAuthHeldResponseGate {
    private(set) var requestCount = 0
    private var responseWaiters: [CheckedContinuation<(Data, Int)?, Never>] = []
    private var releasedResponse: (Data, Int)?
    private var cancelled = false

    private var ignoresCancellation = false
    private var requestWaiters: [CheckedContinuation<Void, Never>] = []
    func waitForRequest() async {
        guard requestCount == 0 else { return }
        await withCheckedContinuation { requestWaiters.append($0) }
    }

    func release(withAccessToken accessToken: String, refreshToken: String = "refresh-token") {
        let body = "{\"access_token\":\"\(accessToken)\",\"refresh_token\":\"\(refreshToken)\",\"expires_in\":3600,\"token_type\":\"Bearer\"}"
        release(response: Data(body.utf8), statusCode: 200)
    }
    func release(response data: Data, statusCode: Int) {
        releasedResponse = (data, statusCode)
        let waiters = responseWaiters
        responseWaiters.removeAll()
        for waiter in waiters { waiter.resume(returning: (data, statusCode)) }
    }
    func ignoreCancellation() {
        ignoresCancellation = true
    }
    func cancel() {
        guard !ignoresCancellation else { return }
        cancelled = true
        let waiters = responseWaiters
        responseWaiters.removeAll()
        for waiter in waiters { waiter.resume(returning: nil) }
    }
    func responseForRequest() async -> (Data, Int)? {
        requestCount += 1
        let waiters = requestWaiters
        requestWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
        if cancelled { return nil }
        if let releasedResponse { return releasedResponse }
        return await withCheckedContinuation { responseWaiters.append($0) }
    }
}

actor OAuthHeldResponseRegistry {
    static let shared = OAuthHeldResponseRegistry()
    private var gates: [String: OAuthHeldResponseGate] = [:]

    func register(_ gate: OAuthHeldResponseGate, for host: String) {
        gates[host] = gate
    }

    func remove(for host: String) {
        gates.removeValue(forKey: host)
    }

    func gate(for host: String?) -> OAuthHeldResponseGate? {
        guard let host else { return nil }
        return gates[host]
    }

    static func register(_ gate: OAuthHeldResponseGate, for host: String) async {
        await shared.register(gate, for: host)
    }

    static func remove(for host: String) async {
        await shared.remove(for: host)
    }

    static func gate(for host: String?) async -> OAuthHeldResponseGate? {
        await shared.gate(for: host)
    }
}

final class OAuthHeldResponseURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.hasSuffix(".oauthkit.test") == true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let host = request.url?.host
        let url = request.url
        nonisolated(unsafe) let target: URLProtocol = self
        Task {
            guard let gate = await OAuthHeldResponseRegistry.gate(for: host),
                  let (data, statusCode) = await gate.responseForRequest() else { return }
            guard let url,
                  let response = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"]) else { return }
            target.client?.urlProtocol(target, didReceive: response, cacheStoragePolicy: .notAllowed)
            target.client?.urlProtocol(target, didLoad: data)
            target.client?.urlProtocolDidFinishLoading(target)
        }
    }

    override func stopLoading() {
        let host = request.url?.host
        Task {
            guard let gate = await OAuthHeldResponseRegistry.gate(for: host) else { return }
            await gate.cancel()
        }
    }
}
