import Foundation

actor OAuthHeldResponseGate {
    private(set) var requestCount = 0
    private var requestWaiters: [CheckedContinuation<Void, Never>] = []
    private var responseWaiters: [CheckedContinuation<Data, Never>] = []
    private var releasedResponse: Data?

    func waitForRequest() async {
        guard requestCount == 0 else { return }
        await withCheckedContinuation { requestWaiters.append($0) }
    }

    func release(withAccessToken accessToken: String) {
        let body = "{\"access_token\":\"\(accessToken)\",\"refresh_token\":\"refresh-token\",\"expires_in\":3600,\"token_type\":\"Bearer\"}"
        let data = Data(body.utf8)
        releasedResponse = data
        let waiters = responseWaiters
        responseWaiters.removeAll()
        for waiter in waiters { waiter.resume(returning: data) }
    }
    func responseForRequest() async -> Data {
        requestCount += 1
        let waiters = requestWaiters
        requestWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
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

final class OAuthHeldResponseURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.hasSuffix(".oauthkit.test") == true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Task { [weak self] in
            guard let self,
                  let gate = await OAuthHeldResponseRegistry.gate(for: request.url?.host) else { return }
            let data = await gate.responseForRequest()
            guard let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"]) else { return }
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {}
}
