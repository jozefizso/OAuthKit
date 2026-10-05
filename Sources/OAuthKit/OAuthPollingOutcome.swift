import Foundation

// Internal result used to race a device-token request against its monotonic expiry.
enum OAuthPollingOutcome {
    case response(Data, URLResponse)
    case timedOut
    case failed
    case expired
}
