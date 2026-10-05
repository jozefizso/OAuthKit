import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// OAuth endpoint redirects are not followed: replaying a grant body or Basic
/// header could disclose credentials to a different origin or insecure transport.
final class OAuthRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = OAuthRedirectDelegate()

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
