//
//  OAuth+Monitor.swift
//  OAuthKit
//
//  Created by Kevin McKee
//

import Foundation
import Observation
@testable import OAuthKit

extension OAuth {

    /// Provides a testing utility to stream OAuth state changes until authorization or error.
    /// This is necessary because a unit test can potentially die as an asynchronous request is received that
    /// inserts an authorization record into the keychain. This allows us to keep the keychain clean and not get littered with test records.
    @MainActor
    class Monitor {

        typealias OAuthStateAsyncStream = AsyncStream<OAuth.State>

        private let oauth: OAuth
        private var continuation: OAuthStateAsyncStream.Continuation?
        private var isStopped = false

        lazy var stream: OAuthStateAsyncStream = {
            AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                self.continuation = continuation
                continuation.onTermination = { [weak self] _ in
                    Task { @MainActor [weak self] in
                        self?.stop()
                    }
                }
                publishCurrentState()
            }
        }()

        /// Initialzation.
        /// - Parameter oauth: the oauth state to stream
        init(oauth: OAuth) {
            self.oauth = oauth
        }

        deinit {
            continuation?.finish()
        }

        func stop() {
            guard !isStopped else { return }
            isStopped = true
            continuation?.finish()
        }

        private func publishCurrentState() {
            guard !isStopped else { return }
            let state = oauth.state
            continuation?.yield(state)
            switch state {
            case .authorized(_, _), .error(_, _):
                stop()
            case .empty, .authorizing, .requestingAccessToken, .requestingDeviceCode, .receivedDeviceCode:
                withObservationTracking {
                    _ = oauth.state
                } onChange: { [weak self] in
                    Task { @MainActor [weak self] in
                        self?.publishCurrentState()
                    }
                }
            }
        }
    }
}
