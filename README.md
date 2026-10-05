![Build](https://github.com/codefiesta/OAuthKit/actions/workflows/swift.yml/badge.svg)
![Swift 6.1+](https://img.shields.io/badge/Swift-6.1%2B-gold.svg)
![Xcode 26.0+](https://img.shields.io/badge/Xcode-26.0%2B-tomato.svg)
![iOS 17.0+](https://img.shields.io/badge/iOS-17.0%2B-crimson.svg)
![macOS 15.0+](https://img.shields.io/badge/macOS-15.0%2B-skyblue.svg)
![tvOS 18.0+](https://img.shields.io/badge/tvOS-18.0%2B-blue.svg)
![visionOS 1.0+](https://img.shields.io/badge/visionOS-1.0%2B-violet.svg)
![watchOS 10.0+](https://img.shields.io/badge/watchOS-10.0%2B-magenta.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-indigo.svg)](https://opensource.org/licenses/MIT)
![Code Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/codefiesta/87655b6e3c89b9198287b2fefbfa641f/raw/oauthkit-coverage.json)

# OAuthKit
<img src="https://github.com/user-attachments/assets/039ee445-42af-433d-9793-56fc36330952" height="100" align="left"/>

OAuthKit is a contemporary, event-driven Swift Package that utilizes the [Observation](https://developer.apple.com/documentation/observation) Framework to implement the observer design pattern and publish [OAuth 2.0](https://oauth.net/2/) events. This enables application developers to effortlessly configure OAuth Providers and concentrate on developing exceptional applications rather than being preoccupied with the intricacies of authorization flows.
<br clear="left"/>

## OAuthKit Features

OAuthKit is a small, lightweight package that provides out of the box [Swift Concurrency](https://docs.swift.org/swift-book/documentation/the-swift-programming-language/concurrency/) safety support and [Observable](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/oauth/state-swift.enum) OAuth 2.0 state events that allow fine grained control over when and how to start authorization flows. 

Key features include:

- [Simple Configuration](#oauthkit-configuration)
- [Item-level biometric Keychain protection](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/configuration#Keychain-Protection)
- [Private Browsing with non-persistent WebKit Datastores](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/configuration#Private-Browsing)
- [Custom URLSession](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/configuration#URL-Session) configuration for complete control custom protocol specific data
- [Observable State](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/gettingstarted#Observing-OAuth-State) driven events to allow full control over when and if users are prompted to authenticate with an OAuth provider
- Supports all Apple Platforms (iOS, macOS, tvOS, visionOS, watchOS)
- [Supported OAuth 2.0 grants](#oauthkit-authorization-flows)
	- [Authorization Code](#oauth-20-authorization-code-flow)
	- [PKCE](#oauth-20-pkce-flow)
	- [Device Code](#oauth-20-device-code-flow)
	- [Client Credentials](#oauth-20-client-credentials-flow)
	- [OpenID Connect](https://www.oauth.com/playground/oidc.html)

## OAuthKit Installation

OAuthKit can be installed using [Swift Package Manager](https://www.swift.org/documentation/package-manager/).

```swift
dependencies: [
    .package(url: "https://github.com/codefiesta/OAuthKit", from: "2.2.0")
]
```

## OAuthKit Usage

The following is an example of the simplest usage of using OAuthKit across multiple platforms (iOS, macOS, visionOS, tvOS, watchOS):

```swift
import OAuthKit
import SwiftUI

@main
struct OAuthApp: App {

    @Environment(\.oauth)
    var oauth: OAuth
    
    /// Build the scene body
    var body: some Scene {

        WindowGroup {
            ContentView()
        }
        
        #if canImport(AuthenticationServices)
        WindowGroup(id: "oauth") {
            OAWebView(oauth: oauth)
        }
        #endif
    }
} 

struct ContentView: View {
    
    @Environment(\.oauth)
    var oauth: OAuth

    #if canImport(AuthenticationServices)
    @Environment(\.openWindow)
    var openWindow
    
    @Environment(\.dismissWindow)
    private var dismissWindow
    #endif

    /// The view body that reacts to oauth state changes
    var body: some View {
        VStack {
            switch oauth.state {
            case .empty:
                providerList
            case .authorizing(let provider, let grantType):
                Text("Authorizing [\(provider.id)] with [\(grantType.rawValue)]")
            case .requestingAccessToken(let provider):
                Text("Requesting Access Token [\(provider.id)]")
            case .requestingDeviceCode(let provider):
                Text("Requesting Device Code [\(provider.id)]")
            case .authorized(let provider, _):
                Button("Authorized [\(provider.id)]") {
                    do { try oauth.clear() }
                    catch {
                        // Show a storage error; credentials were not confirmed deleted.
                        oauth.state = .error(provider, .keychain)
                    }
                }
            case .receivedDeviceCode(_, let deviceCode):
                Text("To login, visit")
                Text(.init("[\(deviceCode.verificationUri)](\(deviceCode.verificationUri))"))
                    .foregroundStyle(.blue)
                Text("and enter the following code:")
                Text(deviceCode.userCode)
                    .padding()
                    .border(Color.primary)
                    .font(.title)
            case .error(let provider, let error):
                Text("Error [\(provider.id)]: \(error.localizedDescription)")
            }
        }
        .onChange(of: oauth.state) { _, state in
            handle(state: state)
        }
    }
    
    /// Displays a list of oauth providers.
    var providerList: some View {
        List(oauth.providers) { provider in
            Button(provider.id) {
                authorize(provider: provider)
            }
        }
    }

    /// Starts the authorization process for the specified provider.
    /// - Parameter provider: the provider to begin authorization for
    private func authorize(provider: OAuth.Provider) {
        #if canImport(AuthenticationServices)
        oauth.authorize(provider: provider)
        #else
        oauth.authorize(provider: provider, grantType: .deviceCode)
        #endif
    }
    
    /// Reacts to oauth state changes by opening or closing authorization windows.
    /// - Parameter state: the published state change
    private func handle(state: OAuth.State) {
        #if canImport(AuthenticationServices)
        switch state {
        case .empty, .error, .requestingAccessToken, .requestingDeviceCode:
            break
        case .authorizing, .receivedDeviceCode:
            openWindow(id: "oauth")
        case .authorized(_, _):
            dismissWindow(id: "oauth")
        }
        #endif
    }
}
```

## OAuthKit Configuration
By default, the easiest way to configure OAuthKit is to simply drop an `oauth.json` file into your main bundle and it will get automatically loaded into your swift application and available as an [Environment](https://developer.apple.com/documentation/swiftui/environment) property wrapper. You can find an example `oauth.json` file [here](https://github.com/codefiesta/OAuthKit/blob/main/Tests/OAuthKitTests/Resources/oauth.json). OAuthKit provides flexible constructor options that allows developers to customize  how their oauth client is initialized and what features they want to implement. See the [oauth.init(\_:bundle:options)](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/oauth) method for details.

### OAuth initialized from main bundle (default)
```swift
@Environment(\.oauth)
var oauth: OAuth
```
### OAuth initialized from specified bundle
If you want to customize your OAuth environment or are using modules in your application, you can also specify which bundle to load configure files from:

```swift
let oauth: OAuth = .init(.module)
```

### OAuth initialized with providers
Provider configuration may be loaded from JSON or constructed programmatically.
Distributed native apps are public clients; neither CI generation nor compilation
makes an embedded client secret confidential.

```swift
let providers: [OAuth.Provider] = ...
let options: [OAuth.Option: Any] = [
    .applicationTag: "com.bundle.identifier",
    .autoRefresh: true
]
let oauth: OAuth = .init(providers: providers, options: options)
```

Keychain records are isolated by the exact `.applicationTag` service namespace;
use a distinct tag for each independent application or environment. `clear()`
throws if storage deletion fails and publishes `.empty` only after confirmed
deletion. Handle that error rather than telling the user logout succeeded.

### OAuth initialized with custom URLSession
A custom `.urlSession` can install `URLProtocol` handlers for application-specific
transport behavior and testing. OAuth endpoint URLs must still use HTTPS;
custom protocols do not opt out of that policy. Token and device endpoint
redirects are refused so credentials cannot be replayed to another destination.

```swift
// Custom URLSession
let configuration: URLSessionConfiguration = .ephemeral
configuration.protocolClasses = [CustomURLProtocol.self]
let urlSession: URLSession = .init(configuration: configuration)

let options: [OAuth.Option: Any] = [.urlSession: urlSession]
let oauth: OAuth = .init(.main, options: options)
```

### OAuth initialized with Keychain protection and browser-session privacy
Set `.requireBiometricAuthentication: true` to protect each stored token with
Keychain `.biometryCurrentSet` access control. The OS enforces authentication on
every protected read, including restoration and refresh; cancelling or denying
authentication fails closed. This policy requires enrolled biometrics, does not
allow a passcode or companion-device substitute, and invalidates protected items
when biometric enrollment changes. Pass `.localAuthentication` to supply an
`LAContext`. Existing unprotected items are rejected in biometric mode rather
than silently treated as protected. Native macOS uses the Data Protection
Keychain; the host needs the appropriate signing, entitlements, and user context.
Each client has independent authentication settings. A client without the
biometric option cannot silently restore protected items or downgrade their
protection on replacement. Such reads fail without displaying an authentication
prompt; enable the option explicitly to authenticate.

OAuthKit uses an ephemeral system browser session by default. To explicitly retain account cookies across sessions, set `.persistBrowserSession: true`. Credential-entry authorization always uses the platform's trusted external user agent; OAuthKit does not embed an authorization web view.
### Authorization-server mix-up protection
Set `issuer` to the authorization server's exact RFC 9207 issuer string when the server returns `iss` in authorization responses. The configured value must be an HTTPS issuer without query or fragment. OAuthKit binds the provider and token endpoint to the pending transaction, requires the callback issuer, and compares it exactly. When the issuer parameter is unavailable, authorization servers configured together must use distinct redirect URIs.

#### Arrange / Act / Assert: issuer and redirect binding
**Arrange:** Configure two authorization servers with distinct issuers and redirect URIs (or, when `iss` is unavailable, distinct redirects), and begin an authorization for one server.

**Act:** Deliver callbacks with the valid state but a missing, wrong-case, wrong-value, duplicate `iss`, lookalike redirect URI, altered static redirect query, duplicate static query item, duplicate state, or duplicate code; then deliver one exact callback with the correct issuer and redirect.

**Assert:** Every mismatch is rejected without exchanging or consuming the transaction. The exact callback is accepted and exchanges only against the token endpoint frozen for its provider; a replay is rejected.


```swift
// Custom LAContext
let localAuthentication: LAContext = .init()
localAuthentication.localizedReason = "read tokens from keychain"

let options: [OAuth.Option: Any] = [
    .localAuthentication: localAuthentication,
    .requireBiometricAuthentication: true,
    .persistBrowserSession: true
]
let oauth: OAuth = .init(.main, options: options)
```

## OAuthKit Authorization Flows
OAuth 2.0 authorization flows are started by calling the [oauth.authorize(provider:grantType:)](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/oauth#Starting-an-authorization-flow) method.

A good resource to help understand the detailed steps involved in OAuth 2.0 authorization flows can be found on the [OAuth 2.0 Playground](https://www.oauth.com/playground/index.html).

```swift
oauth.authorize(provider: provider, grantType: grantType)
``` 

Token and device authorization requests use UTF-8
`application/x-www-form-urlencoded` bodies. Names and values are encoded
individually: spaces become `+`, while literal plus signs, ampersands, percent
signs, and Unicode bytes are escaped. This preserves provider-issued codes and
credentials without letting their contents become additional form parameters.


### OAuth 2.0 Authorization Code with PKCE
Every interactive authorization uses S256 PKCE with fresh, internal state and verifier values; callers cannot supply predictable state or disable PKCE.

```swift
oauth.authorize(provider: provider)
```

### OAuth 2.0 Device Code Flow
OAuthKit supports the [OAuth 2.0 Device Code Flow Grant](https://alexbilbie.github.io/2016/04/oauth-2-device-flow-grant/), which is used by apps that don't have access to a web browser (like tvOS or watchOS). To leverage OAuthKit in tvOS or watchOS apps, simply add the `deviceCodeURL` to your [OAuth.Provider](https://github.com/codefiesta/OAuthKit/blob/main/Sources/OAuthKit/OAuth+Provider.swift).

```swift
let grantType: OAuth.GrantType = .deviceCode
oauth.authorize(provider: provider, grantType: grantType)
```

![tvOS-screenshot](https://github.com/user-attachments/assets/14997164-f86a-4ee0-b6b7-8c0d9732c83e)

### OAuth 2.0 Client Credentials Flow

The OAuth 2.0 Client Credentials flow is a mechanism where a client application authenticates itself to an authorization server using its own credentials rather than a user's credentials. This flow is primarily used in server-to-server communication, where a service or application needs to access a protected resource without involving a user.

This grant is disabled for public clients. Use a trusted backend for confidential
grants, and explicitly configure `clientType: .confidential` only where the
deployment can keep its secret private. Confidential clients default to
`clientAuthentication: .clientSecretBasic`; `.clientSecretPost` is an explicit
alternative for servers requiring body authentication. Public clients default
to `.public` and `.none`, even if a legacy configuration contains a secret.

```swift
let grantType: OAuth.GrantType = .clientCredentials
oauth.authorize(provider: provider, grantType: grantType)
```

## OAuth 2.0 Provider Diagnostics
Provider debugging is disabled by default. When enabled, diagnostics contain only response status and provider ID; raw responses, callback URLs, codes, state, device credentials, tokens, and secrets are never logged.

### Arrange / Act / Assert: captured-log credential safety
The `whenCapturingOAuthDiagnostics` test in `Tests/OAuthKitTests/OAuthTests.swift` arranges sentinel authorization, callback, device, access-token, and refresh-token values and installs a captured diagnostic sink. It exercises token, refresh, device-code, client-credentials, polling, and a mismatched callback, then asserts that captured output contains only status/provider metadata and none of the sentinels or token JSON field names.

## OAuthKit Sample Application
You can find a sample application integrated with OAuthKit [here](https://github.com/codefiesta/OAuthSample).

## Security Best Practices
1. Use the [PKCE](https://github.com/codefiesta/OAuthKit?tab=readme-ov-file#oauth-20-pkce-flow) workflow if possible in your public applications.
2. Client IDs are public identifiers. Client secrets must remain on a trusted backend, not in native binaries, bundles, generated Swift code, or source control.
3. Public/native clients must use public registration and cannot use static-secret authentication or the Client Credentials grant.
4. Configure confidential clients explicitly and choose exactly one token-endpoint authentication strategy. Basic authentication form-encodes the client ID and secret before Base64 encoding; opt into body authentication only when required by the server.
5. Authorization, token, device, and protected-resource URLs must use HTTPS. The bearer helper refuses insecure destinations.
6. Native redirects may use HTTPS, literal loopback HTTP (`127.0.0.1` or `[::1]`), or a reverse-domain custom scheme such as `com.example.oauthkit:/callback`. Register the exact redirect with the authorization server; HTTP provider endpoints are never a redirect exception.


## OAuth 2.0 Providers
OAuthKit should work with any standard OAuth2 provider. Below is a list of tested providers along with their OAuth2 documentation links. If you’re interested in seeing support or examples for a provider not listed here, please open an issue on our [here](https://github.com/codefiesta/OAuthKit/issues).

Token, refresh, and device grant credentials are never sent in URL queries.
Refresh uses the configured `accessTokenURL`, not `authorizationURL`.
The `encodeHttpBody` compatibility mode has been removed; providers must accept
form-encoded bodies rather than require credential-bearing URLs.

* [Auth0 / Okta](https://developer.okta.com/signup/)
* [Box](https://developer.box.com/guides/authentication/oauth2/)
* [Dropbox](https://developers.dropbox.com/oauth-guide)
* [Github](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
* [Google](https://developers.google.com/identity/protocols/oauth2)
* [LinkedIn](https://developer.linkedin.com/)
	* LinkedIn currently doesn't support **PKCE**.
* [Instagram](https://developers.facebook.com/docs/instagram-basic-display-api/guides/getting-access-tokens-and-permissions)
* [Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
* [Slack](https://api.slack.com/authentication/oauth-v2)
    * **Important**: Slack will block unknown browsers from initiating OAuth workflows. See sample [oauth.json](https://github.com/codefiesta/OAuthKit/blob/main/Tests/OAuthKitTests/Resources/oauth.json) for setting the `customUserAgent` as a workaround.
* [Stripe](https://docs.stripe.com/stripe-apps/api-authentication/oauth)
* [Twitter](https://developer.x.com/en/docs/authentication/oauth-2-0)
	* **Unsupported**: Although OAuthKit *should* work with Twitter/X OAuth2 APIs without any modification, **@codefiesta** has chosen not to support any [Elon Musk](https://www.natesilver.net/p/elon-musk-polls-popularity-nate-silver-bulletin) backed ventures due to his facist, racist, and divisive behavior that epitomizes out-of-touch wealth and greed. **@codefiesta** will not raise objections to other developers who wish to contribute to OAuthKit in order to support Twitter OAuth2.

## OAuthKit Documentation

You can find the complete Swift DocC documentation for the [OAuthKit Framework here](https://codefiesta.github.io/OAuthKit/documentation/oauthkit/).


## Linux / Android Support

As of version [2.2.0](https://github.com/codefiesta/OAuthKit/releases/tag/2.2.0) OAuthKit will now compile for both [Android and Linux](https://www.swift.org/documentation/articles/swift-sdk-for-android-getting-started.html). However, secure storage still needs to be implemented for both [Android](https://github.com/codefiesta/OAuthKit/issues/153) and [Linux](https://github.com/codefiesta/OAuthKit/issues/152).

