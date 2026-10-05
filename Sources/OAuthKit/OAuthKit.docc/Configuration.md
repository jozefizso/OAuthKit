# OAuthKit Configuration

Explore advanced OAuth configuration options such as Keychain protection and private browsing.

@Metadata {
    @PageKind(article)
    @PageImage(
        purpose: card, 
        source: "config-card", 
        alt: "OAuthKit Framework Configuration")
    @PageColor(purple)
    @Available(iOS, introduced: "18.0")
    @Available(macOS, introduced: "15.0")
    @Available(tvOS, introduced: "18.0")
    @Available(visionOS, introduced: "2.0")
    @Available(watchOS, introduced: "11.0")
}

## Overview

Both of the ``OAuth`` initializers ``OAuth/init(providers:options:)`` and ``OAuth/init(_:options:)`` accept a dictionary of `[OAuth.Option:Any]` which can be used to configure the loading and runtime options.

### Application Tag
The ``OAuth/Option/applicationTag`` option is used to create unique keys for access tokens that are stored inside the Keychain. Typically, an app would set this value to be the same as their Bundle identifier. 

```swift
let options: [OAuth.Option: Any] = [
    .applicationTag: "com.oauthkit.Sampler",
]
let oauth: OAuth = .init(.main, options: options)
```

### Auto Refresh
The ``OAuth/Option/autoRefresh`` option is used to determine if tokens should be auto refreshed when they expire or not. This value is true by default. 

```swift
let options: [OAuth.Option: Any] = [
    .autoRefresh: false,
]
let oauth: OAuth = .init(.main, options: options)
```

### URL Session
The ``OAuth/Option/urlSession`` option is used to pass in a custom URLSession that will be used by your ``OAuth`` object to support any custom protocols or URL schemes that your app supports.This allows developers to register any custom URLProtocol classes that can handle the loading of protocol-specific URL data.

```swift
// Custom URLSession
let configuration: URLSessionConfiguration = .ephemeral
configuration.protocolClasses = [CustomURLProtocol.self]
let urlSession: URLSession = .init(configuration: configuration)

let options: [OAuth.Option: Any] = [.urlSession: urlSession]
```

### System Browser Session
Interactive credential entry uses ``ASWebAuthenticationSession`` and never an embedded web view. Browser cookies are ephemeral by default; set ``OAuth/Option/persistBrowserSession`` to `true` only when the application explicitly requests persistence. Device-verification URLs are opened by the platform in the external user agent.

#### Arrange / Act / Assert: trusted browser and cancellation lifecycle
**Arrange:** Start an authorization for a provider with a registered callback URI while capturing the platform's authentication-session launch.

**Act:** Confirm the system authentication surface opens at the provider authorization URL, cancel it through the system UI, and separately dismiss the containing OAuth view while a session is active.

**Assert:** Credentials are entered only in the trusted system surface; cancellation and view dismissal cancel the session and discard pending state. The session requests ephemeral cookies by default and requests persistence only when ``OAuth/Option/persistBrowserSession`` is explicitly true.

### Keychain Protection
The ``OAuth/Option/requireBiometricAuthentication`` option protects each stored token item using the Keychain's biometric-current-set access-control policy. The system requires biometric authentication on each protected read, including token refreshes and reads by other OAuth instances; an initializer-only authentication check does not unlock items. Authentication cancellation, missing contexts, and unsupported biometrics fail closed. Existing items without OAuthKit's biometric-policy marker and access control are rejected while biometric protection is enabled. Items are bound to the currently enrolled biometric set and become unavailable if that set changes. Supply an ``OAuth/Option/localAuthentication`` context to control the system authentication prompt. On macOS, OAuthKit selects the data-protection Keychain for all operations; the host executable's entitlements and user-session context determine availability.

```swift
// Custom LAContext
let localAuthentication: LAContext = .init()
localAuthentication.localizedReason = "read tokens from keychain"
localAuthentication.touchIDAuthenticationAllowableReuseDuration = 10

let options: [OAuth.Option: Any] = [
    .localAuthentication: localAuthentication,
    .requireBiometricAuthentication: true
]
let oauth: OAuth = .init(.module, options: options)
```

> Important: The ``OAuth/Option/requireBiometricAuthentication`` option is available only on iOS, macOS, and visionOS. It requires enrolled biometrics; a password or companion device cannot satisfy the item policy.

> Tip: See ``OAuth/Option`` for a complete list of configuration options.

