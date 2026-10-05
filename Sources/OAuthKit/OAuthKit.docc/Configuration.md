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

### Private Browsing
The ``OAuth/Option/useNonPersistentWebDataStore`` option allows developers to implement private browsing inside the ``OAWebView``. Setting this value to true forces the ``OAWebView`` to use a non-persistent data store, preventing data from being written to the file system.

```swift
let options: [OAuth.Option: Any] = [
    .useNonPersistentWebDataStore: true,
]
let oauth: OAuth = .init(.module, options: options)
```

### Keychain Protection
The ``OAuth/Option/requireBiometricAuthentication`` option protects each stored token item using the Keychain's biometric-current-set access-control policy. The system requires biometric authentication on each protected read, including token refreshes and reads by other OAuth instances; an initializer-only authentication check does not unlock items. Authentication cancellation, missing contexts, and unsupported biometrics fail closed. Existing items without Keychain access control are rejected while biometric protection is enabled. Items are bound to the currently enrolled biometric set and become unavailable if that set changes. Supply an ``OAuth/Option/localAuthentication`` context to control the system authentication prompt. On macOS, OAuthKit selects the data-protection Keychain for all operations; the host executable's entitlements and user-session context determine availability.

```swift
// Custom LAContext
let localAuthentication: LAContext = .init()
localAuthentication.localizedReason = "read tokens from keychain"
localAuthentication.localizedFallbackTitle = "Use password"
localAuthentication.touchIDAuthenticationAllowableReuseDuration = 10

let options: [OAuth.Option: Any] = [
    .localAuthentication: localAuthentication,
    .requireAuthenticationWithBiometricsOrCompanion: true
]
let oauth: OAuth = .init(.module, options: options)
```

> Important: The ``OAuth/Option/requireAuthenticationWithBiometricsOrCompanion`` is only available on iOS, macOS, and visionOS.

> Tip: See ``OAuth/Option`` for a complete list of configuration options.

