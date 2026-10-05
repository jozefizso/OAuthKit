# ``OAuthKit/OAuth``
@Metadata {
    @Available(iOS, introduced: "18.0")
    @Available(macOS, introduced: "15.0")
    @Available(tvOS, introduced: "18.0")
    @Available(visionOS, introduced: "2.0")
    @Available(watchOS, introduced: "11.0")
}

## Overview
You can create an observable OAuth object using the ``OAuth/init(_:options:)`` or ``OAuth/init(providers:options:)`` initializers, or
you can access a default OAuth object via SwiftUI ``SwiftUICore/EnvironmentValues`` via the following:

```swift
@Environment(\.oauth)
var oauth: OAuth
```

An OAuth object can also be highly customized when passed a dictionary  of  ``Option`` values into it's iniitializers.

An OAuth object can also be customized by passing a dictionary of ``Option`` values to its initializer. The system browser session uses ephemeral cookies by default; persistence is an explicit opt-in.

```swift
let options: [OAuth.Option: Any] = [
    .applicationTag: "com.bundle.identifier",
    .autoRefresh: true,
    .persistBrowserSession: true
]
let oauth: OAuth = .init(.module, options: options)
```

- SeeAlso:
[RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)


## Topics

### Creating an Observable OAuth

- ``init(_:options:)``
- ``init(providers:options:)``

### Starting an authorization flow

- ``authorize(provider:grantType:)``
- ``OAuth/GrantType``

### OAuth State Tracking

- ``state``
- ``providers``
