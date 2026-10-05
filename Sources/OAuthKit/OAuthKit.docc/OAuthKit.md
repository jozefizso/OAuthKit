# ``OAuthKit``
@Metadata {
    @PageColor(purple)
    @Available(iOS, introduced: "18.0")
    @Available(macOS, introduced: "15.0")
    @Available(tvOS, introduced: "18.0")
    @Available(visionOS, introduced: "2.0")
    @Available(watchOS, introduced: "11.0")
}

A modern and observable framework for implementing OAuth 2.0 authorization flows.

## Overview

OAuthKit offers a robust, type-safe, and performant OAuth 2.0 implementation using the observer design pattern. This pattern allows applications to observe an ``OAuth`` object and be notified of ``OAuth/State`` changes. 

This has the advantage of avoiding direct coupling with an authorization flow, enabling highly flexible and fine-grained control when interacting with an ``OAuth/Provider``. It also allows updates across multiple observers.

OAuthKit provides OAuth resource authorization, not validated OpenID Connect
authentication. ``OAuth/Token/rawIDToken`` captures an optional opaque `id_token`.
Applications must independently validate the signature and all required OIDC
claims, including a transaction-bound nonce, before using it as authenticated
identity. An ``OAuth/State/authorized(_:_:)`` event is not an identity assertion.

### Articles

@Links(visualStyle: detailedGrid) {
    - <doc:GettingStarted>
    - <doc:Configuration>
}

### Sample code

@Links(visualStyle: detailedGrid) {
    - <doc:SampleCode>
}

### Tutorials

@Links(visualStyle: list) {
    - <doc:Contents>
}

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SampleCode>
- ``OAuth``
- ``OAuth/Provider``
- ``OAuth/GrantType``

### State Observability
- ``OAuth/State``
- ``OAuth/state``
