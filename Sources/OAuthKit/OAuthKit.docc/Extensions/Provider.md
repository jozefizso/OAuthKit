# ``OAuthKit/OAuth/Provider``
@Metadata {
    @Available(iOS, introduced: "18.0")
    @Available(macOS, introduced: "15.0")
    @Available(tvOS, introduced: "18.0")
    @Available(visionOS, introduced: "2.0")
    @Available(watchOS, introduced: "11.0")
}

## Overview
The Provider holds the configuration data that is used for communicating with an OAuth 2.0 server. The easiest way to configure OAuthKit is to simply drop an `oauth.json` file into your main bundle and it will get automatically loaded into your swift application and available as an ``SwiftUICore/EnvironmentValues/oauth`` property wrapper. You can find an example `oauth.json` file [here](https://github.com/codefiesta/OAuthKit/blob/main/Tests/OAuthKitTests/Resources/oauth.json). 
```json
[
    {
        "id": "GitHub",
        "authorizationURL": "https://github.com/login/oauth/authorize",
        "accessTokenURL": "https://github.com/login/oauth/access_token",
        "deviceCodeURL": "https://github.com/login/device/code",
        "clientID": "CLIENT_ID",
        "clientType": "public",
        "clientAuthentication": "none",
        "redirectURI": "com.example.oauthkit:/callback",
        "scope": [
            "user",
            "repo",
            "openid"
        ],
        "debug": true
    }
]
```

Public native applications should be configured as `public` clients and must not embed a client secret. Confidential clients and Client Credentials grants belong on a trusted backend. Confidential token requests use `clientSecretBasic` by default; deployments that require a body secret can explicitly choose `clientSecretPost`.

Authorization, token, device, and protected-resource endpoints must use HTTPS. Redirect URIs may use HTTPS, literal loopback HTTP, or a reverse-domain custom scheme.

> Warning: Do not include confidential client secrets in a publicly distributed application. Compiling a secret into a binary does not make the client confidential; keep confidential credentials on a trusted backend.
