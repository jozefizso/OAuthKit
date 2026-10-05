# ``OAuthKit/OAWebView``
@Metadata {
    @Available(iOS, introduced: "18.0")
    @Available(macOS, introduced: "15.0")
    @Available(visionOS, introduced: "2.0")
}

`OAWebView` presents interactive authorization with the platform's trusted `ASWebAuthenticationSession`. Credentials are never entered in an embedded web view; the system surface displays the authorization-server origin. Browser cookies are ephemeral by default unless ``OAuth/Option/persistBrowserSession`` is enabled.
