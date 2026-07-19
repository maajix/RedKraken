---
technique: "oAuth2"
family: "auth-session"
severity_hint: "high"
tags: ["Authentication", "XSS", "Request Smuggling", "CSRF", "Open Redirect", "Account Takeover", "Auth"]
source: "_raw/Web attacks/Web Attacks/oAuth2.md"
source_sha256: "938f9e35e8c687467d81a6ba342c2ed64e1b86f30da8ad0b35d94f1de6a109aa"
curator_version: 2
review_status: imported-unreviewed
---

# oAuth2

> Family: **auth-session** · Severity hint: **high** · Tags: Authentication, XSS, Request Smuggling, CSRF, Open Redirect, Account Takeover, Auth
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `haskell: GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_t`
- `haskell: GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1`
- `haskell: POST /token HTTP/1.1`
- `json: {`
- `haskell: GET /userinfo HTTP/1.1`
- `haskell: GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_t`
- `haskell: GET /callback#access_token=<REDACTED_TEST_ACCESS_TOKEN>&token_type=Bearer&expires_in=5000&scope=openid%20p`
- `haskell: GET /userinfo HTTP/1.1`
- `python: scope=contacts`
- `GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_t`
- `Attack Execution`
- `haskell: https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback`
- `python: <scheme>://<host>:<port>[<path>|<pathPrefix>|<pathPattern>|<pathAdvancedPattern>|<pathSuff`
- `xml: <activity android:exported="true" android:name="PACKAGE_NAME.CLASS_NAME">`
- `xml: <intent-filter android:autoVerify="true">`

## Playbook (operator notes)

# oAuth2

[OAuth 2.0 authentication vulnerabilities | Web Security Academy](https://portswigger.net/web-security/oauth)

[Egor Homakov](https://homakov.blogspot.com/search?q=oauth)

# Overview

- Details

    **Client application** - The website or web application that wants to access the user's data.

    - **Resource owner** - The user whose data the client application wants to access.
    - **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

    There are numerous different ways that the actual OAuth process can be implemented. These are known as OAuth "flows" or "grant types”. Broadly speaking, both grant types involve the following stages:

    1. The client application requests access to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
    2. The user is prompted to log in to the OAuth service and explicitly give their consent for the requested access.
    3. The client application receives a unique access token that proves they have permission from the user to access the requested data. Exactly how this happens varies significantly depending on the grant type.
    4. The client application uses this access token to make API calls fetching the relevant data from the resource server.

# Grant Types Introduction

- **Authorization code grant type**
    - This grant type is quite secure

    ```haskell
    GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
    Host: oauth-authorization-server.com
    ```

    ```haskell
    GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
    Host: client-app.com
    ```

    ```haskell
    POST /token HTTP/1.1
    Host: oauth-authorization-server.com … client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
    ```

    ```json
    {
      "access_token": "<REDACTED_TEST_ACCESS_TOKEN>",
      "token_type": "Bearer",
      "expires_in": 3600, "scope":
      "openid profile",
      …
    }
    ```

    ```haskell
    GET /userinfo HTTP/1.1
    Host: oauth-resource-server.com
    Authorization: Bearer <REDACTED_TEST_ACCESS_TOKEN>
    ```



- **Implicit grant type**
    - Way simpler but not as secure

    ```haskell
    GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
    ```

    ```haskell
    GET /callback#access_token=<REDACTED_TEST_ACCESS_TOKEN>&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=<REDACTED_TEST_STATE> HTTP/1.1
    Host: client-app.com
    ```

    ```haskell
    GET /userinfo HTTP/1.1
    Host: oauth-resource-server.com
    Authorization: Bearer <REDACTED_TEST_ACCESS_TOKEN>
    ```




# Scopes

- Details

    For any OAuth grant type, the client application has to specify which data it wants to access and what kind of operations it wants to perform. It does this using the `scope` parameter of the authorization request it sends to the OAuth service. **As the name of the scope is just an arbitrary text string, the format can vary dramatically between providers. Some even use a full URI as the scope name, similar to a REST API endpoint.**

    ```python
    scope=contacts
    scope=contacts.read
    scope=contact-list-r
    scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly
    ```

    When OAuth is used for authentication, however, the standardized OpenID Connect scopes are often used instead. For example, the scope `openid profile` will grant the client application read access to a predefined set of basic information about the user, such as their email address, username, and so on.


# Parameters

The client application sends a request to the OAuth service's `/authorization` endpoint asking for permission to access specific user data. Note that the endpoint mapping may vary between providers. However, you should always be able to identify the endpoint based on the parameters used in the request.

```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

- Details
    - `client_id` Mandatory parameter containing the unique identifier of the client application. This value is generated when the client application registers with the OAuth service.
    - `redirect_uri` The URI to which the user's browser should be redirected when sending the authorization code to the client application. This is also known as the "callback URI" or "callback endpoint". Many OAuth attacks are based on exploiting flaws in the validation of this parameter.
    - `response_type` Determines which kind of response the client application is expecting and, therefore, which flow it wants to initiate. For the authorization code grant type, the value should be `code`.
    - `scope` Used to specify which subset of the user's data the client application wants to access. Note that these may be custom scopes set by the OAuth provider or standardized scopes defined by the OpenID Connect specification. We'll cover [OpenID Connect](https://portswigger.net/web-security/oauth/openid) in more detail later.
    - `state` Stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of [CSRF](https://portswigger.net/web-security/csrf) token for the client application by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow.

# Recon

To identify vulnerabilities in OAuth service, study HTTP interactions, identify the provider from the hostname, and review available documentation for endpoint names and configuration options. Send a `GET` request to standard endpoints like `/.well-known/oauth-authorization-server` `/.well-known/openid-configuration` and `/.well-known/openid-configuration` to obtain a JSON configuration file with key information about additional features and potential attack surfaces.

# Attacks

*If it is type code, try to set it to token, because code is way more secure. Try bruteforcing parameters to Token,facebookToken,Ftoken…access_token and see if an application accepts other types*

### Example

Application expects a code by default which is then exchanged for an ID token, however, it also directly accepts a ID token via `access_token`

- **Mutable Claims Attack**

    According to the OAuth specification, users are uniquely identified by the `sub` field. However there is no standard format of this field. As a result, many different formats are used, depending on the Authorization Server. Some of the Client applications, in an effort to craft a uniform way of identifying users across multiple Authorization Servers, fall back to user handles, or emails. However this approach may be dangerous, depending on the Authorization Server used. Some of the Authorization Servers do not guarantee immutability for such user properties. Even worse so, in some cases these properties can be arbitrarily changed by the users themselves. In such cases account takeovers might be possible.

    One of such cases emerges, when the feature “Login with Microsoft” is implemented to use the `email` field to identify users.. In such cases, an attacker might create their own AD organization (`doyensectestorg` in this case) on Azure, which can be used then to to perform “Login with Microsoft”. While the `Object ID` field, which is placed in `sub`, is immutable for a given user and cannot be spoofed, the `email` field is purely user-controlled and does not require any verification.



    In the screenshot above, there’s an example user created, that could be used to take over an account `victim@gmail.com` in the Client, which uses the `email` field for user identification.

- **Improper implementation of the implicit grant type**

    The OAuth implicit grant type, recommended for single-page applications, sends the access token via the user's browser as a URL fragment. However, this method can introduce vulnerabilities if the client application doesn't properly verify the access token against other request data. If unchecked, an attacker can manipulate the parameters sent to the server to impersonate any user.

- **Flawed CSRF protection**

    The `state` parameter in OAuth flows, while optional, is strongly recommended due to its role in preventing CSRF attacks. If not used, attackers can potentially initiate an OAuth flow and trick a user's browser into completing it, leading to severe consequences such as account hijacking. Even in cases where login is exclusively via OAuth, the absence of a `state` parameter can still enable login CSRF attacks.

    ```
    Attack Execution
    1. Obtain an authorization code for our own account via the flow
    2. Craft the full URL e.g http://example.com/callback?code=<code>
    3. Drop the request and send the link to the victim
    ```

- **Cross-Site Scripting (XSS)**
    - Reflected parameter in the response can cause XSS
    - E.g if the state parameter is reflected for example in an input tag we can do something like this `state=213as423"><img/src/onerror=alert()>`
- **Flawed redirect_uri validation**

    [OAuth Account Takeover - Account Takeover on Booking.com](https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com)

    When auditing an OAuth flow, it's crucial to experiment with the `redirect_uri` parameter to understand its validation. Techniques include manipulating subdirectories, exploiting discrepancies in URI parsing, and testing for server-side parameter pollution vulnerabilities. Special attention should be given to [`localhost`](http://localhost) (`localhost.evil-user.net`) URIs, which may be permitted in production environments. Testing shouldn't be limited to the `redirect_uri` parameter alone; altering other parameters like `response_mode` can affect the validation of others and potentially allow bypassing of restrictions.

    ```haskell
    https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
    ```

    - `redirect_uri` can be used to steal the victims OAuth token via an open redirect
        - Example
            - OAuth callback is at [`http://academy.htb/callback`](http://academy.htb/callback)
            - Open redirect at [`http://academy.htb/redirect`](http://academy.htb/redirect)
            - Auth server validates the `redirect_uri` via whitelist against [`http://academy.htb/`](http://academy.htb/)
            - We can now exploit this example by using the `redirect_uri` `http://academy.htb/redirect?u=http://attacker.htb/callback`
- **Redirect Scheme Hijacking mobile applications (interesting since less hunted)**

    https://blog.ostorlab.co/one-scheme-to-rule-them-all.html

    When the need to use OAuth on mobile arises, the mobile application takes the role of OAuth User Agents. In order for them to be able to receive the redirect with Authorization Code developers often rely on the mechanism of custom schemes. However, multiple applications can register given scheme on a given device. This breaks OAuth’s assumption that the Client is the only one to control the configured `redirect_uri` and may lead to Authorization Code takeover in case a malicious app is installed in victim’s devices.

    Android Intent URIs have the following structure:

    ```python
    <scheme>://<host>:<port>[<path>|<pathPrefix>|<pathPattern>|<pathAdvancedPattern>|<pathSuffix>]
    ```

    So for instance the following URI `com.example.app://oauth` depicts an Intent with `scheme=com.example.app` and `host=oauth`. In order to receive these Intents an Android application would need to export an Activity similar to the following:

    ```xml
    <activity android:exported="true" android:name="PACKAGE_NAME.CLASS_NAME">
        <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:host="oauthredirect" android:scheme="oauthscheme"/>
        </intent-filter>
    </activity>
    ```

    Android system is pretty lenient when it comes to defining Intent Filters. The less filter details, the wider net and more potential URIs caught. So for instance if only `scheme` is provided, all Intents for this scheme will be caught, regardless of there `host`, `path`, etc.

    If there are more than one applications that can potentially catch given Intent, they system will let the user decide which to use, which means a redirect takeover would require user interaction. However with the above knowledge it is possible to try and create bypasses, depending on how the legitimate application’s filter has been created. Paradoxically, the more specific original developers were, the easier it is to craft a bypass and take over the redirect without user interaction. In detail, [Ostorlab](https://ostorlab.co/) has created the following flowchart to quickly assess whether it is possible:



    should be specified like this to be secure:

    ```xml
    <intent-filter android:autoVerify="true">
      <action android:name="android.intent.action.VIEW" />
      <category android:name="android.intent.category.DEFAULT" />
      <category android:name="android.intent.category.BROWSABLE" />
      <data android:scheme="http" />
      <data android:scheme="https" />
      <data android:host="www.example.com" />
    </intent-filter>
    ```

    host needs to publish a `/.well-known/assetlinks.json`

- **Stealing codes and access tokens via a proxy page**

    When dealing with robust targets in OAuth, even if external domain submission as the `redirect_uri` fails, one can explore the client application's wider attack surface. This can be done by altering the `redirect_uri` to point to other pages on a whitelisted domain or using directory traversal tricks to access any path on the domain. Identifying other pages that can be set as the redirect URI can reveal additional vulnerabilities that can be exploited to leak the code or token. **Open redirects**, dangerous **JavaScript** **handling** **query** **parameters** **and** **URL** **fragments**, **XSS** vulnerabilities, and **HTML injection** vulnerabilities are some examples of potential security loopholes.

- **Flawed scope validation**

    In OAuth flows, users approve access based on the defined scope in the authorization request. However, attackers can sometimes "upgrade" an access token with extra permissions due to flawed validation by the OAuth service. This can occur in the authorization code flow, where an attacker can add an extra `scope` parameter to the code/token exchange request, or in the implicit flow, where an attacker can steal tokens and manually add a new `scope` parameter to a request. The OAuth service should validate the `scope` value against the one used when generating the token to prevent unauthorized access.

    If the Authorization Server accepts and implicitly trusts a `scope` parameter sent in the Access Token Request (Note this parameter is not specified in the RFC for the Access Token Request in the Authorization Code Flow), a malicious application could try to upgrade the scope of Authorization Codes retrieved from user callbacks by sending a higher privileged scope in the **Access Token Request.**

    Once the Access Token is generated, the Resource Server must verify the Access Token for every request. This verification depends on the Access Token format, the commonly used ones are the following:

    - **JWT Access Token**: With this kind of access token, the Resource Server only needs to check the JWT signature and then retrieve the data included in the JWT (`client_id`, `scope`, etc.)
    - **Random String Access Token**: Since this kind of token does not include any additional information in them, the Resource Server needs to retrieve the token information from the Authorization Server.



    Following the RFC guidelines, the `scope` parameter should not be sent in the [Access Token Request](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3) in the Authorization Code flow, although it can be specified in other flows such as the [Resource Owner Password Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).

    The Authorization Server should either ignore the `scope` parameter or verify it matches the previous `scope` provided in the Authorization Request.

- **Unverified user registration / Client Confusion Attack**

    https://www.descope.com/blog/post/noauth

    Attack via Google oAuth2 Playground

    When authenticating users via OAuth, the client application makes the implicit assumption that the information stored by the OAuth provider is correct. This can be a dangerous assumption to make. Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address. Client applications may then allow the attacker to sign in as the victim via this fraudulent account with the OAuth provider.

    # **Abusing a Malicious Client**

    - Authorization servers support OAuth client registration, enabling an attacker to create their own malicious OAuth client under their control
    - Client can be used to obtain access tokens from victims
    - Example
        - Attacker created `evil.htb` and registered an OAuth client with `hubgit.htb`
        - If a victim logs into `evil.htb` with their `hubgit.htb` account the attacker client receives the token
        - Attacker can then use this token to log into `academy.htb`
        - If `academy.htb` does not verify the token was issued for a different client, the attacker is able to impersonate the victim on `academy.htb`

    If steps 8 to 10 are not performed and the token’s Client ID is not validated, it would be possible to perform the following attack:






# Other attacks

---

## Dirty Dancing

[Account hijacking using "dirty dancing" in sign-in OAuth-flows - Labs Detectify](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/)

[Reddit disclosed on HackerOne: One-click account hijack for anyone...](https://hackerone.com/reports/1567186)

## nOAuth

[nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover](https://www.descope.com/blog/post/noauth)

---

[OAuth](https://kathan19.gitbook.io/howtohunt/oauth/oauth)

## Enrichment — OIDC dynamic registration, request_uri & scope upgrade (imported-unreviewed, from course notes)
> Added from personal PortSwigger notes; PII scrubbed. Untrusted until reviewed.

### Unprotected dynamic client registration (`/openid/register` → SSRF via `jwks_uri` / `logo_uri`)

OpenID Connect standardizes dynamic client registration: a client registers itself with a `POST` to a dedicated `/registration` (a.k.a. `/openid/register`) endpoint. Endpoint name is usually listed in `/.well-known/openid-configuration`. Some providers allow registration with **no authentication**, letting an attacker register a malicious client. Several body properties are URIs (`logo_uri`, `jwks_uri`, `userinfo_*` etc.); if the provider fetches any of them, this is a second-order **SSRF** vector.

```http
POST /openid/register HTTP/1.1
Content-Type: application/json Accept: application/json
Host: oauth-authorization-server.com
Authorization: Bearer <REDACTED_TEST_ACCESS_TOKEN>

{
	"application_type": "web",
	"redirect_uris": [ "https://client-app.com/callback", "https://client-app.com/callback2"
	],
	"client_name": "My Application",
	"logo_uri": "https://client-app.com/logo.png",
	"token_endpoint_auth_method": "client_secret_basic",
	"jwks_uri": "https://client-app.com/my_public_keys.jwks",
	"userinfo_encrypted_response_alg": "RSA1_5",
	"userinfo_encrypted_response_enc": "A128CBC-HS256",
	…
}
```

Test: drop `Authorization` header to check whether registration works unauthenticated, then point a URI property (e.g. `logo_uri`, `jwks_uri`) at an attacker-controlled or internal host and watch for the provider fetching it.

### Authorization requests by reference (`request_uri` → SSRF / bypass)

Some OpenID providers let you pass the authorization parameters as a JWT instead of the query string, by supplying a single `request_uri` parameter pointing to that JWT. Depending on config, `request_uri` is another **SSRF** vector — and can also **bypass validation**: some servers validate query-string params (incl. `redirect_uri`) but fail to apply the same validation to params carried inside the referenced JWT.

Check support via the `request_uri_parameter_supported` option in the config file / docs, or just try adding the parameter — some servers support it even when undocumented.

```
request_uri=https://attacker-controlled-or-internal-host/malicious.jwt
```

### Scope upgrade attack

In any flow the token should only grant the scope the user approved. Flawed validation may let an attacker "upgrade" a token (stolen or via a malicious client) with extra permissions.

**Authorization code flow** — attacker's malicious client first requests e.g. `openid email`; after user approval it receives an auth code. Attacker adds an extra `scope` to the code/token exchange (note: `scope` is NOT specified for the Access Token Request in RFC 6749 §4.1.3):

```http
POST /token
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8&scope=openid%20email%20profile
```

If the server does not validate against the original authorization scope, it issues an upgraded token:

```json
{
	"access_token": "<REDACTED_TEST_ACCESS_TOKEN>",
	"token_type": "Bearer",
	"expires_in": 3600,
	"scope": "openid email profile",
	…
}
```

Attacker then uses the client to call the resource server for the newly-granted `profile` data.

**Implicit flow** — access token is delivered via the browser, so an attacker can steal a token from an innocent client and use it directly. Send a normal browser request to `/userinfo`, manually adding a new `scope` parameter. If the service does not validate `scope` against the value used when the token was generated (and the adjusted permissions stay within what was previously granted to that client), the attacker accesses extra data without further user approval.

## Source
Original note: `_raw/Web attacks/Web Attacks/oAuth2.md`
