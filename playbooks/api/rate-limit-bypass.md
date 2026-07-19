---
technique: "Rate-Limit Bypass"
family: "auth-session"
severity_hint: "medium"
tags: ["Rate-Limit", "HTTP"]
source: "_raw/Web attacks/Web Attacks/Rate-Limit Bypass.md"
source_sha256: "9c9d3534abe9eda4a40709a79dcc33698a161d655ca435c788bd511a9e8a91c8"
curator_version: 2
review_status: imported-unreviewed
---

# Rate-Limit Bypass

> Family: **auth-session** · Severity hint: **medium** · Tags: Rate-Limit, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `haskell: X-Forwarded: 127.0.0.1`

## Playbook (operator notes)

# Rate-Limit Bypass

# Rate Limit Bypass Techniques

- Rate Limit Bypass using Header
    - Try changing the user-agent, cookies etc.
    - Try using Headers like:
        
        ```haskell
        X-Forwarded: 127.0.0.1
        X-Forwarded-By: 127.0.0.1
        X-Forwarded-For: 127.0.0.1
        X-Forwarded-For-Original: 127.0.0.1
        X-Forwarder-For: 127.0.0.1
        X-Forward-For: 127.0.0.1
        Forwarded-For: 127.0.0.1
        Forwarded-For-Ip: 127.0.0.1
        X-Custom-IP-Authorization: 127.0.0.1
        X-Originating-IP: 127.0.0.1
        X-Remote-IP: 127.0.0.1
        X-Remote-Addr: 127.0.0.1
        
        -- Double X-Forwarded-For header example --
        X-Forwarded-For:
        X-Forwarded-For: 127.0.0.1
        ```
        
- Rate Limit Bypass using Special Characters
    - Adding `%00` at the end of the Email can sometimes Bypass Rate Limit
    - Try adding a Space Character after a Email (Not Encoded)
    - Some Common Characters that help bypassing Rate Limit :
        - `%0d , %2e , %09 , %20 , %0, %00, %0d%0a, %0a, %0C`
    - Adding a `/` at the end of API endpoint can also Bypass Rate Limits
        - `domain.com/v1/login` -> `domain.com/v1/login/`
- Leveraging API Gateway Behavior
    
    Some API gateways are configured to apply rate limiting based on the combination of endpoint and parameters. By varying the parameter values or adding non-significant parameters to the request, it's possible to circumvent the gateway's rate-limiting logic, making each request appear unique. For exmple `/resetpwd?someparam=1`.
    
- Logging into Your Account Before Each Attempt
    
    Logging into an account before each attempt, or every set of attempts, might reset the rate limit counter. This is especially useful when testing login functionalities. Utilizing a Pitchfork attack in tools like Burp Suite, to rotate credentials every few attempts and ensuring follow redirects are marked, can effectively restart rate limit counters.
    
- Play with requests
    - Change the request body from its current type e.g JSON ↔  XML
    - Change request methods PUT ↔ POST ↔ GET

---

[Rate Limit Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)

[Rate-Limit Bypass](https://kathan19.gitbook.io/howtohunt/rate-limit/ratelimitbypass)

## HackTricks methodology enrichment

Rate-limit checks can affect availability and user lockout state. Establish an
approved test account, maximum attempt count, cooldown, and stop condition before
testing. Prefer a harmless endpoint or invalid OTP/password that cannot mutate a
real account.

### Identify the counter key

1. Establish a baseline until the first throttle response, recording status,
   body, headers, latency, and the time at which access resumes.
2. Change one identity dimension at a time: account, session, API token, source
   address as seen by the trusted proxy, device identifier, and tenant.
3. Treat client-supplied forwarding headers as candidates only when the edge
   actually trusts them. Do not spray a long header list blindly; compare the
   effective client identity in logs or responses when that evidence is
   available.
4. Verify whether successful login, logout/login, or token refresh unexpectedly
   resets a security-sensitive counter.

### Find inconsistent enforcement paths

- Compare versioned and unversioned routes, trailing-slash and case variants,
  alternate methods/content types, and equivalent mobile or legacy endpoints.
- Compare single-item requests with REST bulk endpoints, GraphQL aliases/array
  batches, WebSocket messages, and gRPC streams. Start with two logical actions;
  do not use transport multiplexing to exceed the approved request budget.
- If a CDN or API gateway is present, compare only operator-approved points of
  presence or hostnames. A different counter shard is meaningful only if it
  permits additional security-sensitive actions for the same principal.

### Characterize the window

Measure fixed, sliding, token-bucket, and concurrency behavior with a small,
repeatable sequence around the observed boundary. Distinguish a true bypass from
normal refill, queued requests, retries, cached responses, or per-endpoint policy.
For every claimed bypass, replay the control and variant in alternating order and
show the extra accepted action plus the identity dimension that changed.

HackTricks source: [Rate Limit Bypass](https://hacktricks.wiki/en/pentesting-web/rate-limit-bypass.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/pentesting-web/rate-limit-bypass.md)).

## Source
Original note: `_raw/Web attacks/Web Attacks/Rate-Limit Bypass.md`
