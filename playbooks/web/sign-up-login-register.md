---
technique: "Sign Up (Login / Register)"
family: "auth-session"
severity_hint: "medium"
tags: ["DoS", "Account Takeover", "XSS", "User Enumeration", "SQL Injection", "JavaScript", "HTTP"]
source: "_raw/Web attacks/Web Attacks/Sign Up (Login Register).md"
curator_version: 2
review_status: imported-unreviewed
---

# Sign Up (Login / Register)

> Family: **auth-session** · Severity hint: **medium** · Tags: DoS, Account Takeover, XSS, User Enumeration, SQL Injection, JavaScript, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Overview

Signup/registration flows are a frequent source of business-logic and injection bugs — duplicate-account tricks, weak rate limiting, unverified email, and permissive password policies all show up here. This playbook covers exploiting the signup feature itself, and the weak password policy issue specifically.

## Exploiting the Signup Feature

- **Duplicate registration / overwrite existing users** — some applications allow registering with an email, username, or phone number that's already in use, with critical consequences depending on the attack.
    1. Create a first account with `abc@gmail.com` and a password.
    2. Log out and register another account with the same email and a different password.
    3. Vary the email to probe normalization bugs:
        1. Uppercase
        2. `+1@`
        3. Extra dots in the local part
        4. Special characters in the email name (`%00`, `%09`, `%20`)
        5. Trailing characters after the email: `test@test.com a`
        6. `victim@gmail.com@attacker.com`
        7. `victim@attacker.com@gmail.com`
    4. Finish the creation process and confirm it succeeds.
    5. Go back and log in with the original email and the new password — if it succeeds, the account was overwritten/hijacked.
- **DoS at the name/password field on the signup page** — sending a very long string (e.g. 100,000 characters) can cause a denial of service. Usually caused by a vulnerable string-hashing implementation: hashing a long string exhausts CPU and memory.
    1. Go to the signup form.
    2. Fill it in and enter a long string in the password field.
    3. Submit — a `500 Internal Server Error` indicates the app is vulnerable.
- **Cross-Site Scripting (XSS) in username/account name** — insert XSS payloads into fields like username, email, password, etc.

    Payload for the username field:
    ```html
    <svg/onload=print()>
    ```

    Payload for the email field:
    ```html
    "><svg/onload=print()>"@google.com
    ```
- **No rate limit at the signup page** — a rate-limiting algorithm should throttle a user session or IP based on cached session info. Without it, a malicious user can generate hundreds or thousands of fake accounts, filling the database and impacting the business.

    Test with Burp Intruder:
    1. Capture the signup request and send it to Intruder.
    2. Add different emails as the payload.
    3. Fire Intruder and check whether every request returns `200 OK`.
- **Insufficient email verification** — the app either doesn't verify the email or the verification mechanism is weak enough to bypass:
    1. Forced browsing (directly navigating to pages that should only be reachable after verifying the email).
    2. Response/status-code manipulation (e.g. replacing a `403` with a `200`).
    3. Email verification bypass after signup:
        1. Sign up as `attacker@mail.com`.
        2. You receive a confirmation email at `attacker@mail.com` — don't open the link yet.
        3. Check whether the app lets you navigate to account settings before confirming.
        4. On the settings page, check whether you can change the email.
        5. If allowed, change the email to `victim@mail.com`.
        6. Instead of opening the new confirmation link sent to `victim@mail.com`, go back to the `attacker@mail.com` inbox and open the previously received link.
        7. If the application ends up verifying `victim@mail.com` via the confirmation link that was actually sent to `attacker@mail.com`, that's an email-verification bypass.
    4. There are many more bypass variants — worth a search for the specific framework in use.
- **Path overwrite** — if the app exposes profiles at `/{username}`, try signing up with reserved filenames such as `index.php`, `signup.php`, `login.php`. E.g. registering username `index.php` can make the profile page occupy `target.tld/index.php`; registering `login.php` can take over the login page entirely.
- **Username enumeration** — check whether the app leaks (via error messages, timing, or status codes) whether a given username is already registered.
- **Password policy** — see the [Weak Password Policy](#weak-password-policy) section below.
- **SQL Injection** — signup/login fields are common SQLi entry points; see [SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection#insert-statement).

Further reading: [Sign Up Bugs](https://kathan19.gitbook.io/howtohunt/sign-up-functionality/hunting_for_bugs_in_signup_feature)

## Weak Password Policy

A weak password policy increases the probability of a successful brute-force or dictionary attack against user accounts. An attacker who determines a user's password can take over their account and potentially access sensitive data. Applications often only enforce password restrictions when creating an account — check all three surfaces: account creation, password reset, and password change from account settings.

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/Sign Up (Login Register).md`
- `_raw/Web attacks/Web Attacks/Sign Up (Login Register)/Weak Password Policy.md`
