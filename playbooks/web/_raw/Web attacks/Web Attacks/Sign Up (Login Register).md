# Sign Up (Login / Register)

Status: Erledigt
Tags: DoS (../Tags/DoS%2027f2c37daa298038bf49ddd08fc8ea15.md), Account Takeover (ATO) (../Tags/Account%20Takeover%20(ATO)%2027f2c37daa2980f4abc6c479151370af.md), XSS (../Tags/XSS%2027f2c37daa29805dadb2ff82553491b9.md), User Enumeration (../Tags/User%20Enumeration%2027f2c37daa298077aa4eeff2c9977b5c.md), SQL Injection (../Tags/SQL%20Injection%2027f2c37daa2980d5948ce5a24dacd7e6.md), JavaScript (JS) (../Tags/JavaScript%20(JS)%2027f2c37daa29809aac00f50467f7187c.md)
Tags 2: HTTP

# Exploiting Signup Feature

- Duplicate registration / Overwrite existing users
    
    Duplicate registration is when an application allows us to register or sign up with the same email address, username or phone number. It can have critical consequences based on what kind of attack is performed.
    
    1. Create first account in application with email say [abc@gmail.com](mailto:abc@gmail.com) and password.
    2. Logout of the account and create another account with same email and different password.
    3. Check varying the email
        1. uppsercase
        2. +1@
        3. add some dot in the email
        4. special characters in the email name (%00, %09, %20)
        5. Put black characters after the email: `test@test.com a`
        6. victim@gmail.com@attacker.com
        7. victim@attacker.com@gmail.com
    4. Finish the creation process — and see that it succeeds
    5. Now go back and try to login with email and the new password. You are successfully logged in.
- DOS at Name/Password field in Signup Page
    
    By sending a very long string (100000 characters) it’s possible to cause a denial a service attack on the server. This may lead to the website becoming unavailable or unresponsive. Usually this problem is caused by a vulnerable string hashing implementation. When a long string is sent, the string hashing process will result in CPU and memory exhaustion.
    
    1. Go Sign up form.
    2. Fill the form and enter a long string in password
    3. Click on enter and you’ll get 500 Internal Server error if it is vulnerable.
- Cross-Site Scripting (XSS) in username, account name for registration
    
    Now, for testing Signup page for XSS we can simply insert XSS payoad in fields like: username, email, password,etc.
    
    Payload for Username field:
    
    ```html
    <svg/onload=print()>
    ```
    
    Payload for Email field:
    
    ```html
    "><svg/onload=print()>"@google.com
    ```
    
- No Rate Limit at Signup Page
    
    A **rate limiting** algorithm is used to check if the user session (or IP address) has to be **limited** based on the information in the session cache. Testing for Rate limit at Signup page is quite a good idea.
    
    The Impact can be explained very well. If there is no rate limiting on signup page a malicious users can generate hundreds and thousands of fake accounts that lead to fill the application DataBase with fake accounts, Which can impact the business in many ways.
    
    You can easily test for it with Burp Intruder
    
    1. Capture the signup request and send it to Intruder.
    2. Add different emails as payload .
    3. Fire up Intruder, And check whether it returns 200 OK.
- Insufficient Email Verification
    
    Insufficient Email Verification means the application doesn’t verify the email id or the verification mechanism is too weak to be bypassed. You can easily Bypass Email Verification with some of the following common methods like
    
    1. Forced Browsing (directly navigating to files which comes after verifying the email)
    2. Response or Status Code Manipulation (Replacing the bad response status like 403 to 200 can be useful)
    3. Email verification bypass after signup
        1. Sing up on the web application as [attacker@mail.com](mailto:attacker@mail.com)
        2. You will receive a confirmation email on [attacker@mail.com](mailto:attacker@mail.com), do not open that link now.
        3. The application may ask for confirming your email, check if it allows navigating to account settings page.
        4. On settings page check if you can change the email.
        5. If allowed, change the email to [victim@mail.com](mailto:victim@mail.com).
        6. Now you will be asked to confirm [victim@mail.com](mailto:victim@mail.com) by opening the confirmation link received on [victim@mail.com](mailto:victim@mail.com), instead of opening the new link go to [attacker@mail.com](mailto:attacker@mail.com) inbox and open the previous received link.
        7. If the application verifies [vitim@mail.com](mailto:vitim@mail.com) by using previous verification link received on attacker mail, then this is a email verification bypass.
    4. There are much more ways of bypassing **Tip**: Just google it.
    
- Path Overwrite
    
    If an application allows users to check their profile with direct path /{username} always try to signup with system reserved file names, such as index.php, signup.php, login.php, etc. In some cases what happens here is, when you signup with username: `index.php`, now upon visiting target.tld/index.php, your profile will comeup and occupy the index.php page of an application. Similarly, if an attacker is able to signup with username `login.php`, Imagine login page getting takeovered.
    
- Username Enumeration
    
    Check if you can figure out when a username has already been registered inside the application.
    
- Password Policy
    
    [Weak Password Policy](Sign%20Up%20(Login%20Register)/Weak%20Password%20Policy%20b3b6523690af4da1b076bf0297747a39.md)
    
- SQL Injection
    
    [SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection#insert-statement)
    

---

[Sign Up Bugs](https://kathan19.gitbook.io/howtohunt/sign-up-functionality/hunting_for_bugs_in_signup_feature)