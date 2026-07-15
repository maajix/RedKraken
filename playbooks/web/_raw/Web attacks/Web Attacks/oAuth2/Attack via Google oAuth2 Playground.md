# Attack via Google oAuth2 Playground

# Playground

[OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)

## Client Confusion Attack Explained

Client confusion attack is when we generate a token via the playground. This requires a malicious client application ran by the attacker, where the victim logged into so we can grep his ID token. This ID token can then may be used on the target application to log into the victim, since the valid ID token has its email address in it.

- A vulnerable application will check that:
    - The token is properly signed by the provider (Google)
    - The token contains a valid email
    - The email matches an existing user
- **But it fails to verify the `aud` (audience) claim, which specifies which client the token was issued for**

## Unverified User Registration

Here, we also create our own malicious oAuth application. However, in this case we do not have to have access to the victims email address. We will create the account itself in the oAuth provider — **`not possible in google and others since they verify email ownership, but when not verified it is possible`** . After we obtain tokens for this account using the malicious client and use those to get access in the target application.

With providers like Google:

- You cannot create a new Google account using someone else's email address (e.g., [victim@mail.com](mailto:victim@mail.com)) without verifying access to that email
- This means you cannot obtain tokens for [victim@mail.com](mailto:victim@mail.com) unless you either:
    - Actually control that email inbox to complete verification, or
    - Social engineer the victim to authenticate to your malicious OAuth client

With hypothetical providers that don't verify emails:

- You could potentially register an account claiming to be [victim@mail.com](mailto:victim@mail.com) without proving you control that inbox
- This would allow you to obtain tokens for that email without actually owning it

### Example Microsoft (fixed)

https://youtu.be/ceeA3FmKxtM

![image.png](Attack%20via%20Google%20oAuth2%20Playground/image.png)

# Steps

1. Select the scope and click authorize APIs

![image.png](Attack%20via%20Google%20oAuth2%20Playground/image%201.png)

1. “Give consent” this would be the victim logging into our malicious application

![image.png](Attack%20via%20Google%20oAuth2%20Playground/image%202.png)

1. Exchange the authcode for the ID token

![image.png](Attack%20via%20Google%20oAuth2%20Playground/image%203.png)

1. Use the generated JWT to login to the target application