# Web Playbook Catalog — signal → technique → playbook

Routing table for triage and hunters. Families with a dedicated hunting skill are marked ✅; others are reference playbooks the recon-agent / hunters consult opportunistically.

**98 playbooks across 11 families.**

## access-control  (✅ skill)  — 1 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| IDOR | high | `idor.md` | Authentication, HTTP, Auth |

## agentic-ai  (✅ skill)  — 1 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| LLM | medium | `llm.md` | LLM, SSRF, XSS, Account Takeover |

## auth-session  (✅ skill)  — 10 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| AWS Cognito | medium | `cloud-aws-cognito.md` |  |
| Attack via Google oAuth2 Playground | high | `oauth2-attack-via-google-oauth2-playground.md` |  |
| JWT | high | `jwt.md` | Session Tokens, Account Takeover, XSS, JavaScript, Auth |
| Password Reset | medium | `http-attacks-password-reset.md` |  |
| Rate-Limit Bypass | medium | `rate-limit-bypass.md` | Rate-Limit, HTTP |
| SAML | high | `saml.md` | Authentication, SAML, API, Account Takeover, XXE |
| Sign Up (Login / Register) | medium | `sign-up-login-register.md` | DoS, Account Takeover, XSS, User Enumeration, SQL Injection, JavaScript, HTTP |
| Type Juggling | high | `type-juggling.md` | PHP, Account Takeover, Authentication, HTTP, Session Tokens |
| UUIDs | low | `uuids.md` |  |
| oAuth2 | high | `oauth2.md` | Authentication, XSS, Request Smuggling, CSRF, Open Redirect |

## client-side  (✅ skill)  — 13 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Broken-Link Hijacking | low | `broken-link-hijacking.md` | HTML |
| CORS | medium | `cors.md` | CORS, Account Takeover, CSRF, XSS, Cache Poisoning |
| CSRF | medium | `csrf.md` | CSRF, HTTP, Account Takeover, HTML |
| Clientside PP | medium | `prototype-pollution-clientside-pp.md` |  |
| DOM Vulnerabilities | medium | `dom-vulnerabilities.md` | DOM, JavaScript, XSS, Open Redirect, SQL Injection |
| Dangling Markup | medium | `dangling-markup.md` | HTML, XSS, Content Security Policy, Account Takeover, Session Tokens |
| Open Redirection | medium | `open-redirection.md` | XSS, Deserialization, Open Redirect, JavaScript, HTTP |
| Prototype Pollution | critical | `prototype-pollution.md` | JavaScript, Account Takeover, XSS, 403, Remote Code Execution, HTTP, JS |
| Tabnabbing | low | `tabnabbing.md` | HTML |
| WebSocket Attacks | medium | `websocket-attacks.md` | Web Sockets, HTTP, XSS, SQL Injection, Account Takeover |
| XSS | medium | `xss.md` | JavaScript, HTML, XSS, CSRF, Content Security Policy |
| XSSI | medium | `cors-xssi.md` |  |
| paramspider | medium | `xss-paramspider.md` |  |

## deserialization  (✅ skill)  — 1 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Deserialization Attacks | critical | `deserialization-attacks.md` | Deserialization, PHP, Python, Remote Code Execution, Account Takeover, Session Tokens, HTTP, Authentication, File Upload |

## http-protocol  (✅ skill)  — 23 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Bleichenbacher & DROWN | low | `http-attacks-tls-attacks-bleichenbacher-and-drown.md` |  |
| CRIME & BREACH | low | `http-attacks-tls-attacks-crime-and-breach.md` |  |
| CRLF Injection & Response splitting | medium | `http-attacks-crlf-injection-and-response-splitting.md` |  |
| Cache Poisoning | medium | `cache-poisoning.md` | Cache Poisoning, 403, XSS, DoS, JavaScript |
| Compression | low | `http-attacks-tls-attacks-compression.md` |  |
| Cryptographic Atks | low | `http-attacks-tls-attacks-cryptographic-atks.md` |  |
| Downgrade Attacks | low | `http-attacks-tls-attacks-downgrade-attacks.md` |  |
| HTTP Attacks | medium | `http-attacks.md` | HTTP, Request Smuggling, Password Reset, CRLF, Host-Header |
| HTTP/2 Downgrading | medium | `http-attacks-http-2-downgrading.md` |  |
| Host-Header | medium | `http-attacks-host-header.md` |  |
| PKI | low | `http-attacks-tls-attacks-pki.md` |  |
| POODLE & BEAST | low | `http-attacks-tls-attacks-poodle-and-beast.md` |  |
| Padding Oracles | low | `http-attacks-tls-attacks-padding-oracles.md` |  |
| Parameter Pollution | medium | `parameter-pollution.md` | HTTP, Open Redirect |
| Request Smuggling & HTTP Desync | high | `http-attacks-request-smuggling-and-http-desync.md` |  |
| SSL Stripping | low | `http-attacks-tls-attacks-ssl-stripping.md` |  |
| Status Code Bypass | low | `status-code-bypass.md` | 403, HTTP |
| TLS 1.2 Handshake | low | `http-attacks-tls-attacks-tls-1-2-handshake.md` |  |
| TLS 1.3 | low | `http-attacks-tls-attacks-tls-1-3.md` |  |
| TLS-Attacks | low | `http-attacks-tls-attacks.md` |  |
| Testing TLS Configuration | low | `http-attacks-tls-attacks-testing-tls-configuration.md` |  |
| The Heartbleed Bug | low | `http-attacks-tls-attacks-the-heartbleed-bug.md` |  |
| Verb Tampering | high | `http-attacks-verb-tampering.md` |  |

## injection  (✅ skill)  — 19 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Advanced SQLMap | critical | `sqli-advanced-sqlmap.md` |  |
| Advanced SQLi Techniques | critical | `sqli-advanced-sqli-techniques.md` |  |
| Blind SQL Injection | critical | `sqli-blind-sql-injection.md` |  |
| Custom Tampering | critical | `sqli-custom-tampering.md` |  |
| File Read | critical | `sqli-file-read.md` |  |
| Identifying Vulnerabilities | critical | `sqli-identifying-vulnerabilities.md` |  |
| Intro to MSSQL/SQL Server | critical | `sqli-intro-to-mssql-sql-server.md` |  |
| Introduction PostgreSQL | critical | `sqli-introduction-postgresql.md` |  |
| LDAP Injections | high | `ldap-injections.md` | LDAP, Microsoft, Authentication, Account Takeover |
| Leaking NetNTLM Hashes | critical | `sqli-leaking-netntlm-hashes.md` |  |
| Mitigation | critical | `sqli-mitigation.md` |  |
| OS Command Injection | critical | `os-command-injection.md` | Remote Code Execution |
| Out-of-Band DNS | critical | `sqli-out-of-band-dns.md` |  |
| PostgreSQL-Specific Techniques | critical | `sqli-postgresql-specific-techniques.md` |  |
| Remote Code Execution | critical | `sqli-remote-code-execution.md` |  |
| SQLi | critical | `sqli.md` | SQL Injection, Remote Code Execution, Account Takeover, NTLM, SQL |
| SSTI | critical | `ssti.md` | Template Injection, Remote Code Execution, HTTP, Account Takeover, RCE |
| Time-based SQLi | critical | `sqli-time-based-sqli.md` |  |
| XPath Injections | high | `xpath-injections.md` | Authentication, Account Takeover, xPath, XML, Microsoft |

## ssrf-xxe-file  (✅ skill)  — 7 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| DNS Rebinding | high | `dns-rebinding.md` | DNS, 403, SSRF, Same Origin Policy |
| File Upload | critical | `file-upload.md` | File Upload, Authentication, Remote Code Execution, Account Takeover, XSS |
| LFI | critical | `lfi.md` | LFI, Remote Code Execution, JavaScript, PHP, File Upload |
| PDF Generators | medium | `pdf-generators.md` | HTTP, PDF, SSRF, XSS, JavaScript |
| PHP filter chain (LFI→ RCE) | critical | `php-filter-chain-lfi-rce.md` | PHP, Remote Code Execution, Deserialization, HTTP |
| SSRF | high | `ssrf.md` | SSRF, Open Redirect, DNS, Account Takeover, HTTP |
| XXE | critical | `xxe.md` | XXE, XML, Remote Code Execution, SSRF, XSS |

## api  (📄 reference)  — 5 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| GraphQL | medium | `api-graphql.md` |  |
| REST | medium | `api-rest.md` |  |
| SOAP | medium | `api-soap.md` |  |
| Tools | medium | `api-tools.md` |  |
| kiterunner | medium | `api-tools-kiterunner.md` |  |

## cms  (📄 reference)  — 4 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Drupal | medium | `cms-drupal.md` |  |
| Joomla | medium | `cms-joomla.md` |  |
| Wordpress | medium | `cms-wordpress.md` |  |
| cmsmap | medium | `cms-cmsmap.md` |  |

## misc  (📄 reference)  — 14 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| API | medium | `api.md` |  |
| Auto scanners | medium | `auto-scanners.md` |  |
| CMS | medium | `cms.md` |  |
| CVES | medium | `cves.md` | Misc |
| Cloud | medium | `cloud.md` |  |
| Data Exfiltration via Response Timing | medium | `race-conditions-and-timing-attacks-data-exfiltration-via-response-timing.md` |  |
| General | medium | `race-conditions-and-timing-attacks-general.md` |  |
| Race Conditions | medium | `race-conditions-and-timing-attacks-race-conditions.md` |  |
| Race Conditions & Timing Attacks | medium | `race-conditions-and-timing-attacks.md` | Race Condition, User Enumeration, HTTP |
| SMTP Header injection | medium | `smtp-header-injection.md` | SMTP, EMail |
| Shells | medium | `shells.md` |  |
| User Enumeration via Response Timing | medium | `race-conditions-and-timing-attacks-user-enumeration-via-response-timing.md` |  |
| WAF Bypasses | medium | `waf-bypasses.md` | 403, HTTP |
| ffuf | medium | `ffuf.md` |  |
