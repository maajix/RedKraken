# Web Playbook Catalog — signal → technique → playbook

Routing table for triage and hunters. Families with a dedicated hunting skill are marked ✅; others are reference playbooks the recon-agent / hunters consult opportunistically.

**155 playbooks across 12 families.**

## access-control  (✅ skill)  — 1 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| IDOR | high | `idor.md` | Authentication, HTTP, Auth |

## agentic-ai  (✅ skill)  — 1 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| LLM | medium | `llm.md` | LLM, SSRF, XSS, Account Takeover |

## auth-session  (✅ skill)  — 13 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| AWS Cognito | medium | `cloud-aws-cognito.md` |  |
| Attack via Google oAuth2 Playground | high | `oauth2-attack-via-google-oauth2-playground.md` |  |
| Authentication Bypass | high | `type-juggling-authentication-bypass.md` |  |
| Introduction to Type Juggling | medium | `type-juggling-introduction-to-type-juggling.md` |  |
| JWT | high | `jwt.md` | Session Tokens, Account Takeover, XSS, JavaScript, Auth |
| Password Reset | medium | `http-attacks-password-reset.md` |  |
| Rate-Limit Bypass | medium | `rate-limit-bypass.md` | Rate-Limit, HTTP |
| SAML | high | `saml.md` | Authentication, SAML, API, Account Takeover, XXE |
| Sign Up (Login / Register) | medium | `sign-up-login-register.md` | DoS, Account Takeover, XSS, User Enumeration, SQL Injection |
| Type Juggling | medium | `type-juggling.md` | PHP, Account Takeover, Authentication, HTTP, Session Tokens |
| UUIDs | low | `uuids.md` |  |
| Weak Password Policy | medium | `sign-up-login-register-weak-password-policy.md` |  |
| oAuth2 | high | `oauth2.md` | Authentication, XSS, Request Smuggling, CSRF, Open Redirect |

## client-side  (✅ skill)  — 22 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Broken-Link Hijacking | low | `broken-link-hijacking.md` | HTML |
| CORS | medium | `cors.md` | CORS, Account Takeover, CSRF, XSS, Cache Poisoning |
| CSRF | medium | `csrf.md` | CSRF, HTTP, Account Takeover, HTML |
| Clientside PP | medium | `prototype-pollution-clientside-pp.md` |  |
| DOM Vulnerabilities | medium | `dom-vulnerabilities.md` | DOM, JavaScript, XSS, Open Redirect, SQL Injection |
| Dangling Markup | medium | `dangling-markup.md` | HTML, XSS, Content Security Policy, Account Takeover, Session Tokens |
| Filter Bypasses | medium | `prototype-pollution-filter-bypasses.md` |  |
| Introduction to Prototype Pollution | medium | `prototype-pollution-introduction-to-prototype-pollution.md` |  |
| JavaScript Objects & Prototypes | medium | `prototype-pollution-javascript-objects-and-prototypes.md` |  |
| Open Redirection | medium | `open-redirection.md` | XSS, Deserialization, Open Redirect, JavaScript, HTTP |
| Other attacks via WebSockets | medium | `websocket-attacks-other-attacks-via-websockets.md` |  |
| Privilege Escalation | medium | `prototype-pollution-privilege-escalation.md` |  |
| Prototype Pollution | medium | `prototype-pollution.md` | JavaScript, Account Takeover, XSS, 403, Remote Code Execution |
| Remarks | medium | `prototype-pollution-remarks.md` |  |
| Remote Code Execution | critical | `prototype-pollution-remote-code-execution.md` |  |
| Tabnabbing | low | `tabnabbing.md` | HTML |
| Tools & Prevention | medium | `websocket-attacks-tools-and-prevention.md` |  |
| WebSocket Analysis in Burp | medium | `websocket-attacks-websocket-analysis-in-burp.md` |  |
| WebSocket Attacks | medium | `websocket-attacks.md` | Web Sockets, HTTP, XSS, SQL Injection, Account Takeover |
| XSS | medium | `xss.md` | JavaScript, HTML, XSS, CSRF, Content Security Policy |
| XSSI | medium | `cors-xssi.md` |  |
| paramspider | medium | `xss-paramspider.md` |  |

## deserialization  (✅ skill)  — 7 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Defending against Deserialization Attacks | critical | `deserialization-attacks-defending-against-deserialization-attacks.md` |  |
| Deserialization Attacks | critical | `deserialization-attacks.md` | Deserialization, PHP, Python, Remote Code Execution, Account Takeover |
| Exploiting PHP Deserialization | critical | `deserialization-attacks-exploiting-php-deserialization.md` |  |
| Exploiting Python Deserialization | critical | `deserialization-attacks-exploiting-python-deserialization.md` |  |
| Introduction | critical | `deserialization-attacks-introduction.md` |  |
| Tools of the Trade (PHP Deserialization) | critical | `deserialization-attacks-tools-of-the-trade-php-deserialization.md` |  |
| Tools of the Trade (Python Deserialization) | critical | `deserialization-attacks-tools-of-the-trade-python-deserialization.md` |  |

## http-protocol  (✅ skill)  — 31 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| 1_Introduction_to_HTTP_verb_Tampering_INFO | low | `http-attacks-verb-tampering-1-introduction-to-http-verb-tampering-info.md` |  |
| 2_Bypassing_Basic_Authentication_INFO | high | `http-attacks-verb-tampering-2-bypassing-basic-authentication-info.md` |  |
| 3_Bypassing_Security_Filters_INFO | low | `http-attacks-verb-tampering-3-bypassing-security-filters-info.md` |  |
| 4_Verb_Tampering_Prevention_INFO | low | `http-attacks-verb-tampering-4-verb-tampering-prevention-info.md` |  |
| Bleichenbacher & DROWN | low | `http-attacks-tls-attacks-bleichenbacher-and-drown.md` |  |
| CRIME & BREACH | low | `http-attacks-tls-attacks-crime-and-breach.md` |  |
| CRLF Injection & Response splitting | medium | `http-attacks-crlf-injection-and-response-splitting.md` |  |
| Cache Poisoning | medium | `cache-poisoning.md` | Cache Poisoning, 403, XSS, DoS, JavaScript |
| Compression | low | `http-attacks-tls-attacks-compression.md` |  |
| Cryptographic Atks | low | `http-attacks-tls-attacks-cryptographic-atks.md` |  |
| Downgrade Attacks | low | `http-attacks-tls-attacks-downgrade-attacks.md` |  |
| Further H2 Vulnerabilities | medium | `http-attacks-http-2-downgrading-further-h2-vulnerabilities.md` |  |
| HTTP Attacks | medium | `http-attacks.md` | HTTP, Request Smuggling, Password Reset, CRLF, Host-Header |
| HTTP/2 Downgrading | medium | `http-attacks-http-2-downgrading.md` |  |
| HTTP/2 Downgrading | medium | `http-attacks-http-2-downgrading-http-2-downgrading.md` |  |
| Host-Header | medium | `http-attacks-host-header.md` |  |
| Introduction to HTTP2 | medium | `http-attacks-http-2-downgrading-introduction-to-http2.md` |  |
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
| Tools & Prevention | medium | `http-attacks-http-2-downgrading-tools-and-prevention.md` |  |
| Verb Tampering | medium | `http-attacks-verb-tampering.md` |  |

## injection  (✅ skill)  — 37 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Advanced SQLMap | critical | `sqli-advanced-sqlmap.md` |  |
| Advanced SQLi Techniques | critical | `sqli-advanced-sqli-techniques.md` |  |
| Blind SQL Injection | critical | `sqli-blind-sql-injection.md` |  |
| Command Execution (RCE) | critical | `sqli-postgresql-specific-techniques-command-execution-rce.md` |  |
| Common Character Bypasses | critical | `sqli-advanced-sqli-techniques-common-character-bypasses.md` |  |
| Custom Tampering | critical | `sqli-custom-tampering.md` |  |
| Decompiling Java Archives | critical | `sqli-identifying-vulnerabilities-decompiling-java-archives.md` |  |
| Error-Based SQLi | critical | `sqli-advanced-sqli-techniques-error-based-sqli.md` |  |
| File Read | critical | `sqli-file-read.md` |  |
| Hunting for SQL Errors | critical | `sqli-identifying-vulnerabilities-hunting-for-sql-errors.md` |  |
| Identifying Vulnerabilities | critical | `sqli-identifying-vulnerabilities.md` |  |
| Intro to MSSQL/SQL Server | critical | `sqli-intro-to-mssql-sql-server.md` |  |
| Introduction PostgreSQL | critical | `sqli-introduction-postgresql.md` |  |
| LDAP - Authentication Bypass | high | `ldap-injections-ldap-authentication-bypass.md` |  |
| LDAP - Blind Exploitation | medium | `ldap-injections-ldap-blind-exploitation.md` |  |
| LDAP Injection Prevention | medium | `ldap-injections-ldap-injection-prevention.md` |  |
| LDAP Injections | medium | `ldap-injections.md` | LDAP, Microsoft, Authentication, Account Takeover |
| Leaking NetNTLM Hashes | critical | `sqli-leaking-netntlm-hashes.md` |  |
| Live-Debugging Java Applications | critical | `sqli-identifying-vulnerabilities-live-debugging-java-applications.md` |  |
| Mitigation | critical | `sqli-mitigation.md` |  |
| OS Command Injection | critical | `os-command-injection.md` | Remote Code Execution |
| Out-of-Band DNS | critical | `sqli-out-of-band-dns.md` |  |
| PostgreSQL-Specific Techniques | critical | `sqli-postgresql-specific-techniques.md` |  |
| Prevention | critical | `sqli-postgresql-specific-techniques-prevention.md` |  |
| Reading and Writing Files | critical | `sqli-postgresql-specific-techniques-reading-and-writing-files.md` |  |
| Remote Code Execution | critical | `sqli-remote-code-execution.md` |  |
| SQLi | critical | `sqli.md` | SQL Injection, Remote Code Execution, Account Takeover, NTLM, SQL |
| SSTI | critical | `ssti.md` | Template Injection, Remote Code Execution, HTTP, Account Takeover, RCE |
| Searching for Strings | critical | `sqli-identifying-vulnerabilities-searching-for-strings.md` |  |
| Second-Order SQLi | critical | `sqli-advanced-sqli-techniques-second-order-sqli.md` |  |
| Time-based SQLi | critical | `sqli-time-based-sqli.md` |  |
| XPath - Advanced Data Exfiltration | medium | `xpath-injections-xpath-advanced-data-exfiltration.md` |  |
| XPath - Authentication Bypass | high | `xpath-injections-xpath-authentication-bypass.md` |  |
| XPath - Blind Exploitation | medium | `xpath-injections-xpath-blind-exploitation.md` |  |
| XPath - Data Exfiltration | medium | `xpath-injections-xpath-data-exfiltration.md` |  |
| XPath Injections | medium | `xpath-injections.md` | Authentication, Account Takeover, xPath, XML, Microsoft |
| XPath Tools & Prevention | medium | `xpath-injections-xpath-tools-and-prevention.md` |  |

## ssrf-xxe-file  (✅ skill)  — 15 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Advanced File Disclosure | critical | `xxe-advanced-file-disclosure.md` |  |
| Blind Data Exfiltration | critical | `xxe-blind-data-exfiltration.md` |  |
| DNS Rebinding | medium | `dns-rebinding.md` | DNS, 403, SSRF, Same Origin Policy |
| DNS Rebinding: SSRF Filter Bypass | high | `dns-rebinding-dns-rebinding-ssrf-filter-bypass.md` |  |
| DNS Rebinding: Same-Origin Policy Bypass | medium | `dns-rebinding-dns-rebinding-same-origin-policy-bypass.md` |  |
| DTD’s | critical | `xxe-dtd-s.md` |  |
| File Upload | critical | `file-upload.md` | File Upload, Authentication, Remote Code Execution, Account Takeover, XSS |
| LFI | critical | `lfi.md` | LFI, Remote Code Execution, JavaScript, PHP, File Upload |
| LFI and RCE | critical | `xxe-lfi-and-rce.md` |  |
| PDF Generators | medium | `pdf-generators.md` | HTTP, PDF, SSRF, XSS, JavaScript |
| PHP filter chain (LFI→ RCE) | critical | `php-filter-chain-lfi-rce.md` | PHP, Remote Code Execution, Deserialization, HTTP |
| SSRF | high | `ssrf.md` | SSRF, Open Redirect, DNS, Account Takeover, HTTP |
| SSRF Basic Filter Bypasses | high | `dns-rebinding-ssrf-basic-filter-bypasses.md` |  |
| Tools & Prevention | medium | `dns-rebinding-tools-and-prevention.md` |  |
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

## misc  (📄 reference)  — 16 playbooks

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
| Unbenannt | medium | `unbenannt.md` |  |
| User Enumeration via Response Timing | medium | `race-conditions-and-timing-attacks-user-enumeration-via-response-timing.md` |  |
| WAF Bypasses | medium | `waf-bypasses.md` | 403, HTTP |
| Web attacks | medium | `web-attacks.md` |  |
| ffuf | medium | `ffuf.md` |  |

## recon-tools  (📄 reference)  — 3 playbooks

| technique | severity | playbook | tags |
|---|---|---|---|
| Nuclei | medium | `auto-scanners-nuclei.md` |  |
| NucleiFuzzer | medium | `auto-scanners-nucleifuzzer.md` |  |
| nikto | medium | `auto-scanners-nikto.md` |  |

