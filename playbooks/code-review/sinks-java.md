# Java Sink Pack (Spring / Jakarta)

## Sources
`@RequestParam/@PathVariable/@RequestBody/@RequestHeader/@CookieValue`,
`HttpServletRequest.getParameter/.getHeader/.getInputStream`, deserialized
payloads, JMS/queue messages, and DB rows re-used.

## Sinks
| Source→ | Sink (grep) | Vuln class | Family | Safe pattern |
|---|---|---|---|---|
| any str | `Runtime.getRuntime().exec(`, `new ProcessBuilder(` | OS cmd inj | injection | args list, no shell, allowlist |
| any str | `Statement` + `executeQuery("..."+`, `createQuery("..."+`, `createNativeQuery("..."+` | SQLi | injection | `PreparedStatement` / named params |
| any str | `ScriptEngine.eval(`, SpEL `parser.parseExpression(user)`, OGNL, MVEL | expression inj | injection | no user-driven expressions |
| obj | `ObjectInputStream.readObject(`, XMLDecoder, Jackson `enableDefaultTyping`/`@JsonTypeInfo`, `readValue` polymorphic | insecure deser | deserialization | avoid native deser; safe types only |
| name | `Class.forName(user)`, reflection from input, `context.lookup(user)` (JNDI) | RCE / JNDI inj | deserialization | no user class/JNDI names |
| xml | `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory` w/o `FEATURE_SECURE_PROCESSING`/disallow-doctype | XXE | ssrf-xxe-file | disable DTD & external entities |
| path | `new File(base, user)`, `Files.newInputStream(user)`, `getResourceAsStream(user)` | path traversal | ssrf-xxe-file | canonicalize + prefix check |
| url | `new URL(user).openConnection()`, `RestTemplate`/`WebClient` to user URL | SSRF | ssrf-xxe-file | allowlist host; block internal |
| html | `response.getWriter().print(user)`, JSP `<%= %>`, Thymeleaf `[(...)]` unescaped | XSS | client-side | escape; Thymeleaf `[[...]]` |
| token | JJWT/`Jwts.parser()` w/o signature verify, `alg:none` accepted | auth bypass | auth-session | require signature + fixed alg |
| route | `@RequestMapping` w/o `@PreAuthorize`/security config | broken authz | access-control | method/URL security |
| — | `MessageDigest.getInstance("MD5"/"SHA-1")` for pw, ECB, `TrustManager` that accepts all | weak crypto/TLS | secrets-crypto | bcrypt/PBKDF2; real trust store |
| — | hardcoded secrets in `.properties`/`.yml`/source | secret exposure | secrets-crypto | vault/env |

## Ripgrep sweep
```
rg -n --no-heading -g '*.{java,jsp}' \
  -e 'Runtime\.getRuntime\(\)\.exec' -e 'ProcessBuilder' \
  -e 'createQuery\(' -e 'createNativeQuery\(' -e 'executeQuery\(' -e 'Statement' \
  -e 'ScriptEngine' -e 'parseExpression\(' -e 'Ognl' \
  -e 'readObject\(' -e 'enableDefaultTyping' -e '@JsonTypeInfo' -e 'XMLDecoder' \
  -e 'Class\.forName\(' -e '\.lookup\(' \
  -e 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory' \
  -e 'new File\(' -e 'new URL\(' -e 'RestTemplate|WebClient' \
  -e 'getInstance\("(MD5|SHA-1)"' -e 'InsecureSkip|TrustAllCerts' \
  <src>
```

## Confirm
A grep hit is a **lead**. Promote to `confirmed` only after reading the code and
tracing a request-controlled source to the sink with no sanitizer; record the
`file:line` chain in `dataflow` + a `code_excerpt`. For deserialization/JNDI,
confirm the type is attacker-influenced and a gadget path is plausible.
