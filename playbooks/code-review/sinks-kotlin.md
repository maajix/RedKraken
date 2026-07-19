# Kotlin Sink Pack (Ktor, Spring, JVM)

Use this pack for Kotlin/JVM services and shared JVM libraries. Kotlin null and
type safety do not replace trust-boundary validation. A match is a lead until a
request-controlled source is traced into an effective runtime sink.

## Request-controlled sources

Trace Ktor `call.parameters`, `queryParameters`, request headers/cookies,
`receive<T>()`, `receiveParameters()`, multipart parts, and route values; Spring
MVC annotated parameters and bodies; WebSocket/queue/webhook messages; uploaded
filenames; and stored values reused by later jobs or administrative workflows.

## Source-to-sink review

| Source → sink lead | Risk / family | Confirmation boundary | Safe pattern |
|---|---|---|---|
| Tainted string reaches `Runtime.exec`, shell invocation, or executable slot of `ProcessBuilder` | command injection / injection | A fixed `ProcessBuilder` command list separates arguments; confirm attacker control of executable or shell grammar | Fixed executable and argument list; allowlisted operations; no shell |
| String templates/concatenation reach JDBC `Statement`, Exposed `exec`, JPA native query text, or jOOQ plain SQL | SQL injection / injection | Prove values enter SQL grammar; `PreparedStatement` setters and Exposed DSL parameters are negative evidence | Prepared statements/DSL; allowlist identifiers that cannot be bound |
| `ObjectInputStream`, unsafe YAML constructors, expression/script engines, or polymorphic type selection consumes lower-trust data | deserialization/code injection / deserialization | Confirm reachable lower-trust bytes and effective class/type filters; do not create gadget payloads | `kotlinx.serialization` with closed types; avoid JVM native serialization; bounded input |
| XML reaches JAXP factories with external access or insecure processing enabled | XXE / ssrf-xxe-file | Record factory type, explicit features/properties, JDK/runtime version, resolvers, and limits | Explicit secure processing; deny external DTD/schema/stylesheets; local catalog if required |
| User URL reaches Ktor `HttpClient`, Java HTTP clients, or SDK request builders | SSRF / ssrf-xxe-file | Confirm URL construction, redirects (Ktor follows by default), DNS, proxy, and egress behavior | Allowlisted destination; resolved-address checks; disable/revalidate redirects |
| User path reaches `File`, `Path`/`Files`, static-file response, template loader, or archive extraction | traversal/file access / ssrf-xxe-file | Prove normalized/canonical containment failure including symlinks and archive entries | Generated names; canonical root containment; safe archive extraction |
| Tainted markup reaches `respondText(..., Text.Html)`, raw template output, Thymeleaf `utext`, or kotlinx.html unsafe/raw insertion | XSS / client-side | Confirm HTML context and escaping bypass; kotlinx.html text insertion is negative evidence | HTML DSL/text nodes or contextual template encoding; sanitize approved markup |
| JWT claims are decoded without verifier/claim validation, or privileged routes sit outside `authenticate`/policy checks | auth bypass / auth-session | Confirm signature, algorithm, issuer, audience, expiry, route wrapper, and resource authorization | Ktor verifier plus `validate`; fixed algorithms/claims; route and object policies |
| Object fetch by id lacks tenant/owner/role constraint | IDOR / access-control | Prove minimum-role access and absence of service/repository checks | Owner/tenant-constrained query plus explicit authorization |
| Tainted text reaches raw response/header serialization | response splitting / http-protocol | Ktor/JVM typed headers may reject controls; confirm actual lower-level acceptance before promotion | Typed header APIs; reject CR/LF and control bytes; no hand-built HTTP |
| Weak password hash, predictable token RNG, disabled TLS validation, or literal secret | crypto/secret exposure / secrets-crypto | Confirm production security use and effective client configuration; redact all values | Password KDF, `SecureRandom`, default trust validation, managed secret storage |

## Safe ripgrep sweep

```sh
rg -n --no-heading -g '*.{kt,kts}' \
  -e 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(' -e 'sh\s+-c|cmd\.exe' \
  -e 'createStatement\(|prepareStatement\(|exec\(|createNativeQuery\(|plainSQL' \
  -e 'ObjectInputStream|readObject\(|Yaml\(|ScriptEngine|eval\(' \
  -e 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|FEATURE_SECURE_PROCESSING' \
  -e 'HttpClient\(|client\.(get|post|request)\(|followRedirects' \
  -e 'File\(|Paths\.get|Files\.(read|write)|ZipInputStream|respondFile' \
  -e 'ContentType\.Text\.Html|respondText\(|unsafe\s*\{|raw\(|utext' \
  -e 'JWT\.decode|JWT\.require|verifier\(|authenticate\(' \
  -e 'MessageDigest|getInstance\("(MD5|SHA-1)"|SecureRandom|TrustAll|HostnameVerifier' \
  <src>
```

## Confirmation

Trace from the Ktor/Spring/consumer entry point through Kotlin extension
functions and Java interop into the final API. Record the installed plugins,
route nesting, JDK and library versions, environment gates, worker consumption,
and runtime defaults. Do not promote safe DSL queries, typed kotlinx
serialization, normal kotlinx.html text insertion, or rejected header values.

## Evidence contract

- `dataflow`: ordered `file:line` source → extensions/services/guards → JVM sink.
- `reachability`: route or message consumer, minimum role, installed Ktor/Spring
  plugins, deployment flags, and async worker state.
- `control_verdict`: why SQL binding, process separation, XML restrictions,
  redirect policy, path containment, encoding, token validation, or authz fails.
- `code_excerpt`: minimal redacted proof; never copy credentials, customer data,
  request bodies, production hosts, or local engagement values.
- `negative_checks`: framework defaults, interceptors/filters, route wrappers,
  repository constraints, safe overloads, and tests reviewed before promotion.

## Remediation

Prefer structured JVM/Kotlin APIs: fixed `ProcessBuilder` lists, JDBC/Exposed
parameters, closed typed serialization, explicitly restricted JAXP factories,
destination and redirect policy, canonical path containment, Kotlin HTML DSL or
contextual escaping, full JWT verification, and resource-level authorization.
Use managed secrets and standard TLS trust. Add a synthetic regression test at
the broken boundary.

## Sources

- [Ktor request handling and input sources](https://ktor.io/docs/server-requests.html)
- [Ktor authentication and authorization](https://ktor.io/docs/server-auth.html)
- [Ktor JWT verification and validation](https://ktor.io/docs/server-jwt.html)
- [Ktor client redirect behavior](https://ktor.io/docs/client-redirect.html)
- [Kotlin serialization](https://kotlinlang.org/docs/serialization.html)
- [JDK 25 `ProcessBuilder`](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ProcessBuilder.html)
- [JDK 25 `PreparedStatement`](https://docs.oracle.com/en/java/javase/25/docs/api/java.sql/java/sql/PreparedStatement.html)
- [JDK 25 JAXP security guide](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html)
- [JetBrains Exposed prepared SQL behavior](https://www.jetbrains.com/help/exposed/dsl-statement-builder.html)
