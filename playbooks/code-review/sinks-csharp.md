# C# / .NET Sink Pack (ASP.NET Core)

Use this pack for `.cs`, Razor, and ASP.NET Core code. A textual match is only a
lead: confirm a request-controlled value reaches a security-sensitive API in the
deployed path without an effective framework control, allowlist, or encoding
boundary.

## Request-controlled sources

Trace controller/minimal-API parameters; `[FromQuery]`, `[FromRoute]`,
`[FromForm]`, `[FromBody]`, and `[FromHeader]`; `HttpRequest.Query`, `Form`,
`Headers`, `Cookies`, `Body`, and uploaded `IFormFile` values. Also trace queue
messages, webhook bodies, configuration writable by a lower-trust tenant, and
database values later reused in a sensitive context.

## Source-to-sink review

| Source → sink lead | Risk / family | Confirmation boundary | Safe pattern |
|---|---|---|---|
| Tainted executable, `Arguments`, or shell text reaches `Process.Start` / `ProcessStartInfo` | command injection / injection | Confirm the executable or shell grammar is attacker-controlled; `ArgumentList` with a fixed executable is negative evidence | Fixed executable, allowlisted operation, separate `ArgumentList` entries, no shell |
| Interpolation/concatenation reaches `DbCommand.CommandText`, `FromSqlRaw`, `ExecuteSqlRaw`, or Dapper query text | SQL injection / injection | Trace a value into SQL grammar, not a parameter object; distinguish EF interpolated APIs that parameterize values | Parameters, LINQ, `FromSqlInterpolated`, fixed identifier allowlists |
| `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, or `ObjectStateFormatter` deserializes lower-trust bytes | unsafe deserialization / deserialization | Prove the bytes cross a trust boundary and the call is reachable; do not generate a gadget payload | Remove these serializers; use typed `System.Text.Json` or a constrained data format |
| XML input reaches `XmlReader`/DOM/SAX with DTD parsing or an external resolver enabled | XXE / ssrf-xxe-file | Record effective `XmlReaderSettings`, target framework, resolver, and resource limits | `DtdProcessing.Prohibit`, `XmlResolver = null`, explicit size/depth limits |
| User URL reaches `HttpClient`, `WebRequest`, or an SDK accepting a URI | SSRF / ssrf-xxe-file | Follow construction, redirects, DNS resolution, proxy behavior, and egress policy; a client call alone is not SSRF | Allowlisted scheme/host/port, resolved-IP policy on every hop, redirect revalidation |
| User path reaches `File.*`, `Directory.*`, `FileStream`, `PhysicalFile`, or archive extraction | traversal/file access / ssrf-xxe-file | Prove the canonical final path escapes the authorized root, including symlinks and archive entries | Server-generated names; canonicalize existing root and final path; enforce containment |
| Tainted markup reaches `Html.Raw`, `HtmlString`, `IHtmlContent`, or a raw HTML response | XSS / client-side | Razor output is encoded by default; confirm the code bypasses encoding in the relevant HTML/JS/URL context | Preserve Razor encoding; contextual encoders; sanitize intentionally allowed markup |
| Tainted text reaches raw response/header serialization | response splitting / http-protocol | Modern header APIs may reject CR/LF; confirm a real serialization path accepts it before promotion | Typed header APIs; reject control characters; never hand-build HTTP responses |
| Object lookup or privileged endpoint lacks resource/policy authorization | IDOR/function authz / access-control | Prove the minimum authenticated role can reach the object/action; authentication alone is not authorization | Fallback authorization policy plus resource-based ownership/role checks |
| `MD5`/`SHA1` protects passwords, `Random` creates security tokens, or certificate validation always succeeds | weak crypto/TLS / secrets-crypto | Confirm security use, not checksums/tests; record configuration without secret values | PasswordHasher/PBKDF2/Argon2, `RandomNumberGenerator`, normal certificate validation |
| Literal credential/token/private material in source or configuration | secret exposure / secrets-crypto | Validate the type and reachability without copying the value; dedupe scanner findings | Secret manager or environment injection; rotate exposed material |

## Safe ripgrep sweep

```sh
rg -n --no-heading -g '*.{cs,cshtml,razor}' \
  -e 'Process\.Start|ProcessStartInfo|UseShellExecute|\.Arguments\s*=' \
  -e 'CommandText|FromSqlRaw|ExecuteSqlRaw|Query(Raw|Async)?\(' \
  -e 'BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter' \
  -e 'DtdProcessing|XmlResolver|XmlReader\.Create|DocumentBuilder' \
  -e 'HttpClient|WebRequest|GetAsync\(|PostAsync\(' \
  -e 'File\.(Open|Read|Write)|Directory\.|FileStream|PhysicalFile|ZipFile' \
  -e 'Html\.Raw|HtmlString|IHtmlContent|ContentType\.Text\.Html' \
  -e 'Response\.Headers|Headers\.Append|\[AllowAnonymous\]|\[Authorize' \
  -e 'MD5|SHA1|Random\(|ServerCertificateCustomValidationCallback' \
  <src>
```

## Confirmation

For every trace-family lead, record the entry point, exact source, intermediate
transformations, guard/encoder/validator behavior, and sink. Keep a lead
`suspected` when the source is not attacker-controlled, the route is unreachable,
the value is parameterized/contextually encoded, or a framework API rejects the
dangerous representation. Treat secrets and weak-crypto code facts as
scanner-native only after excluding fixtures, generated code, and non-security
uses.

## Evidence contract

- `dataflow`: ordered `file:line` source → transformations/guards → sink.
- `reachability`: route or consumer, minimum role, deployment/config preconditions,
  and whether asynchronous work is actually consumed.
- `control_verdict`: why parameterization, encoding, canonicalization, policy, or
  parser settings do or do not stop the path.
- `code_excerpt`: the smallest redacted excerpt needed to support the conclusion;
  never include a live secret, token, customer record, or full configuration.
- `negative_checks`: nearby middleware, filters, authorization handlers, safe API
  overloads, and tests reviewed before promotion.

## Remediation

Break the trace at the deepest boundary: use structured process arguments and
fixed executables; parameterize data while allowlisting dynamic identifiers;
replace unsafe serializers; prohibit XML external access; apply destination and
canonical-path policies; retain Razor contextual encoding; require resource-level
authorization; and move credentials to a managed secret store. Add a regression
test using synthetic values that proves the formerly reachable sink is rejected
or safely encoded.

## Sources

- [ASP.NET Core model binding sources](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/model-binding?view=aspnetcore-10.0)
- [.NET BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [XmlReader creation defaults and security considerations](https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-xml-xmlreader-create)
- [Microsoft.Data.Sqlite parameter guidance](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/parameters)
- [ASP.NET Core authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction?view=aspnetcore-10.0)
- [ASP.NET Core XSS prevention](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0)
- [`ProcessStartInfo.ArgumentList`](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist?view=net-9.0)
