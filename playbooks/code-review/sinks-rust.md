# Rust Sink Pack (Axum, Actix Web, Rocket)

Rust's memory-safety guarantees do not establish request authorization, command
or query separation, output encoding, destination policy, or path containment.
Treat every search result as a lead and prove a reachable source-to-sink path.

## Request-controlled sources

Trace Axum `Path`, `Query`, `Form`, `Json`, `HeaderMap`, `Bytes`, and `Request`;
equivalent Actix/Rocket extractors; WebSocket messages; multipart filenames and
content; queue/webhook payloads; CLI/environment input in network services; and
stored values reused across trust boundaries.

## Source-to-sink review

| Source → sink lead | Risk / family | Confirmation boundary | Safe pattern |
|---|---|---|---|
| Tainted program reaches `Command::new`, or text reaches `sh -c` / `cmd /C` | command injection / injection | `Command::arg` is literal on normal executables; confirm attacker control of the executable or shell grammar, including Windows batch behavior | Fixed absolute executable, separate args, operation/argument allowlists, no shell |
| `format!`/concatenation creates text for `sqlx::query`, Diesel `sql_query`, or driver execute methods | SQL injection / injection | Prove data enters SQL grammar; `query!` bind arguments and Diesel expressions are negative evidence | Bind parameters; typed query DSL; allowlist identifiers that cannot be bound |
| User URL reaches `reqwest`, `hyper`, or an SDK request builder | SSRF / ssrf-xxe-file | Confirm effective scheme/host/port, DNS, proxy, redirect policy, and egress boundary | Parse once, allowlist destinations, validate resolved IPs and each redirect hop |
| User path reaches `std::fs`, `tokio::fs`, `NamedFile`, archive extraction, or a template loader | traversal/file access / ssrf-xxe-file | Prove the canonical final path or archive entry escapes its authorized root; account for symlinks and non-existent create targets | Framework traversal guard or canonical containment; generated storage names |
| Untrusted markup reaches raw `Html`, `Response<String>`, Askama `|safe`, or `escape = "none"` | XSS / client-side | Confirm response content type and escaping mode; normal Askama HTML escaping is negative evidence | Contextual template escaping; typed HTML builders; sanitize allowed markup |
| Untrusted bytes reach custom `Deserialize`, `bincode`, MessagePack, or XML parsing without type/size/depth limits | parser/deserialization abuse / deserialization | Typed Serde is not arbitrary-code deserialization by itself; prove dangerous custom hooks, type selection, or resource impact before promotion | Closed types, bounded body/depth/collections, reviewed custom deserializers |
| Token claims come from decode-only helpers or validation omits algorithm/issuer/audience | auth bypass / auth-session | Trace the exact library/version and validation builder; decoding alone must not authorize | Verify signature and fixed algorithms; validate issuer, audience, time, and token type |
| Object fetch or route lacks ownership/role enforcement | IDOR/function authz / access-control | Prove minimum-role reachability and absence of middleware plus resource checks | Authorization layer plus tenant/owner-constrained query |
| Tainted value reaches raw header bytes | response splitting / http-protocol | `HeaderValue::from_str` rejects invalid values; confirm a lower-level serializer or unsafe conversion bypasses that check | Typed header APIs; reject controls; no raw HTTP serialization |
| `md5`/`sha1` protects passwords, weak RNG creates tokens, or TLS verification is disabled | weak crypto/TLS / secrets-crypto | Confirm a security use and effective client configuration, excluding tests/checksums | Password-hashing crate, OS CSPRNG, standard certificate verification |
| Literal credentials, signing keys, or private material | secret exposure / secrets-crypto | Validate without copying the value; exclude examples, fixtures, and generated files | Secret injection, least privilege, rotation |

## Safe ripgrep sweep

```sh
rg -n --no-heading -g '*.rs' \
  -e 'Command::new|\.arg\("-c"\)|cmd\.exe|\.bat"' \
  -e 'sqlx::query|query_as|sql_query|format!\(.*(SELECT|INSERT|UPDATE|DELETE)' \
  -e 'reqwest::|hyper::|Client::new\(' \
  -e 'std::fs|tokio::fs|NamedFile|canonicalize|ZipArchive|tar::Archive' \
  -e '\|safe|escape\s*=\s*"none"|Html\(|Response<String>' \
  -e 'Deserialize|bincode|rmp_serde|quick_xml|serde_yaml' \
  -e 'dangerous::insecure_decode|decode_header|Validation::new' \
  -e 'HeaderValue::from|from_bytes_unchecked|md5|sha1|danger_accept_invalid_certs' \
  <src>
```

## Confirmation

Record the concrete extractor/consumer and prove its value reaches the sink.
Check feature flags, target OS, crate versions, middleware layers, async worker
execution, and error paths. Do not promote generic `unsafe`, Serde derives,
`Command::arg`, `HeaderValue::from_str`, or an HTTP client call without the
missing security invariant that makes the path exploitable.

## Evidence contract

- `dataflow`: ordered `file:line` source → conversions/guards → sink.
- `reachability`: handler/consumer, minimum role, enabled Cargo features,
  deployment/OS conditions, and worker execution where applicable.
- `control_verdict`: effective bind, escaping, destination, canonicalization,
  parser-limit, header, token, and authorization behavior.
- `code_excerpt`: minimal redacted supporting lines; never copy credentials,
  private data, request bodies, or production identifiers.
- `negative_checks`: safe overloads, wrapper types, middleware, crate defaults,
  and tests examined before promotion.

## Remediation

Use fixed executables with separate literal arguments, bound SQL values, a
destination policy that revalidates redirects and resolved addresses, canonical
path containment, contextual template escaping, bounded typed parsing, complete
token verification, and object-level authorization. Keep dependencies reviewed
with RustSec-compatible tooling. Add synthetic regression tests at the boundary
where the trace was broken.

## Sources

- [Rust `std::process::Command`](https://doc.rust-lang.org/std/process/struct.Command.html)
- [Rust `std::fs::canonicalize`](https://doc.rust-lang.org/std/fs/fn.canonicalize.html)
- [Axum extractors](https://docs.rs/axum/latest/axum/extract/index.html)
- [SQLx checked queries and bind parameters](https://docs.rs/sqlx/latest/sqlx/macro.query.html)
- [Reqwest redirect policy](https://docs.rs/reqwest/latest/reqwest/redirect/struct.Policy.html)
- [Askama escaping and `safe` behavior](https://docs.rs/askama/latest/askama/filters/index.html)
- [RustSec advisory database and tooling](https://rustsec.org/)
