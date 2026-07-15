# Go Sink Pack (net/http, common frameworks)

## Sources
`r.URL.Query().Get`, `r.FormValue/.PostFormValue`, `r.Header.Get`, `mux.Vars(r)`,
`json.NewDecoder(r.Body)`, path params (gin/echo/chi), `os.Getenv`, `os.Args`.

## Sinks
| Source→ | Sink (grep) | Vuln class | Family | Safe pattern |
|---|---|---|---|---|
| any str | `exec.Command("sh","-c",user)` / `exec.Command(user...)` | OS cmd inj | injection | fixed argv, no `sh -c` |
| any str | `fmt.Sprintf("...%s...", user)` into SQL, `db.Query("..."+`, `.Exec("..."+` | SQLi | injection | `?`/`$1` placeholders |
| tmpl | `text/template` with user data rendered to HTML | XSS | client-side | `html/template` (auto-escapes) |
| path | `filepath.Join(root, user)`, `os.Open(user)`, `http.ServeFile(w,r,user)` | path traversal | ssrf-xxe-file | `filepath.Clean` + prefix check |
| url | `http.Get(user)`, `http.NewRequest(...,user,...)` | SSRF | ssrf-xxe-file | allowlist host; block internal |
| obj | `gob.NewDecoder(untrusted)`, `encoding/xml` w/ external entities | deser/XXE | deserialization / ssrf-xxe-file | validate; no external entities |
| id | handler fetches by id with no ownership/role check | IDOR | access-control | authz middleware + object check |
| — | `crypto/md5`,`crypto/sha1` for pw, `math/rand` for tokens | weak crypto | secrets-crypto | bcrypt; `crypto/rand` |
| — | `tls.Config{InsecureSkipVerify:true}` | TLS bypass | secrets-crypto | verify certs |
| — | hardcoded keys/tokens as string consts | secret exposure | secrets-crypto | env/secret store |

## Ripgrep sweep
```
rg -n --no-heading -g '*.go' \
  -e 'exec\.Command\(' -e 'exec\.CommandContext\(' \
  -e 'fmt\.Sprintf\(.*(SELECT|INSERT|UPDATE|DELETE)' -e 'db\.(Query|Exec)\(.*\+' \
  -e '"text/template"' -e 'filepath\.Join\(' -e 'os\.Open\(' -e 'ServeFile\(' \
  -e 'http\.Get\(' -e 'http\.NewRequest\(' \
  -e 'gob\.NewDecoder\(' -e 'InsecureSkipVerify' \
  -e 'crypto/md5|crypto/sha1' -e 'math/rand' \
  <src>
```

## Confirm
A grep hit is a **lead**. Promote to `confirmed` only after reading the code and
tracing a request-controlled source to the sink with no sanitizer; record the
`file:line` chain in `dataflow` + a `code_excerpt`. Note the `text/template` vs
`html/template` distinction — the former does NOT auto-escape.
