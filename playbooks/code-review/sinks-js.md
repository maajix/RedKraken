# JavaScript / TypeScript Sink Pack (Node / Express / Next.js)

## Sources
`req.query/.body/.params/.headers/.cookies` (Express), route/searchParams &
`request.json()` (Next.js API/route handlers), `process.env`, `process.argv`,
WebSocket messages, and DOM `location`/`document.referrer`/`postMessage` (client).

## Sinks
| Source→ | Sink (grep) | Vuln class | Family | Safe pattern |
|---|---|---|---|---|
| any str | `child_process.exec(`, `execSync(`, `spawn(`+`{shell:true}` | OS cmd inj | injection | `execFile`/args array, no shell |
| any str | `eval(`, `new Function(`, `vm.runInNewContext`, `vm.runInThisContext` | code inj | injection | avoid dynamic eval |
| any str | `require(`+var, dynamic `import(`+var | code/LFI | injection | static imports, allowlist |
| any str | `sequelize.query(`, `knex.raw(`, `db.query("..."+`, template-literal SQL | SQLi | injection | parameterized / bindings |
| obj | `{ $where:`, `$gt`/`$ne` from body into Mongo query | NoSQL inj | injection | cast/validate types |
| any str | `res.render(` inline template, `eval`-based templating | SSTI | injection | precompiled templates |
| html | `dangerouslySetInnerHTML`, `.innerHTML =`, `document.write(`, `$(el).html(` | XSS | client-side | textContent / sanitize (DOMPurify) |
| obj | recursive merge / `Object.assign` into `__proto__`/`constructor` | prototype pollution | client-side | reject `__proto__` keys; `Map` |
| path | `path.join(__dirname, req...)`, `fs.readFile(user)`, `res.sendFile(user)` | LFI / traversal | ssrf-xxe-file | resolve+prefix-check, allowlist |
| url | `axios/fetch/http.get(user)`, `request(user)` | SSRF | ssrf-xxe-file | allowlist host; block internal |
| token | `jwt.verify(` missing / `algorithms` omitted, `jwt.decode` used as auth | auth bypass | auth-session | verify w/ fixed alg + secret |
| — | `crypto.createHash('md5'/'sha1')` for pw, `Math.random()` for tokens | weak crypto | secrets-crypto | bcrypt/scrypt; `crypto.randomBytes` |
| — | hardcoded `apiKey`/`secret`/`token`/`AWS` literals, `.env` committed | secret exposure | secrets-crypto | env/secret store; gitignore |

## Ripgrep sweep
```
rg -n --no-heading -g '*.{js,jsx,ts,tsx,mjs,cjs}' \
  -e 'child_process' -e 'execSync\(' -e '\bexec\(' -e 'new Function\(' -e '\beval\(' \
  -e 'vm\.runIn' -e 'knex\.raw\(' -e 'sequelize\.query\(' -e '\$where' \
  -e 'dangerouslySetInnerHTML' -e '\.innerHTML' -e 'document\.write\(' \
  -e '__proto__' -e 'path\.join\(' -e 'sendFile\(' -e '(axios|fetch|http)\.get\(' \
  -e 'jwt\.(verify|decode)\(' -e "createHash\('?(md5|sha1)" -e 'InsecureSkip' \
  -e 'apiKey|secret|token' \
  <src>
```

## Confirm
A grep hit is a **lead**. Promote to `confirmed` only after reading the code and
tracing a request-controlled source to the sink with no sanitizer; record the
`file:line` chain in `dataflow` + a `code_excerpt`. Prefer `html/react` auto-escaping as the safe baseline; flag where it's bypassed.
