# Ruby Sink Pack (Rails)

## Sources
`params[...]`, `request.headers/.body/.cookies`, `session`, route globs, and DB
rows re-used. Rails auto-escapes ERB output — flag where that's bypassed.

## Sinks
| Source→ | Sink (grep) | Vuln class | Family | Safe pattern |
|---|---|---|---|---|
| any str | `` `#{...}` `` backticks, `system(`, `exec(`, `%x(`, `Open3` w/ shell | OS cmd inj | injection | args array, no interpolation |
| any str | `eval(`, `instance_eval(`, `class_eval(` | code inj | injection | avoid dynamic eval |
| name | `send(`, `public_send(`, `constantize`, `.to_sym` from input | method inj | injection | allowlist methods |
| any str | `where("..."#{`, `find_by_sql(`, `.order(params`, `exists?("..."+` | SQLi | injection | hash/`?` bind params |
| any str | `render inline:`, `render text:`, ERB from input | SSTI/XSS | injection/client-side | precompiled templates |
| html | `raw(`, `html_safe`, `<%== %>` on user data | XSS | client-side | default escaping; sanitize |
| obj | `YAML.load(`, `Marshal.load(`, `Oj.load` (unsafe) | insecure deser | deserialization | `YAML.safe_load`, JSON |
| url | `open(user)` (open-uri), `Net::HTTP.get(URI(user))` | SSRF/LFI | ssrf-xxe-file | allowlist; `URI.open` restricted |
| url | `Faraday`/`HTTParty`/`RestClient`/`Net::HTTP` to a user URL with the egress/localhost check wrapped in `if <env flag>` (`multitenant?`, `Rails.env.production?`) | SSRF (gated) | ssrf-xxe-file | validate egress **unconditionally** |
| params | `Model.new(params[...])` / `update(params[...])` without `permit` | mass assignment | access-control | strong params `permit(...)` |
| id | `Model.find(params[:id])` with no scope/authorization | IDOR | access-control | scope to `current_user` / Pundit |
| — | `Digest::MD5`/`SHA1` for pw, `OpenSSL::SSL::VERIFY_NONE` | weak crypto/TLS | secrets-crypto | bcrypt; verify peer |
| — | hardcoded secrets in `secrets.yml`/`credentials`/source | secret exposure | secrets-crypto | Rails credentials/env |

## Ripgrep sweep
```
rg -n --no-heading -g '*.{rb,erb}' \
  -e 'system\(' -e '`.*#\{' -e '%x\(' -e '\beval\(' -e 'instance_eval\(' \
  -e '\bsend\(' -e 'public_send\(' -e 'constantize' \
  -e 'where\(".*#\{' -e 'find_by_sql\(' -e 'render\s+(inline|text):' \
  -e '\braw\(' -e 'html_safe' -e 'YAML\.load\(' -e 'Marshal\.load\(' \
  -e '\bopen\(' -e 'Net::HTTP' -e 'VERIFY_NONE' \
  -e 'Digest::(MD5|SHA1)' \
  <src>
```

## Confirm
A grep hit is a **lead**. Promote to `confirmed` only after reading the code and
tracing a request-controlled source to the sink with no sanitizer; record the
`file:line` chain in `dataflow` + a `code_excerpt`. For mass assignment, confirm
the attribute is sensitive (e.g. `admin`, `role`) and not filtered by `permit`.

### Rails-specific confirm notes
- **Egress/SSRF guard gated on an env flag.** `if Docuseal.multitenant?` /
  `if Rails.env.production?` around an allowlist or `localhost` denylist means the
  sink is **live whenever the flag is false** — read the *deployed* env, not the
  source default. Check whether the same flag gates other paths too (DocuSeal's
  `multitenant?` also toggles `plugin :sidekiq_embed`, so self-hosted = guard off
  **and** worker on = the webhook SSRF auto-fires).
- **Async delivery (webhooks/jobs).** A sink reached via `perform_later` /
  `perform_async` / `Sidekiq::Client.push` only fires if a worker consumes the
  job. Check `config.active_job.queue_adapter` and whether a worker runs — Rails
  apps may embed Sidekiq in the web process (`plugin :sidekiq_embed` in
  `config/puma.rb`), so a single container processes jobs with no separate
  process to observe.
- **Not SQLi.** Interpolating an **integer index** or an **allowlisted symbol**
  into an Arel bind-parameter *name* (`:term#{i}`, `Arel.sql("… :#{key}")` where
  the value is still bound via `sanitize_sql_array`/hash params) is parameterized.
  Don't flag search/tsquery builders on the interpolation alone — confirm a
  *value* (not just a bind-name) is concatenated.
- **Reflection oracles are status-gated.** When a sink stores a response for
  later reflection, check the condition: DocuSeal only persists
  `response.body` when `status >= 400` (`send_webhook_request.rb`), so a 2xx/3xx
  body is blind — the exfil primitive is error-page bytes + status/timing, not a
  clean read of successful internal responses.
