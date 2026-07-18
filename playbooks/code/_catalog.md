# Code-Audit Catalog (signal → sink → family → playbook)

Whitebox analogue of `playbooks/web/_catalog.md`. Maps a code signal (a grep hit
or a scanner lead) to a vuln class, an **attack family**, and the sink playbook
to open. The `/audit` orchestrator (`code-audit-loop`) uses this in P2 triage;
`code-auditor` agents use it to pick their sinks.

**Families (10):** shared blackbox and whitebox families —
`injection`, `auth-session`, `http-protocol`, `ssrf-xxe-file`,
`deserialization`, `client-side`, `access-control`, plus the
source/configuration-heavy families `secrets-crypto`, `supply-chain`, and
`config-iac`.

## Two kinds of lead (important)

- **Trace families** (`injection`, `client-side`, `ssrf-xxe-file`,
  `deserialization`, `auth-session`, `http-protocol`, `access-control`):
  a grep/scanner hit is only a **lead**. The `code-auditor` must read the code
  and trace a request-controlled **source → sink** with no effective sanitizer
  before promoting `suspected → confirmed`. No traced path ⇒ stays `suspected`.
- **Scanner-native families** (`supply-chain`, `secrets-crypto` secrets,
  `config-iac`): the scanner output *is* the finding — you can't taint-trace
  "dependency X has CVE-Y" or "AWS key at file:line". These go to
  `findings.jsonl` fairly directly (deduped, validated, reachability-checked),
  `source: sca:<tool>` / `secret:<tool>` / `iac:<tool>`. The auditor's job here
  is triage/false-positive reduction, not source→sink tracing.

## Confirmation heuristics — before you promote or escalate

A traced source→sink is necessary but **not sufficient**. Before `confirmed`
(and before spending a grey-box / exploit agent), run every lead through two
lenses. This is the highest-leverage filter in the loop — it kills most
"code-smell" findings that don't survive contact with a real deployment, and it
front-loads the verdict instead of paying for it in a research agent later.

1. **Does it fire on a real hosted deploy? (prove, don't assume.)** Find the
   real-world precondition and prove the *deployed* runtime satisfies it — never
   infer it from the source default alone:
   - Guard gated on an env flag (`if ENV['X']` / `if multitenant?`): read the
     **running** environment, not the code default.
   - **Queued / async sinks** (ActiveJob/Sidekiq/webhooks): a sink behind
     `perform_later`/`perform_async` only fires if a worker consumes the job.
     Check the queue adapter **and** that a worker actually runs — separate
     process *or* embedded-in-web (e.g. a puma `sidekiq_embed` plugin). No worker
     ⇒ not triggered; embedded worker ⇒ fires with no separate process to see.
   - One env flag often gates **multiple** security-relevant paths — map its full
     blast radius (DocuSeal's `multitenant?` disables the SSRF egress guard *and*
     enables the embedded worker: self-hosted default = guard off **and** worker
     on = auto-fires end-to-end).
2. **Intentional design or a forgotten check?** Prove intent from the repo:
   `git blame` the guard, grep whether the **same** pattern is applied
   consistently elsewhere (a sibling sink with the identical gate ⇒ a design
   stance, not an oversight), read upstream advisories / issues / SECURITY.md,
   and pin the role model (who can actually reach it — minimal rights). Vendor
   intended + precondition-gated is still real, but usually lower severity than
   an accidental hole.

Set severity to the **proven real-world exploitability** (precondition + minimal
rights + reachable impact), not the raw sink class. Record both verdicts in the
finding: `impact` = proven effect + minimal rights; note "vendor-intended, gated
on X" when so. A scanner's severity (or a bare CWE) is a lead, not the verdict —
it can be wrong in **both** directions.

## Routing table

| Code signal (grep / scanner lead) | Vuln class | Family | Playbook | Scanner lead source |
|---|---|---|---|---|
| string-concatenated SQL, ORM `.raw()`/`.extra()`/`createQuery("..."+` | SQLi | injection | sinks-<lang>.md | opengrep, bandit, brakeman, gosec |
| `exec/system/spawn/Runtime.exec` with tainted arg | OS cmd injection | injection | sinks-<lang>.md | opengrep, njsscan, gosec, bandit |
| `render_template_string`, `render inline:`, unsafe `${}`/`{{}}` | SSTI | injection | sinks-<lang>.md | opengrep |
| LDAP/XPath query built from input | LDAP/XPath inj | injection | sinks-<lang>.md | opengrep |
| `pickle/yaml.load/unserialize/ObjectInputStream/Marshal/gob` on input | insecure deserialization | deserialization | sinks-<lang>.md | opengrep, bandit |
| XML parser w/o secure-processing / entity resolution on | XXE | ssrf-xxe-file | sinks-<lang>.md | opengrep |
| HTTP client fed a user URL, no allowlist | SSRF | ssrf-xxe-file | sinks-<lang>.md | opengrep, gosec |
| `send_file`/`open`/`path.join(root,user)` with tainted path | LFI / path traversal | ssrf-xxe-file | sinks-<lang>.md | opengrep |
| object fetched by id with no owner/role check | IDOR / broken object-level authz | access-control | sinks-<lang>.md | manual (uses codemap entry_points+auth) |
| sensitive route with no role/`is_admin`/auth guard | broken function-level authz | access-control | sinks-<lang>.md | manual |
| `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, unescaped template | XSS | client-side | sinks-<lang>.md | opengrep, njsscan |
| `__proto__`/`constructor.prototype` merge | prototype pollution | client-side | sinks-<lang>.md | opengrep, njsscan |
| JWT `alg:none` / no `verify` / algorithms omitted / hardcoded secret | auth bypass | auth-session | sinks-<lang>.md | opengrep |
| weak session/cookie flags, predictable tokens | session weakness | auth-session | sinks-<lang>.md | opengrep |
| Host/CRLF header reflection, open redirect from param | header/redirect | http-protocol | sinks-<lang>.md | opengrep |
| hardcoded key/secret/token in source or git history | secret exposure | secrets-crypto | sinks-<lang>.md | **gitleaks, trufflehog, trivy** |
| MD5/SHA1 for passwords, DES/ECB, static IV, `InsecureSkipVerify`/`verify=False` | weak/misused crypto | secrets-crypto | sinks-<lang>.md | opengrep, trivy |
| vulnerable / loosely-pinned / typosquatted dependency | known-vuln dependency | supply-chain | (scanner) | **osv-scanner, trivy, grype** |
| Dockerfile runs root/`:latest`, IaC public bucket, `debug=True`, CI `pull_request_target`, unpinned action | misconfiguration | config-iac | (scanner) | **trivy config, hadolint, checkov** |

## Language sink packs

| Language / files | Playbook |
|---|---|
| C# / .NET (`*.cs`, `*.cshtml`, `*.razor`) | [sinks-csharp.md](sinks-csharp.md) |
| Go (`*.go`) | [sinks-go.md](sinks-go.md) |
| Java (`*.java`, `*.jsp`) | [sinks-java.md](sinks-java.md) |
| JavaScript / TypeScript | [sinks-js.md](sinks-js.md) |
| Kotlin / JVM (`*.kt`, `*.kts`) | [sinks-kotlin.md](sinks-kotlin.md) |
| PHP (`*.php`) | [sinks-php.md](sinks-php.md) |
| Python (`*.py`) | [sinks-python.md](sinks-python.md) |
| Ruby (`*.rb`, `*.erb`) | [sinks-ruby.md](sinks-ruby.md) |
| Rust (`*.rs`) | [sinks-rust.md](sinks-rust.md) |

## Baseline without scanners

Every `sinks-<lang>.md` ships a ripgrep sweep — the audit runs on `rg` + the LLM
auditor even with **zero** scanners installed. Scanners widen coverage
(especially the scanner-native families) but are not required for the trace
families.
