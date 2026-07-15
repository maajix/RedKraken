# PHP Sink Pack (Laravel / raw PHP)

## Sources
`$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES/$_SERVER`, `php://input`,
`request()->input()/all()/query()` (Laravel), route params, and DB rows re-used.

## Sinks
| Source→ | Sink (grep) | Vuln class | Family | Safe pattern |
|---|---|---|---|---|
| any str | `system(`, `exec(`, `shell_exec(`, `passthru(`, `popen(`, `proc_open(`, backticks | OS cmd inj | injection | `escapeshellarg`, avoid shell |
| any str | `eval(`, `assert(`, `create_function(`, `preg_replace('/e')` | code inj | injection | avoid dynamic eval |
| any str | dynamic `include`/`require`/`include_once` w/ user path | LFI/RCE | ssrf-xxe-file | allowlist, no user paths |
| any str | `unserialize(` on input | insecure deser | deserialization | `json_decode`; allowed_classes=[] |
| any str | `mysqli_query("..."+`, `$pdo->query("..."`, `$wpdb->query(` concat, `->whereRaw(` | SQLi | injection | prepared stmts / bindings |
| any arr | `extract(` on request data | var overwrite | injection | never on untrusted |
| url | `file_get_contents(user)`, `curl_setopt(...URL,user)`, `fopen(user)` | SSRF/LFI | ssrf-xxe-file | allowlist scheme+host |
| xml | `simplexml_load_*`/`DOMDocument->load` w/o `LIBXML_NONET`/disable entities | XXE | ssrf-xxe-file | `libxml_disable_entity_loader`(<8), no DTD |
| file | `move_uploaded_file(` w/o type/ext check, user-controlled dest | upload → RCE | ssrf-xxe-file | validate type, random name, non-exec dir |
| auth | `==` / `strcmp` loose compare on secrets, `md5(`/`sha1(` password | type juggling / weak crypto | secrets-crypto / auth-session | `===`/`hash_equals`, `password_hash` |
| — | hardcoded key/secret/token literals, `.env` committed | secret exposure | secrets-crypto | env/secret store |
| id param | `Model::find($id)` with no policy/gate | IDOR | access-control | Laravel policies / gates |

## Ripgrep sweep
```
rg -n --no-heading -g '*.php' \
  -e '\bsystem\(' -e '\bexec\(' -e 'shell_exec\(' -e 'passthru\(' -e 'popen\(' -e 'proc_open\(' \
  -e '\beval\(' -e '\bassert\(' -e 'create_function\(' \
  -e '(include|require)(_once)?\s*\(?\s*\$' -e '\bunserialize\(' -e '\bextract\(' \
  -e 'whereRaw\(' -e 'mysqli_query\(' -e '->query\(' \
  -e 'file_get_contents\(\s*\$' -e 'move_uploaded_file\(' \
  -e 'simplexml_load|DOMDocument' -e 'md5\(|sha1\(' -e '==\s*\$_' -e 'strcmp\(' \
  <src>
```

## Confirm
A grep hit is a **lead**. Promote to `confirmed` only after reading the code and
tracing a request-controlled source to the sink with no sanitizer; record the
`file:line` chain in `dataflow` + a `code_excerpt`. Watch for `==` type-juggling
auth bypass (`0e...` magic hashes) — confirm with the compared value's origin.
