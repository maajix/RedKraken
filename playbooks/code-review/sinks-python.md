# Python Sink Pack (Django / Flask / FastAPI)

## Sources
`request.args/.form/.values/.json/.data/.files/.headers/.cookies` (Flask),
`request.GET/.POST/.body/.META/.FILES` (Django), path/query/body params &
Pydantic models (FastAPI), `os.environ`, CLI `sys.argv`, and DB rows re-used in
queries (second-order).

## Sinks
| Source→ | Sink (grep) | Vuln class | Family | Safe pattern |
|---|---|---|---|---|
| any str | `subprocess.*shell=True`, `os.system(`, `os.popen(`, `commands.` | OS cmd inj | injection | list argv, `shell=False` |
| any str | `eval(`, `exec(`, `compile(` | code inj | injection | avoid; `ast.literal_eval` |
| any str | `pickle.load(`, `cPickle`, `yaml.load(` (no `SafeLoader`), `dill`, `marshal.loads` | insecure deser | deserialization | `yaml.safe_load`, json |
| any str | `.raw(`, `.extra(`, `cursor.execute(f"..."`, `execute("..."% `, `"..."+ ` in SQL | SQLi | injection | parameterized `execute(sql,(p,))` |
| any str | `render_template_string(`, `Template(...).render(`, `Environment(...).from_string` | SSTI | injection | static templates, autoescape on |
| path | `send_file(`, `send_from_directory(` (unchecked), `open(` w/ user path, `os.path.join(root,user)` | LFI / traversal | ssrf-xxe-file | `werkzeug.utils.safe_join`, allowlist |
| url | `requests.get/post(user)`, `urllib.*urlopen(user)`, `httpx.get(user)` | SSRF | ssrf-xxe-file | allowlist host; block internal/link-local |
| xml | `lxml.etree.parse`, `xml.dom.minidom`, `etree` w/ `resolve_entities=True` | XXE | ssrf-xxe-file | `defusedxml` |
| id param | `Model.objects.get(pk=id)` / `.query.get(id)` with no owner/role check | IDOR | access-control | enforce object-level authz |
| route | view/endpoint with no `@login_required`/permission check | broken authz | access-control | decorator/dependency guard |
| — | `hashlib.md5(`/`sha1(` for passwords, `DES`, `MODE_ECB`, static IV, `verify=False` | weak crypto | secrets-crypto | bcrypt/argon2; TLS verify on |
| — | hardcoded `SECRET_KEY`/`AWS_`/`token=`/`password=` literals | secret exposure | secrets-crypto | env/secret store |
| — | `app.run(debug=True)`, `DEBUG = True`, `jsonify` of stack traces | config | config-iac | disable debug in prod |

## Ripgrep sweep
```
rg -n --no-heading -g '*.py' \
  -e 'shell=True' -e 'os\.system\(' -e 'os\.popen\(' -e '\beval\(' -e '\bexec\(' \
  -e 'pickle\.load' -e 'yaml\.load\(' -e 'marshal\.loads' \
  -e '\.raw\(' -e '\.extra\(' -e 'cursor\.execute\(f' -e 'execute\(.*%' \
  -e 'render_template_string' -e 'send_file\(' -e 'os\.path\.join\(' \
  -e 'requests\.(get|post)\(' -e 'urlopen\(' \
  -e 'md5\(|sha1\(' -e 'verify=False' -e 'DEBUG\s*=\s*True' -e 'SECRET_KEY\s*=' \
  <src>
```

## Confirm
A grep hit is a **lead**. Promote to `confirmed` only after reading the code and
tracing a request-controlled source to the sink with no effective sanitizer;
record the `file:line` chain in `dataflow` and a `code_excerpt`. Weak-crypto /
hardcoded-secret / debug hits are `secrets-crypto`/`config-iac` and can be
confirmed by the code fact itself (still cite file:line).
