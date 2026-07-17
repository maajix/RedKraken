---
name: injection-attacks
description: Triage and exploit server-side injection — SQLi (incl. MSSQL/PostgreSQL, blind/time/error/second-order/OOB), NoSQL, LDAP, XPath, OS command injection, and SSTI. Use when an endpoint/param is a candidate for injection (numeric/id params, search, login, template-rendered output, LDAP/XPath auth).
---

# Injection Family

Covers: **SQLi**, **NoSQL/operator injection**, **ORM relational-filter leaks**,
**LDAP injection**, **XPath injection**, **OS command injection**, **SSTI
including error oracles**, **XML/XSLT/expression/format/second-order injection**,
and **CSV/spreadsheet formula injection**. Open the
precise playbook before acting: prefer matching `playbooks/modern/` cards, then
look the technique up in `playbooks/web/_catalog.md` → read
`playbooks/web/<file>.md`. Obey `scope-guard` +
`tool-preflight`.

## Signals → technique

| Signal | Try |
|--------|-----|
| numeric/`id`/filter param, DB-backed app, SQL errors | SQLi (error→boolean→time→OOB) |
| login/search returns logic differences | SQLi auth-bypass, NoSQL (`[$ne]`, `[$gt]`) |
| param reflected into rendered output (`{{7*7}}`→49) | SSTI |
| auth/search against a directory service | LDAP / XPath injection |
| param flows into a shell/ping/convert feature | OS command injection |

## Detection → confirmation → escalation

1. **SQLi.** Manual first: `'`, `' OR '1'='1`, true/false pairs (`AND 1=1` vs `AND 1=2`), then time (`SLEEP(5)` / `pg_sleep` / `WAITFOR DELAY`). Confirm with a controlled boolean/time difference you actually observe. Then `sqlmap -u '<url>' -p <param> --batch --threads <max_threads> --level 3 --risk 2` (honor rate limit). DB-specifics: MSSQL `xp_cmdshell`/NetNTLM leak, PostgreSQL `COPY ... PROGRAM` (RCE), file read/write — all in the SQLi playbooks. OOB via `oob_host` when blind.
2. **NoSQL.** Load `nosql-operator-injection.md`; vary scalar/object/array/null
   and one harmless operator against synthetic positive/negative records. Require
   a stable query or authorization differential; never enumerate production data.
3. **SSTI.** Load `playbooks/modern/ssti-error-oracles.md`. Identify the engine
   with harmless render, syntax, error-based, and boolean-error pairs, including
   blind contexts. Confirm with a synthetic canary; engine-specific file/command
   access is exploitation and remains RoE-gated.
4. **LDAP / XPath.** `*)(uid=*))(|(uid=*` style auth bypass; blind char-by-char exfiltration per the playbook.
5. **OS command injection.** Separators (`;`,`|`,`&&`,`$( )`, backticks, newline), blind via time delay or OOB DNS; then controlled command. `commix` as a power tool.
6. **ORM filters.** When request objects shape `where`/filter/include/select/order
   clauses, load `orm-relational-filter-leaks.md`; test relation and operator
   oracles against a synthetic hidden value without enumerating production data.
7. **Spreadsheet output.** Load `spreadsheet-formula-injection.md`; inspect raw
   CSV/workbook cells before opening a disposable export offline. Never use DDE,
   commands, external links, or callbacks as the default proof.
8. **Structured/delayed interpreters.** Load
   `structured-interpreter-injection.md`; trace representations across storage to
   the final XML/XSLT, expression, SSI/ESI, format, rule, or query interpreter and
   prove only a literal, boolean, or arithmetic effect by default.

## Evidence
Save the request + the distinguishing response (boolean diff, timing, extracted data, command output) to `evidence/<id>/`. For destructive steps (writes, RCE, `xp_cmdshell`) require `destructive_allowed`; otherwise stop at a read-only PoC and mark `exploitable-not-detonated`.
