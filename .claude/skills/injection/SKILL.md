---
name: injection-attacks
description: Triage and exploit server-side injection — SQLi (incl. MSSQL/PostgreSQL, blind/time/error/second-order/OOB), NoSQL, LDAP, XPath, OS command injection, and SSTI. Use when an endpoint/param is a candidate for injection (numeric/id params, search, login, template-rendered output, LDAP/XPath auth).
---

# Injection Family

Covers: **SQLi**, **NoSQL/operator injection**, **ORM relational-filter leaks**,
**LDAP injection**, **XPath injection**, **OS command injection**, **SSTI
including error oracles**, **XML/XSLT/expression/format/second-order injection**,
and **CSV/spreadsheet formula injection**. Look the signal up in
`playbooks/_catalog.md`, open the routed topic `README.md` first, then consult
its sibling imported reference only when payload depth is needed. Obey `scope-guard` +
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

1. **SQLi.** Load `playbooks/sql-injection/README.md`. Establish a repeated manual
   true/false or error pair first. Save the exact redacted HTTP request, mark one
   injection point with `*` or one explicit `-p`, then replay with `sqlmap -r`,
   `--parse-errors`, `-t <engagement>/state/scan-raw/sqlmap-traffic.txt`,
   `--threads 1 --level 1 --risk 1`, bounded techniques/time, and native rate
   controls only when enabled. Write full output under `state/scan-raw/`; read a
   redacted bounded summary. Tor, external proxy lists, generic WAF evasion, bulk
   dumps, file write/read, credential extraction, and OS execution are not
   default detection and require explicit RoE escalation.
2. **NoSQL.** Load `playbooks/nosql-injection/README.md`; vary scalar/object/array/null
   and one harmless operator against synthetic positive/negative records. Require
   a stable query or authorization differential; never enumerate production data.
3. **SSTI.** Load `playbooks/ssti/README.md`. Identify the engine
   with harmless render, syntax, error-based, and boolean-error pairs, including
   blind contexts. Confirm with a synthetic canary; engine-specific file/command
   access is exploitation and remains RoE-gated.
4. **LDAP / XPath.** `*)(uid=*))(|(uid=*` style auth bypass; blind char-by-char exfiltration per the playbook.
5. **OS command injection.** Separators (`;`,`|`,`&&`,`$( )`, backticks, newline), blind via time delay or OOB DNS; then controlled command. `commix` as a power tool.
6. **ORM filters.** When request objects shape `where`/filter/include/select/order
   clauses, load `playbooks/orm/README.md`; test relation and operator
   oracles against a synthetic hidden value without enumerating production data.
7. **Spreadsheet output.** Load `playbooks/spreadsheet-injection/README.md`; inspect raw
   CSV/workbook cells before opening a disposable export offline. Never use DDE,
   commands, external links, or callbacks as the default proof.
8. **Structured/delayed interpreters.** Load
   `playbooks/structured-injection/README.md`; trace representations across storage to
   the final XML/XSLT, expression, SSI/ESI, format, rule, or query interpreter and
   prove only a literal, boolean, or arithmetic effect by default.

## Evidence
Save the request and least-sensitive distinguishing response. Writes require
`mutation_allowed`; real data reads require `sensitive_data_access_allowed`;
discovered credential use requires `credential_use_allowed`; cross-service access
requires `pivoting_allowed`; load/timing techniques with material service impact
require `availability_impact_allowed`. Otherwise stop at a synthetic read-only PoC
and mark `exploitable-not-detonated`.
