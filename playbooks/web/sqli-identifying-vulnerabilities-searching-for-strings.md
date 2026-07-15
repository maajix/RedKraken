---
technique: "Searching for Strings"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Searching for Strings.md"
source_sha256: "b024ddda4a2aaaa74ef9abfb1a037157ef1f6554ebd865c1991aa3456bd730a9"
curator_version: 2
review_status: imported-unreviewed
---

# Searching for Strings

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: grep -irnE 'SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP' .`

## Playbook (operator notes)

# Searching for Strings

## **RegEx**

- In this case we are interested especially in SQL injections but we can search for any vulnerabilities
- **Usefull to take notes of the used libraries and coding style so we can adapt our search**

| Query | Description |
| --- | --- |
| `SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP` | Search for the basic SQL commands. Injection can occur in more than 
just SELECT statements, exploitation may just be a bit trickier. |
| `(WHERE|VALUES).*?'` | Search for strings which include `WHERE` or `VALUES` and then a `single quote`, which could indicate a string concatenation. |
| `(WHERE|VALUES).*" \+` | Search for strings which include `WHERE` or `VALUES` followed by a double quote and a plus sign, which could indicate a string concatenation. |
| `.*sql.*"` | Search for lines which include `sql` and then a `double quote`. |
| `jdbcTemplate` | Search for lines which include `jdbcTemplate`. There are various ways to interact with `SQL` databases in `Java`. `JdbcTemplate` is one of them; others include `JPA` and `Hibernate`. |

## **Grep**

- `grep -E <RegEx> <File>`
    - Enhancements
        - `--include *.java` to only search for matches in `.java` files
        - `-n` to display line numbers
        - `-i` to ignore case
        - `-r` to search recursively through a directory

```bash
grep -irnE 'SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP' .
```

## **Visual Studio Code**

## Example Finding

<aside>
⚠️

Note: If you don't know what `controllers` are, you can imagine them as API endpoints.

</aside>

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Searching for Strings.md`
