---
technique: "Hunting for SQL Errors"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Hunting for SQL Errors.md"
source_sha256: "8bab06384eccc53bcd4c304bf4cb0427f56f275053384476501244b6f29f3a90"
curator_version: 2
review_status: imported-unreviewed
---

# Hunting for SQL Errors

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `sql: find / -type f -name postgresql.conf 2>/dev/null`
- `sql: sudo systemctl restart postgresql`
- `sql: sudo watch -n 1 tail <log_directory>/postgresql-2023-02-14_081533.log`

## Playbook (operator notes)

# Hunting for SQL Errors

## **Enabling PostgreSQL Logging**

- Another way to identify the `SQL` queries which are run, as well as debug your payloads when developing an exploit is to enable `SQL logging`
- Find `postgresql.conf`
    - Usually it is located in `/etc/postgresql/<version>/main/`
    
    ```sql
    find / -type f -name postgresql.conf 2>/dev/null
    ```
    
- Change `#logging_collector = off` to `logging_collector = on`
    - This enables the logging collector background process [[source](https://postgresqlco.nf/doc/en/param/logging_collector/)]
- Chane `#log_statement = 'none'` to `log_statement = 'all'`
    - This makes it so all statement types (SELECT, CREATE, INSERT, ...) are logged [[source](https://postgresqlco.nf/doc/en/param/log_statement/)]
- Uncomment `#log_directory = '...'` to define the directory in which the logfiles will be saved [[source](https://postgresqlco.nf/doc/en/param/log_directory/)]
- Uncomment `#log_filename = '...'` to define the filename in which logfiles will be saved [[source](https://postgresqlco.nf/doc/en/param/log_filename/)]

```sql
sudo systemctl restart postgresql
```

- We can watch the log messages in near-realtime with the following command

```sql
sudo watch -n 1 tail <log_directory>/postgresql-2023-02-14_081533.log

<SNIP>
2023-02-14 09:06:04.819 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:04.819 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'bmdyy'
2023-02-14 09:06:10.423 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:10.423 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'admin'
2023-02-14 09:06:12.999 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:12.999 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'test'
2023-02-14 09:06:16.688 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:16.688 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'itsmaria'
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Hunting for SQL Errors.md`
