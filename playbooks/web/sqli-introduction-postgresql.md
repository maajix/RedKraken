---
technique: "Introduction PostgreSQL"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Introduction PostgreSQL.md"
source_sha256: "5d691401b55ac3d922889d84edb0373360e3bedd916715ebf646c90f54743329"
curator_version: 2
review_status: imported-unreviewed
---

# Introduction PostgreSQL

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: curl.

## Quick index — payloads & commands in this note
- `bash: sudo apt install postgresql-client-15`
- `bash: psql -h 127.0.0.1 [-p PORT] -U acdbuser acmecorp`
- `bash: psql -h 127.0.0.1 [-p PORT] -U acdbuser -l`
- `bash: acmecorp=> \l # or \l+ for more detail`
- `bash: \c <DATABASE>`
- `bash: acmecorp=> \dt+`
- `bash: acmecorp=> SELECT first_name, last_name, email FROM employees LIMIT 5;`
- `bash: curl -fsS https://www.pgadmin.org/static/packages_pgadmin_org.pub | sudo gpg --dearmor -o `
- `bash: SELECT * FROM dept_emp`
- `bash: acmecorp=> SELECT * FROM dept_emp INNER JOIN employees ON dept_emp.emp_id = employees.id L`
- `bash: SELECT * FROM salaries`

## Playbook (operator notes)

# Introduction PostgreSQL

# **Interacting with PostgreSQL**

- Most common tools for interacting [psql](https://www.postgresql.org/docs/current/app-psql.html) and [pgAdmin4](https://www.pgadmin.org/)

### **psql (PostgreSQL Interactive Terminal)**

- CLI tool that comes pre-packaged with PostgreSQL server and works on Linux and Windows

```bash
sudo apt install postgresql-client-15
```

<aside>
⚠️

Note: It's possible that the distribution of `Linux` you are running does not have version `15`. In that case, you can install version `13` and everything will work fine with minimally adapted steps.

</aside>

- Connect to a `PostgreSQL` database with the following command

```bash
psql -h 127.0.0.1 [-p PORT] -U acdbuser acmecorp

Password for user acdbuser: 
psql (15.1 (Debian 15.1-1+b1), server 13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

acmecorp=>
```

Or if we do not know the databases:

```bash
psql -h 127.0.0.1 [-p PORT] -U acdbuser -l
```

**List Databases**

```bash
acmecorp=> \l # or \l+ for more detail
                                             List of databases
   Name    |  Owner   | Encoding | Collate |  Ctype  | ICU Locale | Locale Provider |   Access privileges   
-----------+----------+----------+---------+---------+------------+-----------------+-----------------------
 acmecorp  | postgres | UTF8     | C.UTF-8 | C.UTF-8 |            | libc            | 
 postgres  | postgres | UTF8     | C.UTF-8 | C.UTF-8 |            | libc            | 
 template0 | postgres | UTF8     | C.UTF-8 | C.UTF-8 |            | libc            | =c/postgres          +
           |          |          |         |         |            |                 | postgres=CTc/postgres
 template1 | postgres | UTF8     | C.UTF-8 | C.UTF-8 |            | libc            | =c/postgres          +
           |          |          |         |         |            |                 | postgres=CTc/postgres
(4 rows)
```

**Switch Databses**

```bash
\c <DATABASE> 
```

**List Tables**

```bash
acmecorp=> \dt+
                                        List of relations
 Schema |    Name     | Type  |  Owner   | Persistence | Access method |    Size    | Description 
--------+-------------+-------+----------+-------------+---------------+------------+-------------
 public | departments | table | postgres | permanent   | heap          | 8192 bytes | 
 public | dept_emp    | table | postgres | permanent   | heap          | 72 kB      | 
 public | employees   | table | postgres | permanent   | heap          | 176 kB     | 
 public | salaries    | table | postgres | permanent   | heap          | 72 kB      | 
 public | titles      | table | postgres | permanent   | heap          | 80 kB      | 
(5 rows)
```

**Query the database** 

```bash
acmecorp=> SELECT first_name, last_name, email FROM employees LIMIT 5;
 first_name |  last_name  |           email           
------------+-------------+---------------------------
 Kathleen   | Flint       | knflint82@acme.corp
 Henry      | Watson      | hywatson40@acme.corp
 Ruth       | Perez       | rhperez84@acme.corp
 Leon       | Tappin      | lntappin80@acme.corp
 Donita     | Fairweather | dafairweather92@acme.corp
(5 rows)
```

### **pgAdmin4**

- Details
    - GUI application for Linux and Windows
    
    ```bash
    curl -fsS https://www.pgadmin.org/static/packages_pgadmin_org.pub | sudo gpg --dearmor -o /usr/share/keyrings/packages-pgadmin-org.gpghtb-student@htb[/htb]
    
    sudo sh -c 'echo "deb [signed-by=/usr/share/keyrings/packages-pgadmin-org.gpg] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/$(lsb_release -cs) pgadmin4 main" > /etc/apt/sources.list.d/pgadmin4.list && apt update'
    
    sudo apt install pgadmin4
    ```
    
    <aside>
    ⚠️
    
    Note: If you are using `Kali` or `ParrotOS` (like the `Pwnbox`), you will want to replace `$(lsb_release -cs)` in the second command with `bullseye`, otherwise the installation will fail.
    
    </aside>
    

---

### Reminder

**JOINS - Combine Tables and search for results**

<aside>
⚠️

The `WHERE` comes at the `END` as well as other operands!

</aside>

```bash
SELECT * FROM dept_emp 
INNER JOIN employees ON dept_emp.emp_id = employees.id 
WHERE dept_id=4 
ORDER BY hire_date desc 
LIMIT 5;
```

```bash
acmecorp=> SELECT * FROM dept_emp INNER JOIN employees ON dept_emp.emp_id = employees.id LIMIT 2;
 emp_id | dept_id | from_date  | to_date | id |  username  |        email         |                           password                           | first_name | last_name | birth_date | hire_date  
--------+---------+------------+---------+----+------------+----------------------+--------------------------------------------------------------+------------+-----------+------------+------------
      1 |       4 | 2022-10-11 |         |  1 | knflint82  | knflint82@acme.corp  | $2a$12$JsqAolSX2J3l.cMtBRlDo6VDcmLu0anDqzQF6AxmJUq8ykyBGhBE7 | Kathleen   | Flint     | 1999-09-14 | 2022-10-11
      2 |       4 | 2022-01-12 |         |  2 | hywatson40 | hywatson40@acme.corp | $2a$12$s74l8GBseV4MbvVRfds6wdqB9quk18zXzi9nQV8GArQCKUGXz8bj9 | Henry      | Watson    | 1993-12-12 | 2022-01-12
(2 rows)
```

Combines the tables, and we can then search in this new table

**Multi Table Example**

```bash
SELECT * FROM salaries 
INNER JOIN employees ON salaries.emp_id = employees.id 
INNER JOIN dept_emp ON dept_emp.emp_id = employees.id 
WHERE first_name='William' and dept_id=4
ORDER BY salary asc LIMIT 5;
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Introduction PostgreSQL.md`
