---
technique: "Intro to MSSQL/SQL Server"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Intro to MSSQL SQL Server.md"
source_sha256: "a2577c6938f99731c2031ae3973f87412dd35e37879332523036d660274e1ca5"
curator_version: 2
review_status: imported-unreviewed
---

# Intro to MSSQL/SQL Server

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `powershell: PS C:\htb> sqlcmd -S 'SQL01' -U 'thomas' -P 'TopSecretPassword23!' -d bsqlintro -W`
- `powershell: PS C:\htb> sqlcmd -S 'SQL01' -U 'thomas' -P 'TopSecretPassword23!' -d bsqlintro -W`
- `python: impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintro`
- `python: impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintro`
- `bash: impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintroImpacket v0.10.0 - C`
- `sql: **SELECT * from users u`

## Playbook (operator notes)

# Intro to MSSQL/SQL Server

## **Interacting with MSSQL**

---

### **SQLCMD (Windows, Command Line)**

```powershell
PS C:\htb> sqlcmd -S 'SQL01' -U 'thomas' -P 'TopSecretPassword23!' -d bsqlintro -W
1>
```

```powershell
PS C:\htb> sqlcmd -S 'SQL01' -U 'thomas' -P 'TopSecretPassword23!' -d bsqlintro -W
1> SELECT *
2> FROM INFORMATION_SCHEMA.TABLES;
3> GO
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME TABLE_TYPE
------------- ------------ ---------- ----------
bsqlintro dbo users BASE TABLE
bsqlintro dbo posts BASE TABLE

(2 rows affected)
1> SELECT TOP 5 users.firstName, users.lastName, posts.title
2> FROM users
3> JOIN posts
4> ON users.id=posts.authorId;
5> GO
firstName lastName title
--------- -------- -----
Edward Strong Voluptatem neque labore dolore velit ut.
David Ladieu Etincidunt etincidunt adipisci sed consectetur.
Natasha Ingham Aliquam quiquia velit non aliquam sed sit etincidunt.
Jessica Fitzpatrick Dolor porro quiquia labore numquam numquam sit.
Mary Evans Tempora sed velit consectetur labore consectetur.

(5 rows affected)
```

### **Impacket-MSSQLClient (Linux, Command Line)**

[https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)

```python
impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintro
```

```python
impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintro
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: bsqlintro
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01): Line 1: Changed database context to 'bsqlintro'.
[*] INFO(SQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> SELECT * FROM INFORMATION_SCHEMA.TABLES;

TABLE_CATALOG                                                          TABLE_SCHEMA                                                          TABLE_NAME                                                          TABLE_TYPE
-----------------------------------------------------------   -----------------------------------------------------------   -----------------------------------------------------------   -----------------------------------------------------------
bsqlintro                                                           dbo                                                               users                                                          b'BASE TABLE'   
bsqlintro                                                           dbo                                                               posts                                                          b'BASE TABLE'   

SQL> SELECT TOP 5 users.firstName, users.lastName, posts.title FROM users JOIN posts ON users.id=posts.authorId;
firstName                                                              lastName                                                              title
-----------------------------------------------------------   -----------------------------------------------------------   -----------------------------------------------------------   
b'Edward'                                                          b'Strong'                                                          b'Voluptatem neque labore dolore velit ut.'
b'David'                                                           b'Ladieu'                                                          b'Etincidunt etincidunt adipisci sed consectetur.'
b'Natasha'                                                         b'Ingham'                                                          b'Aliquam quiquia velit non aliquam sed sit etincidunt.'
b'Jessica'                                                         b'Fitzpatrick'                                                     b'Dolor porro quiquia labore numquam numquam sit.'
b'Mary'                                                            b'Evans'                                                           b'Tempora sed velit consectetur labore consectetur.'

SQL> exit
```

Since this is a pentest tool it has some features that help us attack MSSQL

```bash
impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintroImpacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: bsqlintro
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01): Line 1: Changed database context to 'bsqlintro'.
[*] INFO(SQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands

SQL> enable_xp_cmdshell
[*] INFO(SQL01): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(SQL01): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.

SQL> xp_cmdshell whoami
exitoutput

------------------
NT SERVICE\mssqlserver
NULL

SQL> exit
```

### **SQL Server Management Studio (Windows, GUI)**

**Lab Solve**

```sql

**SELECT * from users u 
where u.id IN(
	SELECT p.authorid FROM posts p WHERE p.title LIKE 'N%'
) 
and u.firstname LIKE 's%' 
and LEN(email) > 20 
ORDER BY u.firstname asc**
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Intro to MSSQL SQL Server.md`
