# Searching for Strings

## **RegEx**

- In this case we are interested especially in SQL injections but we can search for any vulnerabilities
- **Usefull to take notes of the used libraries and coding style so we can adapt our search**

| Query | Description |
| --- | --- |
| `SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP` | Search for the basic SQL commands. Injection can occur in more than 
just SELECT statements, exploitation may just be a bit trickier. |
| `(WHERE|VALUES).*?'` | Search for strings which include `WHERE` or `VALUES` and then a `single quote`, which could indicate a string concatenation. |
| `(WHERE|VALUES).*" \+` | Search for strings which include `WHERE` or `VALUES` followed by a double quote and a plus sign, which could indicate a string concatenation. |
| `.*sql.*"` | Search for lines which include `sql` and then a `double quote`. |
| `jdbcTemplate` | Search for lines which include `jdbcTemplate`. There are various ways to interact with `SQL` databases in `Java`. `JdbcTemplate` is one of them; others include `JPA` and `Hibernate`. |

## **Grep**

- `grep -E <RegEx> <File>`
    - Enhancements
        - `--include *.java` to only search for matches in `.java` files
        - `-n` to display line numbers
        - `-i` to ignore case
        - `-r` to search recursively through a directory

```bash
grep -irnE 'SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP' .
```

## **Visual Studio Code**

![image.png](Searching%20for%20Strings/image.png)

## Example Finding

![image.png](Searching%20for%20Strings/image%201.png)

![image.png](Searching%20for%20Strings/image%202.png)

<aside>
⚠️

Note: If you don't know what `controllers` are, you can imagine them as API endpoints.

</aside>