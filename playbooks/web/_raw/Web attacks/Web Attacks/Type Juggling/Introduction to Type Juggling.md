# Introduction to Type Juggling

[Whitebox_Attacks_Module_Cheat_Sheet.pdf](Introduction%20to%20Type%20Juggling/Whitebox_Attacks_Module_Cheat_Sheet.pdf)

https://www.php.net/manual/en/language.operators.comparison.php#language.operators.comparison.types

In PHP, [type juggling](https://www.php.net/manual/en/language.types.type-juggling.php) is an internal behavior that results in the conversion of variables to other data types in certain contexts, such as comparisons. While this is not inherently a security vulnerability, it can result in unexpected or undesired outcomes, resulting in security vulnerabilities depending on the concrete web application.

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
| `null` | `string` | Convert `null` to `""` |
| `null` | anything but `string` | Convert both sides to `bool` |
| `bool` | anything | Convert both sides to `bool` |
| `int` | `string` | Convert `string` to `int` |
| `float` | `string` | Convert `string` to `float` |

For example, consider the comparison `1 == "1HelloWorld"` which evaluates to `true`. Since the first operand is an `int` and the second operand is a `string`, PHP converts the string to an integer. When converting `"1HelloWorld"` to an integer, the result is `1`. Thus, the comparison evaluates to true after type juggling.

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