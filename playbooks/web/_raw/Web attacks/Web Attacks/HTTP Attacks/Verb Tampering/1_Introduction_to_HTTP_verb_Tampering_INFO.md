# 1_Introduction_to_HTTP_verb_Tampering_INFO

- Programmers mostly consider only `GET` and `POST`
- Web application can break if not developed to handle for example `HEAD` or `PUT`

## HTTP Verb Tampering

- Commonly used HTTP verbs

| Verb | Description |
| --- | --- |
| HEAD | Identical to a GET request, but its response only contains the `headers`, without the response body |
| PUT | Writes the request payload to the specified location |
| DELETE | Deletes the resource at the specified location |
| OPTIONS | Shows different options accepted by a web server, like accepted HTTP verbs |
| PATCH | Apply partial modifications to the resource at the specified location |

## Insecure Configurations

- Insecure web server configurations cause the first type of HTTP Verb Tampering vulnerabilities

```xml
<Limit GET POST>    Require valid-user</Limit>
```

- Attacker may still use other HTTP methods like `HEAD` which could bypass the authentication

## Insecure Coding

- This can occur when a web developer applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter
- For example, admin tries to fix a SQL injection by using a regex pattern which only looks for a GET method

```php
$pattern = "/^[A-Za-z\s]+$/";if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";    ...SNIP...
}
```