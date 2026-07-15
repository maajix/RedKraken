# Tools & Prevention

# **Tools - Interacting with WebSockets**

Instead of using Burp to manipulate and replay WebSocket messages, command-line tools such as [wscat](https://github.com/websockets/wscat) and [websocat](https://github.com/vi/websocat) provide similar functionality. We will showcase `websocat` here, but feel free to play around with both tools and choose which one you prefer.

We can install `websocat` by downloading a precompiled binary from the [GitHub repository](https://github.com/vi/websocat/releases/tag/v1.11.0); on the default `PwnBox` instance, we need the `websocat_max.x86_64-unknown-linux-musl` build.

Afterward, we have to make the binary executable and run it:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ chmod +x websocat_max.x86_64-unknown-linux-muslmaxrandhahn@htb[/htb]$ ./websocat_max.x86_64-unknown-linux-musl -hwebsocat 1.11.0
Vitaly "_Vi" Shukela <vi0oss@gmail.com>
Command-line client for web sockets, like netcat/curl/socat for ws://.

USAGE:
    websocat ws://URL | wss://URL               (simple client)
    websocat -s port                            (simple server)
    websocat [FLAGS] [OPTIONS] <addr1> <addr2>  (advanced mode)
<SNIP>

```

We can specify a WebSocket URL for the tool to connect to:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ ./websocat_max.x86_64-unknown-linux-musl ws://172.17.0.2/echoHello EchoServer!
Hello EchoServer!

```

For more advanced features, check out the tool's help menu by running the command `websocat --help=long`.

---

# **Tools - Vulnerability Detection**

[Security Testing and Enumeration of WebSockets (STEWS)](https://github.com/PalindromeLabs/STEWS) is a tool suite that can help us fingerprint and identify WebSocket libraries and test for CSWH vulnerabilities. We will focus on the fingerprinting and vulnerability detection modules provided in the `fingerprint` and `vuln-detect` directories.

### **Fingerprinting**

To use the `fingerprinting` module, we change directories to `fingerprint` and then install the dependencies using `pip`:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ pip3 install -r requirements.txt
```

Subsequently, we can run the tool using Python:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ python3 STEWS-fingerprint.py -husage: STEWS-fingerprint.py [-h] [-v] [-d] [-u URL] [-f FILE] [-n] [-k] [-o ORIGIN] [-g] [-a] [-1] [-2] [-3] [-4] [-5] [-6] [-7]

Security Testing and Enumeration of WebSockets (STEWS) Fingerprinting Tool

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose tracing of communications
  -d, --debug           Print each test case to track progress while running
  -u URL, --url URL     Provide a URL to connect to
  -f FILE, --file FILE  Provide a file containing URLs to check for valid WebSocket connections
  -n, --no-encryption   Connect using ws://, not wss:// (default is wss://)
  -k, --nocert          Ignore invalid SSL cert
  -o ORIGIN, --origin ORIGIN
                        Set origin
  -g, --generate-fingerprint
                        Generate a fingerprint for a known server
  -a, --all-tests       Run all tests
  -1, --series-100      Run the 100-series (opcode) tests
  -2, --series-200      Run the 200-series (rsv bit) tests
  -3, --series-300      Run the 300-series (version) tests
  -4, --series-400      Run the 400-series (extensions) tests
  -5, --series-500      Run the 500-series (subprotocols) tests
  -6, --series-600      Run the 600-series (long payloads) tests
  -7, --series-700      Run the 700-series (hybi and similar) tests

```

`STEWS` tests and analyzes different properties of a WebSocket connection to try and determine the specific implementation used by the web server. Knowing the exact WebSocket implementation allows attackers to prepare specialized attacks that target it. We can run `STEWS` with all tests using the `-a` flag or specify a subset of tests using the `-1` through `-7` flags. The tool expects the URL passed in the `-u` parameter not to contain the scheme ( i.e., no `http://` or `https://`).

As an example, let us run the tool's series `5` tests on the CSWH lab from the previous section:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ python3 STEWS-fingerprint.py -u websockets.htb/messages -n -5=======================================================
Identifying...
=======================================================
List of deltas between detected fingerprint and those in database
[2, 0, 0, 2, 0, 0, 2, 0]
=======================================================
>>>Most likely server: Faye, Gorilla, Java Spring boot, Python websockets, Python Tornado -- % match: 100.0
>>>Second most likely server: NodeJS ws, uWebSockets, Ratchet -- % match: 0.0
=======================================================
Most likely server's fingerprint:
{'100': 1, '101': 1, '102': 0, '103': 0, '104': 'Received unexpected continuation frame', '105': 1, '200': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '201': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '202': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '203': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '204': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '205': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '206': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '300': 1, '301': 1, '302': 1, '303': 1, '304': 1, '305': 1, '306': 0, '307': 1, '308': 1, '309': 0, '310': 0, '400': 0, '401': 0, '402': 0, '403': 0, '404': 0, '405': 0, '500': 0, '501': 0, '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 1, '606': 1, '607': 1, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0, '700': 'Unsupported WebSocket version', '701': 'Not a WebSocket request', '702': '400', '703': '101', '704': 'yTFHc]O', '705': '101'}
=======================================================
Tested server's fingerprint:
{'500': 0, '501': 0}

```

We can see that `STEWS` determined the WebSocket implementation to be one of the following: `Faye`, `Gorilla`, `Java Spring boot`, `Python websockets`, or `Python Tornado`.

However, the actual WebSocket implementation belongs to the `flask_sock` Python package; however, since it is unknown to `STEWS`, it cannot determine the library correctly. We can confirm this by running a different test series and observing an entirely different result:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ python3 STEWS-fingerprint.py -u websockets.htb/messages -n -4=======================================================
Identifying...
=======================================================
List of deltas between detected fingerprint and those in database
[6, 6, 6, 6, 0, 6, 6, 6]
=======================================================
>>>Most likely server: Java Spring boot -- % match: 100.0
>>>Second most likely server: NodeJS ws, Faye, Gorilla, uWebSockets, Python websockets, Ratchet, Python Tornado -- % match: 0.0
=======================================================
Most likely server's fingerprint:
{'100': 0, '101': 0, '102': 0, '103': 0, '104': 'A WebSocket frame was sent with an unrecognised opCode of [0]', '105': 'The client sent a close frame with a single byte payload which is not valid', '200': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '201': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '202': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '203': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '204': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '205': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '206': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '300': 0, '301': 0, '302': 0, '303': 0, '304': 0, '305': 0, '306': 1, '307': 0, '308': 0, '309': 0, '310': 0, '400': 'permessage-deflate', '401': 'permessage-deflate', '402': 'permessage-deflate', '403': 'permessage-deflate', '404': 'permessage-deflate', '405': 'permessage-deflate', '500': 0, '501': 0, '600': 0, '601': 0, '602': 0, '603': 0, '604': 0, '605': 0, '606': 0, '607': 0, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0, '700': '426', '701': 'Can "Upgrade" only to "WebSocket".', '702': 'Bad Request', '703': '403', '704': 'Bad Request', '705': 'Bad Request'}
=======================================================
Tested server's fingerprint:
{'400': 'permessage-deflate', '401': 'permessage-deflate', '402': 'permessage-deflate', '403': 'permessage-deflate', '404': 'permessage-deflate', '405': 'permessage-deflate'}

```

### **Vulnerability Detection**

Similar to the `fingerprinting` module, we need to install the dependencies for the `vulnerability detection` module using `pip`. Afterward, we can run `STEWS` to test for CSWH vulnerabilities and some public vulnerabilities in specific WebSocket implementations.

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ python3 STEWS-vuln-detect.py -husage: STEWS-vuln-detect.py [-h] [-v] [-d] [-u URL] [-f FILE] [-n] [-k] [-o ORIGIN] [-1] [-2] [-3] [-4]

Security Testing and Enumeration of WebSockets (STEWS) Vulnerability Detection Tool

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose tracing of communications
  -d, --debug           Print each test case to track progress while running
  -u URL, --url URL     URL to connect to
  -f FILE, --file FILE  File containing URLs to check for valid WebSocket connections
  -n, --no-encryption   Connect using ws://, not wss:// (default is wss://)
  -k, --nocert          Ignore invalid SSL cert
  -o ORIGIN, --origin ORIGIN
                        Set origin
  -1                    Test for generic Cross-site WebSocket Hijacking (CSWSH)
  -2                    Test CVE-2021-32640 - ws Sec-Websocket-Protocol Regex DoS
  -3                    Test CVE-2020-7662 & 7663 - faye Sec-WebSocket-Extensions Regex DoS
  -4                    Test CVE-2020-27813 - Gorilla DoS Integer Overflow

```

Again, we will use `STEWS` on the CSWH lab from the previous section to check if it can identify the CSWH vulnerability:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ python3 STEWS-vuln-detect.py -n -u websockets.htb/messages -1   Testing ws://websockets.htb/messages
>>>Note: ws://websockets.htb/messages allowed http or https for origin
>>>Note: ws://websockets.htb/messages allowed null origin
>>>Note: ws://websockets.htb/messages allowed unusual char (possible parse error)
>>>VANILLA CSWSH DETECTED: ws://websockets.htb/messages likely vulnerable to vanilla CSWSH (any origin)
====Full list of vulnerable URLs===
['ws://websockets.htb/messages']
['>>>VANILLA CSWSH DETECTED: ws://websockets.htb/messages likely vulnerable to vanilla CSWSH (any origin)']

```

As we can see from the output, `STEWS` correctly identified the CSWH vulnerability; however, it only checks different origins. Therefore, it cannot determine CSWH vulnerabilities that do not rely on checking the `Origin` header. To get more details about the requests sent, we can add the debug flag `-d`:

WebSocket Attacks: Tools & Prevention

```
maxrandhahn@htb[/htb]$ python3 STEWS-vuln-detect.py -n -u websockets.htb/messages -1 -d<SNIP>
-----------START-----------
GET http://websockets.htb/messages
Upgrade: websocket
Origin: null
Sec-WebSocket-Key: U2NqiNJpRpRGdvagcfySUA==
Connection: Upgrade
Sec-WebSocket-Version: 13

Response status code: 101
-----------START-----------
GET http://websockets.htb/messages
Upgrade: websocket
Origin: https://websockets.htb`google.com
Sec-WebSocket-Key: U2NqiNJpRpRGdvagcfySUA==
Connection: Upgrade
Sec-WebSocket-Version: 13

Response status code: 101
<SNIP>

```

For more details on WebSocket security, check out [this](https://github.com/PalindromeLabs/awesome-websocket-security) GitHub repository.

---

# **Prevention**

Different WebSocket vulnerabilities have different methods of prevention. Preventing the CSRF attack on the WebSocket handshake prevents CSWH attacks. Potential countermeasures include checking the [Origin header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin), implementing CSRF tokens, or secure configuration of the [SameSite](https://web.dev/i18n/en/samesite-cookies-explained/) cookie flag.

Furthermore, there are some general security considerations we should follow when implementing WebSocket connections:

- Always prefer the `wss://` scheme over `ws://` due to the security provided by TLS
- Sanitize data received over WebSocket connections accordingly, just like we sanitize data received in HTTP requests. The sanitization needs to correspond to the purpose of the data received, for instance, if used in SQL queries or inserted into the DOM to prevent XSS. In particular, the data needs to be treated as untrusted in both directions, i.e., the server should not trust data received by the client, and the client should not trust data received by the server