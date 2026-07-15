# WebSocket Analysis in Burp

![Untitled](WebSocket%20Analysis%20in%20Burp/Untitled.png)

# **Inspecting Messages**

- Inspect data sent over WebSocket connections in the `WebSockets history` tab within the `Proxy`

![Untitled](WebSocket%20Analysis%20in%20Burp/Untitled%201.png)

# **Manipulating, Injecting, and Replaying Messages**

- Same as with normal http requests
- We can also use repeater as usually (either to server or to client)
- Burp also enables us to manipulate the WebSocket handshake, disconnect existing WebSocket connections, or establish new WebSocket connections
    - To do so, send any WebSocket message to Repeater. Afterward, we can disconnect the existing connection and re-connect by clicking the same icon
    
    ![Untitled](WebSocket%20Analysis%20in%20Burp/Untitled%202.png)
    
- To manipulate the handshake, click on the little pencil icon
    - Burp displays an overview of all past WebSocket connections and some meta information
    
    ![Untitled](WebSocket%20Analysis%20in%20Burp/Untitled%203.png)
    
    - We can select a different WebSocket connection for the message in Repeater and click `Attach` to send the message in the selected connection
    - Furthermore, we can click `clone` to establish a new WebSocket connection to the same server