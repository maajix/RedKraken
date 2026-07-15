---
technique: "WebSocket Analysis in Burp"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/WebSocket Attacks/WebSocket Analysis in Burp.md"
source_sha256: "de7934fc4fd38f5cbf2e45db5587930afce608cc361630c97b747df54d91fdb7"
curator_version: 2
review_status: imported-unreviewed
---

# WebSocket Analysis in Burp

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- (no code blocks in this note)

## Playbook (operator notes)

# WebSocket Analysis in Burp

# **Inspecting Messages**

- Inspect data sent over WebSocket connections in the `WebSockets history` tab within the `Proxy`

# **Manipulating, Injecting, and Replaying Messages**

- Same as with normal http requests
- We can also use repeater as usually (either to server or to client)
- Burp also enables us to manipulate the WebSocket handshake, disconnect existing WebSocket connections, or establish new WebSocket connections
    - To do so, send any WebSocket message to Repeater. Afterward, we can disconnect the existing connection and re-connect by clicking the same icon
    
    
    
- To manipulate the handshake, click on the little pencil icon
    - Burp displays an overview of all past WebSocket connections and some meta information
    
    
    
    - We can select a different WebSocket connection for the message in Repeater and click `Attach` to send the message in the selected connection
    - Furthermore, we can click `clone` to establish a new WebSocket connection to the same server

## Source
Original note: `_raw/Web attacks/Web Attacks/WebSocket Attacks/WebSocket Analysis in Burp.md`
