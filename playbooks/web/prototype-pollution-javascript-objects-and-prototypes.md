---
technique: "JavaScript Objects & Prototypes"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Prototype Pollution/JavaScript Objects & Prototypes.md"
source_sha256: "6c71c45ee7d5a6d8d901c4bd281724e6c2a6adb982eb6af348e69cac2350d77b"
curator_version: 2
review_status: imported-unreviewed
---

# JavaScript Objects & Prototypes

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `jsx: >> module.toString()`
- `jsx: module.toString = function() {return "This is the HTB Academy module: " + this.name;}`

## Playbook (operator notes)

# JavaScript Objects & Prototypes

# **Objects in JavaScript**

- Objects bundle multiple datatypes in them
    - Those are called `properties` of the object
- `module = { name: "Web Attacks", author: "21y4d", tier: 2 }`
    - Object
    - Properties
- Access properties via `object.propertie` e.g. `module.name`
- We can create / add new properties in that object via `module.propertie = data`
    - We can add `functions` or other `objects` as properties as well
        
        
        

# **Prototypes in JavaScript**

- A pre-defined “template” of inheritance is always applied to existing objects
    - To provide basic functionallity
    - Implemented via [Object prototypes](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects/Object_prototypes)
- The prototype of an object is a reference to another object that is inherited from it
    - Each object inherits from a prototype
    - As such, the prototype of an object itself also has a prototype
    - Called the `prototype chain`
        
        ```jsx
        >> module.toString()
        
        "[object Object]"
        ```
        
- Our object inherits this property from the module object's prototype
    - The prototype of the `module` object is an object called `Object.prototype`
        
        
        
    - This is the base prototype that all created objects inherit
    - If we try to access a property that does not exist, the prototype is searched
        - If it does not exist there either the prototype of the prototype is searched, so on
        - If the full chain is searched and nothing was found, `undefined` is returned
- We can override properties to implement specific things our self
    - This process is called `shadowing`
        
        ```jsx
        module.toString = function() {return "This is the HTB Academy module: " + this.name;}
        ```

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution/JavaScript Objects & Prototypes.md`
