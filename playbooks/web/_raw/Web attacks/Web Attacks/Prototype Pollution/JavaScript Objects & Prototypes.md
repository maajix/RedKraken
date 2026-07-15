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
        
        ![image.png](JavaScript%20Objects%20&%20Prototypes/image.png)
        

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
        
        ![image.png](JavaScript%20Objects%20&%20Prototypes/image%201.png)
        
    - This is the base prototype that all created objects inherit
    - If we try to access a property that does not exist, the prototype is searched
        - If it does not exist there either the prototype of the prototype is searched, so on
        - If the full chain is searched and nothing was found, `undefined` is returned
- We can override properties to implement specific things our self
    - This process is called `shadowing`
        
        ```jsx
        module.toString = function() {return "This is the HTB Academy module: " + this.name;}
        ```