---
technique: "Introduction to Prototype Pollution"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Prototype Pollution/Introduction to Prototype Pollution.md"
source_sha256: "8efe55376eb18a7d1893e1d25b0a9ea0d9a1b8f6eb00a97aadd0a441ff9fb252"
curator_version: 2
review_status: imported-unreviewed
---

# Introduction to Prototype Pollution

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `jsx: module.__proto__.toString = function () {return "shadowed";}`
- `jsx: function Module(name, author, tier) {`
- `jsx: webAttacks.__proto__.__proto__.academy = "polluted";`
- `jsx: {"comment": "Great module."}`
- `jsx: // helper to determine if recursion is required`
- `jsx: {"__proto__": {"poc": "pwned"}}`

## Playbook (operator notes)

# Introduction to Prototype Pollution

# **Prototype Pollution**

- We can also override properties of the prototype
- For this we call the prototype of the object and then do the same as before
    
    ```jsx
    module.__proto__.toString = function () {return "shadowed";}
    ```
    
- With this every new object we create will have this `toString` method
    
    
    
- Occurs if we can set a property in an object's prototype when it is not intended
    
    ```jsx
    function Module(name, author, tier) {
    	this.name = name;
    	this.author = author;
    	this.tier = tier;
    }
    
    var webAttacks = new Module("Web Attacks", "21y4d", 2)
    ```
    
    - The `new` operator instantiates a new `Module`
        - The `Module` function then receives a `prototype` since `webAttacks` inherited
        - To pollute the `Object.prototype` we have to go back up the chain 2 steps
            
            
            
        - Then we can create / modify any existing functions
            
            ```jsx
            webAttacks.__proto__.__proto__.academy = "polluted";
            ```
            
            
            

# **Prototype Pollution Vulnerabilities**

### Example

A Web application that accepts JSON user input for comments

```jsx
{"comment": "Great module."}
```

After receiving this request, the web application sets the `comment` property of the corresponding `module` object. However, the web developer wants to support arbitrary keys instead of hardcoding the `comment` property to allow for the support of new properties in the future. As such, the developer might implement the following function to `merge` the user-supplied JSON object with the existing `module` object:

```jsx
// helper to determine if recursion is required
function isObject(obj) {
	return typeof obj === 'function' || typeof obj === 'object';
}

// merge source with target
function merge(target, source) {
	for (let key in source) {
		if (isObject(target[key]) && isObject(source[key])) {
			merge(target[key], source[key]);
		} else {
			target[key] = source[key];
		}
	}
	return target;
}
```

We can easily confirm that the function works as intended for the use case described above, as the `comment` property of the `module` object is correctly set:

However, due to the recursiveness of the function, it also supports more complicated merge tasks with objects within objects:

As such, the function is vulnerable to `prototype pollution` if the user-supplied JSON data contains the keyword `__proto__`. For instance, we can provide the following payload:

```jsx
{"__proto__": {"poc": "pwned"}}
```

This is due to `target[key] = source[key];` being `module["__proto__"]["poc"] = "pwned"`  which is equal to calling `module.__proto__ = ...`

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution/Introduction to Prototype Pollution.md`
