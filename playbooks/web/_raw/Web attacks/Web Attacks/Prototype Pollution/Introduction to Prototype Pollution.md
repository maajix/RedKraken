# Introduction to Prototype Pollution

# **Prototype Pollution**

- We can also override properties of the prototype
- For this we call the prototype of the object and then do the same as before
    
    ```jsx
    module.__proto__.toString = function () {return "shadowed";}
    ```
    
- With this every new object we create will have this `toString` method
    
    ![image.png](Introduction%20to%20Prototype%20Pollution/image.png)
    
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
            
            ![image.png](Introduction%20to%20Prototype%20Pollution/image%201.png)
            
        - Then we can create / modify any existing functions
            
            ```jsx
            webAttacks.__proto__.__proto__.academy = "polluted";
            ```
            
            ![image.png](Introduction%20to%20Prototype%20Pollution/image%202.png)
            

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

![image.png](Introduction%20to%20Prototype%20Pollution/image%203.png)

However, due to the recursiveness of the function, it also supports more complicated merge tasks with objects within objects:

![image.png](Introduction%20to%20Prototype%20Pollution/image%204.png)

As such, the function is vulnerable to `prototype pollution` if the user-supplied JSON data contains the keyword `__proto__`. For instance, we can provide the following payload:

```jsx
{"__proto__": {"poc": "pwned"}}
```

![image.png](Introduction%20to%20Prototype%20Pollution/image%205.png)

This is due to `target[key] = source[key];` being `module["__proto__"]["poc"] = "pwned"`  which is equal to calling `module.__proto__ = ...`