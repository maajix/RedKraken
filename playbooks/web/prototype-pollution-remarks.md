---
technique: "Remarks"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Prototype Pollution/Remarks.md"
source_sha256: "99d9bda4f838cf205618cf0981bb313c47bbf8599d63b586f3b44999c3f0e5ac"
curator_version: 2
review_status: imported-unreviewed
---

# Remarks

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `jsx: {`
- `json: {`
- `bash: $ echo -n 'HelloWorld!!!' | iconv -f UTF-8 -t UTF-7HelloWorld+ACEAIQAh-`
- `json: {`

## Playbook (operator notes)

# Remarks

# Check PP as safe as possible

### **Status Code**

The first and most universal technique is manipulating the status code returned when the web application encounters an issue. First, we need to determine how the web application reacts if we provide an invalid JSON request body:

`400` status code

To confirm prototype pollution, we can manipulate the returned status code by polluting the `status` property of the `Object.prototype` object using a payload similar to the following:

```jsx
{
	"__proto__":{
		"status":555
	}
}
```

Depending on the web application's implementation, we might need to traverse multiple steps up the prototype chain to reach the `Object.prototype` object. When we now send the above request again, the server returns the custom-set status code `555`:

### **Parameter Limiting**

The second technique requires that the web application contains an endpoint that reflects GET parameters in any way. In our simple example below, the response body reflects the GET parameters in a JSON object:

We can manipulate the number of GET parameters returned by the web application by polluting the `parameterLimit` property of the `Object.prototype` object using a payload similar to the following:

```json
{
	"__proto__":{
		"parameterLimit":1
	}
}
```

When we send the above request again, the web application responds with only the first GET parameter since we limited the number of parameters to one. Thus, all parameters after the first one are ignored:

### **Content-Type**

Our last example requires the reflection of a JSON object. We can force the web application to accept other encodings without breaking the web application. We will use the `UTF-7` encoding for this since it does not break the web application's default `UTF-8` encoding. First, we need to encode a test string in UTF-7, which we can do using `iconv`:

```bash
$ echo -n 'HelloWorld!!!' | iconv -f UTF-8 -t UTF-7HelloWorld+ACEAIQAh-
```

```json
{
	"__proto__":{
		"content-type":"application/json; charset=utf-7"
	}
}
```

# **Prevention & Patching**

- Blocking the obvious key `__proto__` is insufficien
    - Other ways e.g. constructor or prototype

However, a more secure approach would be implementing a whitelist approach that consists of a list of explicitly whitelisted keys. These keys need to be chosen carefully for the corresponding context and may even help to prevent further vulnerabilities such as [Mass Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment).

Another way to prevent prototype pollution is by freezing an object, meaning it cannot be modified. This can be done using the [Object.freeze()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/freeze) function. If we call the function on the global `Object.prototype` object that all objects inherit from, any modifications to it are prevented. As an example, consider the following steps:

As we can see, the property `module.polluted` is `undefined`. That is because we froze the `Object.prototype` object using the `Object.freeze` function. Therefore, we prevented prototype pollution by disallowing the `polluted` property from being set.

However, this is not a universal fix since freezing the `Object.prototype` property alone may be insufficient. Recall the prototype pollution vulnerability we exploited to gain remote code execution in a previous sections. In that case, we polluted a property in the `User.prototype` object and did not modify the `Object.prototype` object. Therefore, in order to prevent that prototype pollution vulnerability, the `User.prototype` object needs to be frozen.

Lastly, we can also manipulate inheritance to set the prototype to `null`. This can be achieved using `Object.create(null)` to create the object, which sets the prototype of the newly created object to `null`. Thus, there are no inherited properties and no possibility of prototype pollution. However, since there is no prototype, the object does not contain properties like `toString()` and other useful properties provided by the global `Object.prototype` object. It only contains properties explicitly added to the object. While this can prevent prototype pollution vulnerabilities, it is probably impractical in many use cases.

Prototype pollution vulnerabilities arise when recursively manipulating an object's properties from user input, a functionality we should import from available libraries. As such, patching prototype pollution vulnerabilities is often as simple as using secure libraries and keeping them updated. An additional line of defense is provided by packages like [nopp](https://github.com/snyk-labs/nopp) which ensure some of the defenses discussed are implemented.

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution/Remarks.md`
