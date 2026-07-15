---
technique: "Filter Bypasses"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Prototype Pollution/Filter Bypasses.md"
source_sha256: "bfaf3cc1ecd957ed10d5ea08a8ca06ddd64e0dd6e21e6cabb6513ff2f6e3420a"
curator_version: 2
review_status: imported-unreviewed
---

# Filter Bypasses

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `jsx: {`

## Playbook (operator notes)

# Filter Bypasses

## Other ways to call `__proto__`

- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/constructor
    - Each JS object has a `constructor`
    - References the function that created the object

We can see that the `constructor` property of our `test` object references the function `Test`, which we used to create the `test` object. Now we can access the `prototype` property of the constructor to reach the object's prototype. The property chain `test.constructor.prototype` is equivalent to `test.__proto__`, as we can see here:

We can also do `x.constructor.__proto__.__proto__`

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

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution/Filter Bypasses.md`
