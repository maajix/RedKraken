# Filter Bypasses

## Other ways to call `__proto__`

- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/constructor
    - Each JS object has a `constructor`
    - References the function that created the object

![image.png](Filter%20Bypasses/image.png)

We can see that the `constructor` property of our `test` object references the function `Test`, which we used to create the `test` object. Now we can access the `prototype` property of the constructor to reach the object's prototype. The property chain `test.constructor.prototype` is equivalent to `test.__proto__`, as we can see here:

![image.png](Filter%20Bypasses/image%201.png)

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