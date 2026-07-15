# Tabnabbing

Status: Nicht begonnen
Tags: HTML (../Tags/HTML%2027f2c37daa29805eb66be9bf05414a38.md)

# How to exploit

```html
<a href="..." target="_blank" rel="opener" />  
<a href="..." target="_blank" />
```

1. In a situation where an **attacker** can **control** the **`href`** argument of an **`<a`** tag with the attribute **`target="_blank" rel="opener"`** that is going to be clicked by a victim, the **attacker** **point** this **link** to a web under his control (a **malicious** **website**)
    1. `window.opener.location = "[http://evil.com](http://evil.com/)"`
2. He tricks the victim into visiting the link, which is opened in the browser in a new tab
3. At the same time the JS code is executed and the background tab is redirected to the website [evil.com](http://evil.com/), which is most likely a phishing website
4. If the victim opens the background tab again and doesn't look at the address bar, it may happen that he thinks he is logged out, because a login page appears, for example
5. The victim tries to log on again and the attacker receives the credentials

---

[Tabnabbing](https://kathan19.gitbook.io/howtohunt/tabnabbing/tabnabbing)

[Reverse Tab Nabbing](https://book.hacktricks.xyz/pentesting-web/reverse-tab-nabbing)