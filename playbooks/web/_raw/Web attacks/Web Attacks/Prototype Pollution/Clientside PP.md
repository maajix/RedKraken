# Clientside PP

`__proto__[srcdoc][]=<script>window.location%3d"/poc.php";</script>`

- Script gadgets are legitimate and benign JavaScript code that can be used in combination with a different attack vector to achieve XSS
- In particular, we are interested in script gadgets that lead to XSS if the prototype object is manipulated
    - https://github.com/BlackFan/client-side-prototype-pollution#script-gadgets
    - https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/recaptcha.md
- We can use Dominvador (Burp browser) to find gadgets as well