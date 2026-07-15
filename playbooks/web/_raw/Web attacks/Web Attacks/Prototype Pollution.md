# Prototype Pollution

Status: Erledigt
Tags: JavaScript (JS) (../Tags/JavaScript%20(JS)%2027f2c37daa29809aac00f50467f7187c.md), Account Takeover (ATO) (../Tags/Account%20Takeover%20(ATO)%2027f2c37daa2980f4abc6c479151370af.md), XSS (../Tags/XSS%2027f2c37daa29805dadb2ff82553491b9.md), 403 (../Tags/403%2027f2c37daa2980c7b62be7b31dee36cc.md), Remote Code Execution (RCE) (../Tags/Remote%20Code%20Execution%20(RCE)%2027f2c37daa29804392b8ec44c972391b.md), HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md)
Tags 2: JS

<aside>
💡

⚠️ PP can break the whole web page, be carefull on live targets!

Check the loaded libraries, then check if we can find a PP for the loaded version. We can then check via the console `Object.prototype` if the PP was successful. We can then search for gadgets that result in XSS for those libs.

</aside>

[Whitebox_Attacks_Module_Cheat_Sheet.pdf](Prototype%20Pollution/Whitebox_Attacks_Module_Cheat_Sheet.pdf)

https://github.com/BlackFan/client-side-prototype-pollution#prototype-pollution

https://github.com/BlackFan/client-side-prototype-pollution/blob/master/pp/jquery-deparam.md

https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/recaptcha.md

https://github.com/BlackFan/client-side-prototype-pollution/tree/master/gadgets

# Lecture

[**JavaScript Objects & Prototypes**](Prototype%20Pollution/JavaScript%20Objects%20&%20Prototypes%201b62c37daa2980528dc4cee8dc8f7527.md)

[**Introduction to Prototype Pollution**](Prototype%20Pollution/Introduction%20to%20Prototype%20Pollution%201b62c37daa2980ca9789e462bf59f7d2.md)

[**Privilege Escalation**](Prototype%20Pollution/Privilege%20Escalation%201b62c37daa29801b944ac4e9adae238d.md)

[**Remote Code Execution**](Prototype%20Pollution/Remote%20Code%20Execution%201b62c37daa2980c7a234f98d077906e6.md)

[**Filter Bypasses**](Prototype%20Pollution/Filter%20Bypasses%201b62c37daa298049b252ee0c22435688.md)

[Clientside PP](Prototype%20Pollution/Clientside%20PP%201c82c37daa29805391d0d9531c98de28.md)

[Remarks ](Prototype%20Pollution/Remarks%201c82c37daa2980f3b92af6b5e0016c78.md)