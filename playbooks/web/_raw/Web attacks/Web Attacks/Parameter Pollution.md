# Parameter Pollution

Status: Erledigt
Tags: HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md), Open Redirect (../Tags/Open%20Redirect%2027f2c37daa29809f8952deb2c81c7faf.md)
Tags 2: HTTP

# HTTP Parameter Pollution (HPP) Overview

### Example:

- A banking application transaction URL
    - **Original URL:** `https://www.victim.com/send/?from=accountA&to=accountB&amount=10000`
- By inserting an additional `from` parameter
    - **Manipulated URL:** `https://www.victim.com/send/?from=accountA&to=accountB&amount=10000&from=accountC`

The transaction may be incorrectly charged to `accountC` instead of `accountA`, showcasing the potential of HPP to manipulate transactions or other functionalities such as password resets, 2FA settings, or API key requests.

# **Parameter Pollution In Social Sharing Buttons**

### Steps:

1. Find a article or blog present on target website which must have a link to share that blog on different social networks such as Facebook,Twitter etc.
2. Let's say we got and article with URL [https://taget.com/how-to-hunt](https://taget.com/how-to-hunt) 
    1. Append a parameter like `?&u=https://attacker.com` 
3. Now hit enter with the above URL and click on share with social media → observe the content weather it is including our payload i.e. [https://attacker.com](https://attacker.com/)
    
    [HackerOne disclosed on HackerOne: Parameter pollution in social...](https://hackerone.com/reports/105953)
    

---

[Parameter Pollution](https://book.hacktricks.xyz/pentesting-web/parameter-pollution)

[Parameter Pollution In Social Sharing Buttons](https://kathan19.gitbook.io/howtohunt/parameter-pollution/parameter_pollution_in_social_sharing_buttons)