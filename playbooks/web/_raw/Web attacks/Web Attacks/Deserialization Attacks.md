# Deserialization Attacks

Status: Erledigt
Tags: Deserialization (../Tags/Deserialization%2027f2c37daa2980949cf9d8b7de2aa0ec.md), PHP (../Tags/PHP%2027f2c37daa29808abeddf84f03bbf5e1.md), Python (../Tags/Python%2027f2c37daa2980ac8f88d4d9cefd51e5.md), Remote Code Execution (RCE) (../Tags/Remote%20Code%20Execution%20(RCE)%2027f2c37daa29804392b8ec44c972391b.md), Account Takeover (ATO) (../Tags/Account%20Takeover%20(ATO)%2027f2c37daa2980f4abc6c479151370af.md), Session Tokens (Cookie) (../Tags/Session%20Tokens%20(Cookie)%2027f2c37daa29806eb79aee9d381a33b5.md), HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md), Authentication (../Tags/Authentication%2027f2c37daa29806cb382fb4d3ccf9448.md), File Upload (../Tags/File%20Upload%202802c37daa29801badd6ff5dc4845c0b.md)
Tags 2: Deserialization, PHP, Python

https://net-square.com/yaml-deserialization-attack-in-python.html

https://davidhamann.de/2020/04/05/exploiting-python-pickle/

https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/

https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf

---

[deserialize.pdf](Deserialization%20Attacks/deserialize.pdf)

---

[Introduction](Deserialization%20Attacks/Introduction%2027e2c37daa29800fbd1bc05b1e73448c.md)

[**Exploiting PHP Deserialization**](Deserialization%20Attacks/Exploiting%20PHP%20Deserialization%2027e2c37daa298057b45ec72450e0ffc6.md)

[**Exploiting Python Deserialization**](Deserialization%20Attacks/Exploiting%20Python%20Deserialization%2027e2c37daa2980a38c5efc7df44ec05b.md)

---

[**Defending against Deserialization Attacks**](Deserialization%20Attacks/Defending%20against%20Deserialization%20Attacks%2027e2c37daa2980109113dc0db3e6afd2.md)

[**Tools of the Trade (PHP Deserialization)**](Deserialization%20Attacks/Tools%20of%20the%20Trade%20(PHP%20Deserialization)%2027e2c37daa298001b348f12e9ed97ed6.md)

[**Tools of the Trade (Python Deserialization)**](Deserialization%20Attacks/Tools%20of%20the%20Trade%20(Python%20Deserialization)%2027e2c37daa29801e9fe8ccd24256e141.md)

---

```python
sudo tcpdump -i tun0

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:28:15.131656 IP view-localhost > view-localhost: ICMP echo request, id 63693, seq 1, length 64
15:28:15.131668 IP view-localhost > view-localhost: ICMP echo reply, id 63693, seq 1, length 64
15:28:16.135472 IP view-localhost > view-localhost: ICMP echo request, id 63693, seq 2, length 64
...
```