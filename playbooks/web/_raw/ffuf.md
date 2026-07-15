# ffuf

Status: Erledigt

# Header Brute-Forcing

```bash
ffuf -w $WL -u https://$DOMAIN/FUZZ -H "X-Custom-Header: FUZZ"
```

# WAF Bypass

```bash
ffuf -w $WL -u https://$DOMAIN/FUZZ -X GET -H "User-Agent: FUZZ"
```

# HTTP Request Smuggling

```bash
ffuf -w $WL -u https://$DOMAIN/ -X FUZZ
```

# Content Type Fuzzing

```bash
ffuf -w $WL -u https://$DOMAIN/ -X POST -H "Content-Type: FUZZ" -d '{"data":"example"}'
```