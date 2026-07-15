# nikto

Verantwortliche/r: Max Randhahn
Status: Erledigt

```bash
export DOMAIN = "example.com"
```

# Run a simple nikto scan

```bash
sudo nikto -followredirects -Format htm -o nikto-scan -host https://$DOMAIN
```

# View the output

```bash
firefox nikto-scan
```