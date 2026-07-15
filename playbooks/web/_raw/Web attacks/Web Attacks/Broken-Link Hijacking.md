# Broken-Link Hijacking

Status: Erledigt
Tags: HTML (../Tags/HTML%2027f2c37daa29805eb66be9bf05414a38.md)

[Free Broken Link Checking Tool](https://www.deadlinkchecker.com/)

[Free Broken Link Checker - Online Tool](https://brokenlinkcheck.com/)

[Free Broken Link Checker - Dead Link Checking Tool by Ahrefs](https://ahrefs.com/broken-link-checker)

```bash
export DOMAIN = "example.com"
```

# How to Hunt for Broken Links

1. Run the [Broken Link Checker](https://github.com/stevenvachon/broken-link-checker) in the background:
    
    ```bash
    blc -rof --filter-level 3 <https://$DOMAIN> | grep -i broken
    ```
    
2. While the automated scanner is running, manually check for broken links (Social Media Accounts or external Media) or use free websites that check for broken links.
3. After gathering some links, check if the referred page is one you could control by acquiring the domain, etc.

---

[Broken-Link Hijacking](https://kathan19.gitbook.io/howtohunt/broken-link-hijacking/brokenlinkhijacking)