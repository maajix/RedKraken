# cmsmap

Verantwortliche/r: Max Randhahn
Status: Erledigt

[https://github.com/dionach/CMSmap](https://github.com/dionach/CMSmap)

```bash
export DOMAIN = "example.com"
```

# Run a simple cmsmap scan

- If we know the CMS we can set it via `-f W/D/J`
    - Wordpress, Drupal, Joomla
- Do a full scan using large plugin lists `-F`

```bash
cmsmap https://$DOMAIN -D -o cmsmap-scan
```