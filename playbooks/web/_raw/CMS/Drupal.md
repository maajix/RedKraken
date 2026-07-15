# Drupal

Status: Erledigt

[Drupal](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal)

[https://github.com/SamJoan/droopescan](https://github.com/SamJoan/droopescan)

```bash
export DOMAIN = "example.com"
```

# Run a simple droopscan

```bash
droopescan scan drupal -u https://$DOMAIN -t 32
```