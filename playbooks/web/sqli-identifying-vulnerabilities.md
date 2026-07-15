---
technique: "Identifying Vulnerabilities"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities.md"
curator_version: 2
review_status: imported-unreviewed
---

# Identifying Vulnerabilities

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Overview

Identifying SQL injection points combines black-box probing with white-box source review: grepping application source for SQL-building patterns, watching database error output and query logs, and — when only a compiled Java archive is available — decompiling and even live-debugging the application to recover the vulnerable query-building code.

## Searching for Strings

Search application source for the basic SQL commands — injection can occur in more than just `SELECT` statements, exploitation may just be a bit trickier:

| Query | Description |
| --- | --- |
| `SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP` | Search for the basic SQL commands. Injection can occur in more than just SELECT statements, exploitation may just be a bit trickier. |
| `(WHERE|VALUES).*?'` | Search for strings which include `WHERE` or `VALUES` and then a `single quote`, which could indicate a string concatenation. |
| `(WHERE|VALUES).*" \+` | Search for strings which include `WHERE` or `VALUES` followed by a double quote and a plus sign, which could indicate a string concatenation. |
| `.*sql.*"` | Search for lines which include `sql` and then a `double quote`. |
| `jdbcTemplate` | Search for lines which include `jdbcTemplate`. There are various ways to interact with `SQL` databases in `Java`. `JdbcTemplate` is one of them; others include `JPA` and `Hibernate`. |

Take note of the libraries and coding style in use so the search regex can be adapted.

`grep -E <RegEx> <File>` enhancements:
- `--include *.java` — only search for matches in `.java` files
- `-n` — display line numbers
- `-i` — ignore case
- `-r` — search recursively through a directory

```bash
grep -irnE 'SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP' .
```

Note: if you don't know what `controllers` are, you can imagine them as API endpoints.

## Hunting for SQL Errors

Another way to identify the SQL queries being run, and to debug payloads while developing an exploit, is to enable SQL logging.

**Enabling PostgreSQL Logging**:
- Find `postgresql.conf`, usually located in `/etc/postgresql/<version>/main/`:

```sql
find / -type f -name postgresql.conf 2>/dev/null
```

- Change `#logging_collector = off` to `logging_collector = on` — enables the logging collector background process ([source](https://postgresqlco.nf/doc/en/param/logging_collector/)).
- Change `#log_statement = 'none'` to `log_statement = 'all'` — logs all statement types (SELECT, CREATE, INSERT, ...) ([source](https://postgresqlco.nf/doc/en/param/log_statement/)).
- Uncomment `#log_directory = '...'` to define the directory where logfiles are saved ([source](https://postgresqlco.nf/doc/en/param/log_directory/)).
- Uncomment `#log_filename = '...'` to define the logfile filename pattern ([source](https://postgresqlco.nf/doc/en/param/log_filename/)).

```sql
sudo systemctl restart postgresql
```

Watch the log messages in near-realtime:

```sql
sudo watch -n 1 tail <log_directory>/postgresql-2023-02-14_081533.log

<SNIP>
2023-02-14 09:06:04.819 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:04.819 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'bmdyy'
2023-02-14 09:06:10.423 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:10.423 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'admin'
2023-02-14 09:06:12.999 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:12.999 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'test'
2023-02-14 09:06:16.688 EST [22510] bbuser@bluebird LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
2023-02-14 09:06:16.688 EST [22510] bbuser@bluebird DETAIL:  parameters: $1 = 'itsmaria'
```

## Decompiling Java Archives

Scenario: a white-box security assessment on a target application named `BlueBird`, a [Java Spring Boot](https://spring.io/) web application using `PostgreSQL` as its database, where only the compiled `JAR` file is available (no source code).

**Fernflower** — an open-source Java decompiler maintained by [JetBrains](https://www.jetbrains.com/) and included in [IntelliJ IDEA](https://www.jetbrains.com/idea/):

```bash
git clone https://github.com/fesh0r/fernflower.git
./gradlew build
# if needed:
# sudo apt install openjdk-17-jdk
# sudo update-java-alternatives --list
# sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
```

```bash
java -jar fernflower.jar BlueBird-0.0.1-SNAPSHOT.jar out
```

After Fernflower finishes, enter `out` and extract all the `.java` files:

```bash
jar -xf BlueBird-0.0.1-SNAPSHOT.jar

tree
.
├── BlueBird-0.0.1-SNAPSHOT.jar
├── BOOT-INF
│   ├── classes
│   │   ├── application.properties
│   │   ├── com
│   │   │   └── bmdyy
│   │   │       └── bluebird
```

**JD-GUI** — another open-source tool to decompile `JAR` files (alternative: `JADX`):

```bash
java -jar jd-gui-1.6.6.jar BlueBird-0.0.1-SNAPSHOT.jar
```

## Live-Debugging Java Apps

See [JetBrains' remote debug tutorial](https://www.jetbrains.com/help/idea/tutorial-remote-debug.html#create-run-configurations). Forward the application's execution to the local machine, since the database and everything else is set up on the remote VM:

```bash
ssh -L 8000:127.0.0.1:8000 student@x.x.x.x
```

**Debugging with IntelliJ** — specify the SDK via Project Structure (`CTRL+ALT+SHIFT+S`).
- Local: find the main application and click debug; add the `lib` folder for the JAR application. If the application needs the database, set that up too, otherwise authentication errors like the following occur:

```sql
org.postgresql.util.PSQLException: FATAL:
Ident authentication failed for user "bbuser"
```

**Remote Debugging with Visual Studio Code**:

```bash
mkdir src
java -jar fernflower.jar BlueBird-0.0.1-SNAPSHOT.jar src
cd src
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
```

- Launch VS Code and open the folder `src/BOOT-INF/classes`. Source files will be open but many lines will be underlined in red due to unresolved imports.
- Fix this via `Java Projects > Referenced Libraries` in the sidebar, click `+`, and select all the `JAR` files from the decompiled `src/BOOT-INF/lib` folder.
- Hit `CTRL+SHIFT+D` to bring up the debug pane and create a `launch.json` file:

```bash
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "java",
            "name": "Remote Debugging",
            "request": "attach",
            "hostName": "127.0.0.1",
            "port": 8000
        }
    ]
}
```

```bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar /opt/bluebird/BlueBird-0.0.1-SNAPSHOT.jar

Listening for transport dt_socket at address: 8000
```

**Remote Debugging with Eclipse**:
- Create a new Java Project, then import the "source" of `BlueBird` by copying the contents of the decompiled `classes/` folder into the Eclipse project's `src/` folder:

```bash
cp -r src/BOOT-INF/classes/* ~/eclipse-workspace/BlueBird/src
```

- Packages show errors due to missing imports — import all dependencies from the decompiled JAR via `File > Properties > Java Build Path > Libraries > Modulepath > Add External JARs`, adding all JAR files from the `lib/` folder created by Fernflower.

```bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar BlueBird-0.0.1-SNAPSHOT.jar

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening for transport dt_socket at address: 8000
```

- Attach from Eclipse via `Run > Debug Configurations`, create a new `Remote Java Application` with the default settings, then click `Apply` and `Debug`.

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities.md`
- `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Searching for Strings.md`
- `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Hunting for SQL Errors.md`
- `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Decompiling Java Archives.md`
- `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Live-Debugging Java Applications.md`
