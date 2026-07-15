---
technique: "Decompiling Java Archives"
family: "injection"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Decompiling Java Archives.md"
source_sha256: "27c2e7283853fcacb1eccf22ae4ec1644746e82856c58497d27958f6117923e7"
curator_version: 2
review_status: imported-unreviewed
---

# Decompiling Java Archives

> Family: **injection** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: git clone https://github.com/fesh0r/fernflower.git`
- `bash: java -jar fernflower.jar BlueBird-0.0.1-SNAPSHOT.jar out`
- `bash: jar -xf BlueBird-0.0.1-SNAPSHOT.jar`
- `bash: java -jar jd-gui-1.6.6.jar BlueBird-0.0.1-SNAPSHOT.jar`

## Playbook (operator notes)

# Decompiling Java Archives

Imagine that we were contracted to perform a `white-box` security assessment on a target application named `BlueBird`, a [Java Spring Boot](https://spring.io/)  web application which uses `PostgreSQL` as its database.

- No source code, but the `JAR` file

## **Fernflower**

- [Fernflower](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine) is an open-source Java decompiler which is maintained by [JetBrains](https://www.jetbrains.com/) and included in their [IntelliJ IDEA](https://www.jetbrains.com/idea/) IDE
    - Installation
        
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

- After Fernflower is done we can enter `out` and extract all the `.java` files

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

## JD-GUI

- Another open-source tool we can use to decompile `JAR` files is [JD-GUI](https://github.com/java-decompiler/jd-gui)
- Alternative `JADX`

```bash
java -jar jd-gui-1.6.6.jar BlueBird-0.0.1-SNAPSHOT.jar 
```

## Source
Original note: `_raw/Web attacks/Web Attacks/SQLi/Identifying Vulnerabilities/Decompiling Java Archives.md`
