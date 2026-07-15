# Live-Debugging Java Applications

https://www.jetbrains.com/help/idea/tutorial-remote-debug.html#create-run-configurations

- We need to forward the execution of the application to our own computer via: `ssh -L 8000:127.0.0.1:8000 student@x.x.x.x`
    - Since the database and everything is setup on that VM

## Debugging with IntelliJ

We can specify the SDK via the Project Structure (`STR+ALT+SHFT+S`)

![image.png](Live-Debugging%20Java%20Applications/image.png)

- Local
    - Find the main application and click debug
    
    ![image.png](Live-Debugging%20Java%20Applications/image%201.png)
    
    - Add the `lib` folder for the JAR application
    
    `CTRL+ALT+SHIFT+S` 
    
    ![image.png](Live-Debugging%20Java%20Applications/image%202.png)
    
    In this case the application needs the database so we would have to set that up if we want to test it 
    
    ```sql
    org.postgresql.util.PSQLException: FATAL: 
    Ident authentication failed for user "bbuser"
    ```
    
- Remote
    
    ![image.png](Live-Debugging%20Java%20Applications/image%203.png)
    
    ![image.png](Live-Debugging%20Java%20Applications/image%204.png)
    

---

## **Remote Debugging with Visual Studio Code**

- Details
    
    ```bash
    mkdir src
    java -jar fernflower.jar BlueBird-0.0.1-SNAPSHOT.jar src
    cd src
    jar -xf BlueBird-0.0.1-SNAPSHOT.jar
    ```
    
    - Launch `VSCode` and open the folder `src/BOOT-INF/classes`
    - We should have all the source files open, but a lot of lines will be underlined in red due to unresolved imports
    - We can fix this by navigating to `Java Projects > Referenced Libraries` on the lefthand sidebar, clicking the `+` icon and selecting all the `JAR` files from the decompiled `src/BOOT-INF/lib` folder
    
    ![image.png](Live-Debugging%20Java%20Applications/image%205.png)
    
    - Hit `[CTRL]+[SHIFT]+[D]` to bring up the debug pane, and `create a launch.json file`
    
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
    
    `ssh -L 8000:127.0.0.1:8000 student@x.x.x.x`
    
    ```bash
    java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar /opt/bluebird/BlueBird-0.0.1-SNAPSHOT.jar
    
    Listening for transport dt_socket at address: 8000
    ```
    
    ![image.png](Live-Debugging%20Java%20Applications/image%206.png)
    
    ![image.png](Live-Debugging%20Java%20Applications/image%207.png)
    

## **Remote Debugging with Eclipse**

- Details
    - Go ahead and create a `new Java Project` with the following settings
    
    ![image.png](Live-Debugging%20Java%20Applications/image%208.png)
    
    - Import the "source" of `BlueBird` into the `Eclipse` project by copying the contents of the decompiled `classes/` folder into the `src/` folder for the `Eclipse` project we just made
    
    ```bash
    cp -r src/BOOT-INF/classes/* ~/eclipse-workspace/BlueBird/src
    ```
    
    ![image.png](Live-Debugging%20Java%20Applications/image%209.png)
    
    - The reason the packages have errors is due to missing imports
        - Import all the dependencies from the decompiled JAR
        - Go to `File > Properties > Java Build Path > Libraries > Modulepath > Add External JARs` and add all the JAR files from `lib/` (created by `Fernflower` when decompiling)
    
    ![image.png](Live-Debugging%20Java%20Applications/image%2010.png)
    
    ```bash
    java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar BlueBird-0.0.1-SNAPSHOT.jar 
    
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Listening for transport dt_socket at address: 8000
    ```
    
    - To attach to this, we need to head back to `Eclipse`, go to `Run > Debug Configurations` and create a new `Remote Java Application` with the following settings (should be default)
    - Click `Apply` and then `Debug`

---