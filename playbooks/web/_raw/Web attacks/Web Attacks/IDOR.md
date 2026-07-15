# IDOR

Status: Erledigt
Tags: Authentication (../Tags/Authentication%2027f2c37daa29806cb382fb4d3ccf9448.md), HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md)
Tags 2: Auth, HTTP

# Types of IDOR you will see in wild

1. The value of a parameter is used directly to retrieve a database record
    
    ```python
    http://foo.bar/somepage?invoice=12345
    ```
    
2. The value of a parameter is used directly to perform an operation in the system
    
    ```python
    http://foo.bar/changepassword?user=someuser
    ```
    
3. The value of a parameter is used directly to retrieve a file system resource
    
    ```python
    http://foo.bar/showImage?img=img00011
    ```
    
4. The value of a parameter is used directly to access application functionality
    
    ```python
    http://foo.bar/accessPage?menuitem=12
    ```
    

# Testing for IDOR - Manual-Method

1. If possible, create two accounts. If not, enumerate users first
2. Verify if the endpoint is private or public and check if it contains an ID parameter
3. Attempt to change the parameter value to another user's ID and observe if it impacts their account

### Testcase - 1: Add IDs to requests that don’t have them

```python
GET /api/MyPictureList → /api/MyPictureList?user_id=<other_user_id>

Pro tip: You can find parameter names to try by deleting or editing other objects and seeing the parameter names used.
```

### Testcase - 2: Try replacing parameter names

```python
Instead of this:
GET /api/albums?album_id=<album id>

Try This:
GET /api/albums?account_id=<account id>

Tip: There is a Burp extension called Paramalyzer which will help with this by remembering all the parameters you have passed to a host.
```

### Testcase - 3: Supply multiple values for the same parameter

```python
Instead of this:
GET /api/account?id=<your account id>

Try this:    
GET /api/account?id=<your account id>&id=<admin's account id>

Tip: This is known as HTTP parameter pollution. Something like this might get you access to the admin’s account
```

### Testcase - 4: Try changing the HTTP request method when testing for IDORs

```python
Instead of this:
POST /api/account?id=<your account id>

Try this:    
PUT /api/account?id=<your account id>

Tip: Try switching POST and PUT and see if you can upload something to another user’s profile. For RESTful services, try changing GET to POST/PUT/DELETE to discover create/update/delete actions.
```

### Testcase - 5: Try changing the request’s content type

```python
Instead of this:
POST /api/chat/join/123 […] Content-type: application/xml → test

Try this:
POST /api/chat/join/123 […] Content-type: application/json {“user”: “test”}

Tip: Access controls may be inconsistently implemented across different content types. Don’t forget to try alternative and less common values like text/xml, text/x-json, and similar.
```

### Testcase - 6: Try changing the requested file type (Test if Ruby)

```python
Instead of this:
GET /user_data/2341 --> 401 Unauthorized

Try this:
GET /user_data/2341.json --> 200 OK

Tip: Experiment by appending different file extensions (e.g. .json, .xml, .config) to the end of requests that reference a document.
```

### Testcase - 7: Does the app ask for non-numeric IDs? Use numeric IDs instead

```python
There may be multiple ways of referencing objects in the database and the application only has access controls on one. 
Try numeric IDs anywhere non-numeric IDs are accepted.

Example:
username=user1 → username=1234
account_id=7541A92F-0101-4D1E-BBB0-EB5032FE1686 → account_id=5678
album_id=MyPictures → album_id=12
```

### **Testcase - 8: Try using an array**

```python
If a regular ID replacement isn’t working, try wrapping the ID in an array and see if that does the trick. For example:

{“id”:19} → {“id”:[19]}
```

### Testcase - 9: Wildcard ID

```python
These can be very exciting bugs to find in the wild and are so simple. Try replacing an ID with a wildcard. You might get lucky!

GET /api/users/<user_id>/ → GET /api/users/*
```

### Testcase - 10: Pay attention to new features

```python
If you stumble upon a newly added feature within the web app, such as the ability to upload a profile picture for an upcoming charity event, and it performs an API call to:

/api/CharityEventFeb2021/user/pp/<ID>

It is possible that the application may not enforce access control for this new feature as strictly as it does for core features.
```

---

[IDOR](https://kathan19.gitbook.io/howtohunt/idor/idor)