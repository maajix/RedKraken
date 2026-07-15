# General

# **Timing Attacks**

- Timing attacks are [side-channel attacks](https://www.rambus.com/blogs/side-channel-attacks/)
- Do not directly attack the core components of web applications
    - Mesure response timing to exfiltrate potentially sensitive information

# **Race Conditions**

- Arise when the timing or sequence of specific actions can influence the outcome unexpectedly and undesirably
- Multi-threaded programs are particularly susceptible to race conditions
- Attacks require pressice timing, multiple attack attempts might be required

## [Time-of-check Time-of-use (TOCTOU)](https://cwe.mitre.org/data/definitions/367.html)

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