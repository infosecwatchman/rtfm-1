### 1. get password policy for root
```
chage -l root
```
**- linux,bash,passwords,enumeration,user information**
#### References:

http://www.thegeekstuff.com/2009/04/chage-linux-password-expiration-and-aging/
__________
### 2. get remote timestamp
```
hping3 -S [ip] -p [port] --tcp-timestamp
```
**- linux,bash,networking,enumeration**
#### References:

http://wiki.hping.org/
__________
### 3. list windows services
```
net start
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 4. list windows password requirements : add /domain for AD
```
net accounts
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 5. password requirements domain
```
net accounts /domain
```
**- enumeration,Windows,users**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 6. WIFI : Scan the range in an orderly manner
```
airodump-ng -f 4000  --cswitch 1 --band abg  wlan0mon --output-format csv -w WifiOverview
```
**- enumeration,wireless,wifi**
#### References:

https://www.aircrack-ng.org/doku.php?id=airodump-ng
__________
### 7. Priv esc check weak service perms, you may need an older version for older windows!
```
accesschk.exe -uwcqv "Authenticated Users" *
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/sysinternals/accesschk.aspx
__________
### 8. loop to find user shares
```
for host in $(cat ../nmap/[IP File]); do echo "Trying $host"; smbclient -L $host -U  [DOM]/[USER]%'[PASS]'; done
```
**- linux,bash,loop,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
https://yg.ht
__________
### 9. loop for who is where
```
for host in $(cat userhosts.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host 'WMIC ComputerSystem Get UserName'; done | tee loggedin-dirty.txt;cat loggedin-dirty.txt | grep -v "^\[" | grep -v "^Impacket" | grep -v "^Trying" | grep -v "SMB SessionError" | sed '/^$/d'
```
**- loop,enumeration,user information,smb,impacket**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 10. Powershell password last changed, run on DC
```
Get-ADUser -filter * -properties * | sort-object passwordlastset | select-object samaccountname, passwordlastset, passwordneverexpires, homedirectory, mail, enabled | Export-csv -path c:\temp\pwprofile.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://yg.ht
https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 11. dump dns zone on DC
```
dnscmd 127.0.0.1 /ZoneExport [FQDN] [OUT].zone
```
**- enumeration,dns,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc772069(v=ws.11).aspx
__________
### 12. Look in 'mount' for share (mount sysvol first)
```
egrep -r "cpassword|net" mount
```
**- linux,enumeration,smb**
#### References:

https://blogs.technet.microsoft.com/ash/2014/11/10/dont-set-or-save-passwords-using-group-policy-preferences/
__________
### 13. loop to look for dual homed hosts
```
for host in $(cat ../nmap/IPs-SMB.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host "ipconfig"; done | grep "IPv4 Address\|Ethernet adapter\|^[0-9]" | sed '/^$/d' | tee dualhomed-search.txt
```
**- networking,loop,enumeration,impacket**
#### References:

https://yg.ht
https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 14. loop to find local admins
```
for i in `cat smb_up `; do timeout 10 psexec.py [user]:[pass]@$i net localgroup administrators; done | tee local_admin_information
```
**- linux,loop,enumeration,user information,impacket**
#### References:

https://technet.microsoft.com/en-us/library/bb490706.aspx
__________
### 15. Recover IIS password
```
c:\windows\system32\inetsrv\appcmd.exe list apppool "SharePoint Central Administration v4" /text:ProcessModel.Password
```
**- passwords,enumeration,Windows,IIS**
#### References:

https://yg.ht
https://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
__________
### 16. get domain trusts
```
netdom query trust
```
**- enumeration,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc772217(v=ws.11).aspx
__________
### 17. windows firewall status
```
sc query "MpsSvc"
```
**- enumeration,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-gb/library/bb490995.aspx
https://technet.microsoft.com/en-us/library/dd228922(v=ws.11).aspx
__________
### 18. windows firewall status
```
netsh advfirewall firewall
```
**- enumeration,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 19. Windows process list
```
tasklist /v
```
**- enumeration,Windows,process management,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 20. Windows list listening ports
```
netstat -a | find "LISTENING"
```
**- networking,enumeration,Windows**
#### References:

http://Microsoft.com
__________
### 21. Windows open files
```
tasklist /FI "IMAGENAME eq [process].exe" /V
```
**- files,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 22. RPCClient smb show users and groups
```
rpcclient -U '[DOMAIN]\[USER]'%'[PASS]' '[TARGET]' -c enumdomusers,enumdomgroups
```
**- linux,enumeration,user information,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages/rpcclient.1.html
__________
### 23. Unquoted Service Paths
```
wmic service get name,displayname,pathname,startmode
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 24. Unquoted Service Paths
```
sc query
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 25. Unquoted Service Paths
```
sc qc "[SERVICE]"
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 26. Unquoted Service Paths, start service
```
sc config "[SERVICE]" start= auto
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 27. Unquoted Service Paths
```
sc config "[SERVICE]" start= disabled
```
**- enumeration,Windows**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
http://pentestmonkey.net/tools/windows-privesc-check
__________
### 28. Windows Wireless
```
netsh wlan show profile
```
**- networking,passwords,enumeration,Windows,wireless,wifi**
#### References:

http://Microsoft.com
__________
### 29. loop dump wifi keys
```
for host in $(cat localsubnet.txt); do echo "Trying $host"; winexe --user [Domain]/[user]%[pass] //$host "netsh wlan export profile name=[PROFILE] key=clear"; done
```
**- bash,loop,passwords,enumeration,wireless,wifi**
#### References:

https://yg.ht
https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 30. Domain Admins windows
```
net group "Domain Admins" /domain
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 31. Windows ARP Cache
```
ipconfig /displaydns
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 32. network discovery RDNS
```
cat networks-dirty.txt | grep "^[0-9]" | awk {'print $1'} | awk -F "." {'print $3"."$2"."$1".0/24"'} | sort -u > nets.txt
```
**- networking,loop,enumeration,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 33. List smb shares on a target host domain and pass are optional, % seperates user from pass
```
smbclient -L [TARGET] -U [DOM]/[USER]%'[PASS]'
```
**- linux,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
__________
### 34. Get a listing of all users and groups for targeting your post exploitation
```
enum4linux.pl -a -u [USER] -p [PASS] [TARGET] | tee [CLIENTNAME].domainenum
```
**- linux,enumeration,user information,smb**
#### References:

https://labs.portcullis.co.uk/tools/enum4linux/
__________
### 35. Get a list of all the users in the domain from a full dump
```
cat [CLIENTNAME].domainenum | grep "^user" | cut -d ":" -f 2 | cut -d "]" -f 1 | cut -d "[" -f 2 > userlist.txt
```
**- linux,enumeration,user information,smb**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 36. Convert a user list in format "first last" to flast
```
cat users | awk '{print substr ($0, 1, 1),$2}' | tr [A-Z] [a-z] | sort | uniq
```
**- linux,bash,enumeration,user information,recon**
#### References:

https://necurity.co.uk
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 37. create medusa or hydra password list from cracked hashes
```
cat DC_dump.txt | awk -F : '{print $1":"$4}' | sort -k 2 -t : > sorted_hash; cat ntlm_cracked | sort -k 1 > sorted_cracked; join -t : -1 2 sorted_hash -2 1 sorted_cracked  >> pass_info
```
**- pivoting,passwords,enumeration,user information,cracking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 38. list users without password
```
logins -p
```
**- enumeration,user information,solaris**
#### References:

http://www.net.uom.gr/Books/Manuals/usail/man/solaris/logins.1.html
__________
### 39. system information
```
ver
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb491028.aspx
__________
### 40. remote system info
```
systeminfo /S [victim] /U [domain]/[user] /P [pass]
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491007.aspx
__________
### 41. search for text in the reg
```
reg query HKLM /f [text]  /t REG SZ /s
```
**- enumeration,Windows,privilege escalation,forensics**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc742028(v=ws.11).aspx
__________
### 42. grep for text in files
```
findstr /si [text] '.txt|xml|xls'
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-gb/library/bb490907.aspx
__________
### 43. show hosts in the current domain or add a domain for searching
```
net view /domain
```
**- networking,enumeration,dns,Windows,recon**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490719.aspx
__________
### 44. current smb shares
```
net share
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 45. active sessions
```
net session
```
**- enumeration,smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 46. show dnscache
```
ipconfig /displaydns
```
**- networking,enumeration,dns,Windows,forensics**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 47. listening ports
```
netstat -anop | findstr LISTEN
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc940097.aspx
https://technet.microsoft.com/en-us/library/bb490947.aspx
__________
### 48. show interface information
```
netsh interface ip show
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 49. Domain and DC info
```
wmic ntdomain list
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 50. list patches
```
wmic qfe
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 51. view logical shares
```
wmic logicaldisk get description,name
```
**- enumeration,Windows,filesystem**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 52. get logged in users from the remote host
```
wmic /node:[victim] computersystern get username
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 53. list remote processes every second
```
wmic /node:[victim] process list brief /every:1
```
**- enumeration,Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 54. How many times has someone logged in
```
wmic netlogin where (name like "%[user]%") get numberoflogons
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 55. unquoted service path search add node for remote sys
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\windows\\" | findstr /i /v """
```
**- enumeration,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 56. list of drives : cd Env:\ . . . mind . . . blown
```
get-psdrive
```
**- enumeration,interesting,Windows,configuration,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-psdrive
__________
### 57. get system information
```
Get-WmiObject -class win32 operatingsystem | select -property * | exportcsv c:\temp\os.txt
```
**- enumeration,Windows,powershell**
#### References:

http://www.energizedtech.com/2010/03/powershell-check-your-windows.html
__________
### 58. list hostname and ip for domain pc's
```
Get-WmiObject -ComputerName [DC] -Namesapce root\microsoftDNS -class MicrosoftDNS_ResourceRecord -Filter "domainname='[domain]' | select textrepresentation
```
**- enumeration,dns,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 59. Windows information in the reg
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion
```
**- enumeration,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 60. Mapped drives in reg
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
```
**- enumeration,smb,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 61. Machine or User software
```
HKLM|HKCU\Software
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 62. Recent Documents
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 63. Recent user location (MRU Most Recntly used)
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU & \OpenSaveMRU
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 64. Typed Urls
```
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```
**- enumeration,dns,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 65. list users
```
dsquery user -limit 0
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 66. List groups for domain.com
```
dsquery group "cn=users,dc=[domain],dc=[tld]"
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 67. Get Domain admins (prefer net groups "domain Admins")
```
dsquery group -name "domain admins" | dsget group -members -expand
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 68. get groups for user (net groups [user])
```
dsquery user -name [user] | dsget user -memberof -expand
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 69. get user login name
```
dsquery user -name [user] | dsget user -samid
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 70. List accounts that have been inactive for two weeks
```
dsquery user -inactive 2
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 71. List os's in the domain
```
dsquery * "DC=[domain],DC=[tld]" -scope subtree -attr "cn" "opperatingSystem"
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc731823(v=ws.11).aspx
__________
### 72. list site names
```
dsquery site -o rdn -limit 0
```
**- enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc731823(v=ws.11).aspx
__________
### 73. list subnets within the sites shown
```
dsquery subnet -site [site] -o rdn
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc732207(v=ws.11).aspx
__________
### 74. list servers within site
```
dsquery server -site [site] -o rdn
```
**- enumeration,dns,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc732885(v=ws.11).aspx
__________
### 75. list DC's
```
host [domain]
```
**- linux,enumeration,dns**
#### References:

https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 76. do a zone transfer request (just use host . . .)
```
dnsrecon -t axfr -d [domain]
```
**- linux,networking,enumeration,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 77. generate user list from PDF's, you can get more info to such as pdf maker
```
for i in *; do pdfinfo $i | egrep -i "Auth"; done  | sort
```
**- loop,enumeration,user information,interesting,recon**
#### References:

http://linuxcommand.org/man_pages/pdfinfo1.html
__________
### 78. list installed patches on windows
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
**- enumeration,Windows,privilege escalation**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
__________
### 79. Ask for a zone transfer
```
host -t axfr [ip]
```
**- linux,networking,enumeration**
#### References:

https://tools.ietf.org/html/rfc5936
__________
### 80. show users rlogin
```
rusers -al [ip]
```
**- linux,enumeration**
#### References:

http://linuxcommand.org/man_pages/rusers1.html
__________
### 81. List users of the remote system
```
samrdump.py -hashes [LMHASH:NTHASH] [user]:[pass]@[victim]
```
**- linux,enumeration,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 82. Show remote users using finger : Not installed by default? : use 0@[ip] for Solaris bug
```
finger @[ip]
```
**- linux,enumeration**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 83. Fingerprint remote oracle server
```
tnscmd10g version -h [victim]
```
**- enumeration,Oracle**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
http://cyborg.ztrela.com/tnscmd10g.php/
__________
### 84. Get Current user oracle DB : CMD new lines removed
```
CREATE OR REPLACE FUNCTION GETDBA(FOO varchar) return varchar deterministic authid curren_user is pragma autonomous_transaction; begin execute immediate 'grant dba to user1 identified by pass1'; commit; return 'FOO'; end;
```
**- enumeration,Oracle**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 85. Check for accounts that don't have password expiry set
```
Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol | export-csv U-DONT_EXPIRE_PASSWORD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 86. Check for accounts that have no password requirement
```
Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol | export-csv U-PASSWD_NOTREQD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 87. Accounts that have the password stored in a reversibly encrypted format
```
Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol | export-csv U-ENCRYPTED_TEXT_PWD_ALLOWED.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 88. List users that are trusted for Kerberos delegation
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
### 89. List accounts that don't require pre-authentication
```
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | export-csv U-DONT_REQUIRE_PREAUTH.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 90. List accounts that have credentials encrypted with DES
```
Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol | export-csv U-USE_DES_KEY_ONLY.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 91. Dump Ldap structure
```
ldapsearch -x -LLL -E pr=200/noprompt -h [victim] -D "[domain]\\[user]" -w '[password]' -b "dc=[fqdn],dc=co,dc=uk"
```
**- enumeration,user information,ldap**
#### References:

https://www.centos.org/docs/5/html/CDS/ag/8.0/Finding_Directory_Entries-Using_ldapsearch.html
https://access.redhat.com/documentation/en-US/Red_Hat_Directory_Server/8.2/html/Administration_Guide/Examples-of-common-ldapsearches.html
https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_9.0.1/admin/conf_examplesofusingldapsearch_t.html
__________
### 92. EICAR Test string
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
**- enumeration,Anti Virus**
#### References:

https://en.wikipedia.org/wiki/EICAR_test_file
__________
### 93. enumerate users and groups
```
getent passwd; getent group;
```
**- linux,enumeration**
#### References:

https://www.unixtutorial.org/commands/getent/
__________
### 94. Piped to tee for later manipulation
```
ping6 -c1 -I < [Interface] ff02::1 | tee ipv6-hosts
```
**- enumeration,ipv6**
#### References:

https://superuser.com/questions/840767/ipv6-multicast-address-for-all-nodes-on-network
__________
