### 1. get password policy for root
```
chage -l root
```
**- linux,bash,passwords,enumeration,user information**
#### References:

http://www.thegeekstuff.com/2009/04/chage-linux-password-expiration-and-aging/
__________
### 2. password requirements domain
```
net accounts /domain
```
**- enumeration,Windows,users**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
__________
### 3. loop for who is where
```
for host in $(cat userhosts.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host 'WMIC ComputerSystem Get UserName'; done | tee loggedin-dirty.txt;cat loggedin-dirty.txt | grep -v "^\[" | grep -v "^Impacket" | grep -v "^Trying" | grep -v "SMB SessionError" | sed '/^$/d'
```
**- loop,enumeration,user information,smb,impacket**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 4. Powershell password last changed, run on DC
```
Get-ADUser -filter * -properties * | sort-object passwordlastset | select-object samaccountname, passwordlastset, passwordneverexpires, homedirectory, mail, enabled | Export-csv -path c:\temp\pwprofile.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://yg.ht
https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 5. loop to find local admins
```
for i in `cat smb_up `; do timeout 10 psexec.py [user]:[pass]@$i net localgroup administrators; done | tee local_admin_information
```
**- linux,loop,enumeration,user information,impacket**
#### References:

https://technet.microsoft.com/en-us/library/bb490706.aspx
__________
### 6. turn loop for local admins into csv
```
egrep -v "(\*\] T|\[\*\] F|[\*\] C|[\*\] U|[\*\] S|[\*\] R)" local_admin_information | egrep -v "(\[\*\] P|\[\*\] R|\[\*\] S|\[\*\] O|\[\*\] U)" | grep -v "Alias name" | grep -v "Administrators have complete" | grep -v \[\!\] | grep -v \[-\] | dos2unix | grep -v "^$" | sed s/"\[\*\] Creating service.*on"/''/g | grep -v Members | sed s/\\.\\.\\.\\.\\./','/g | sed s/"^ "/"€"/g | sed s/'The command completed successfully.'/€/g | tr "\n" "," | tr € "\n" | grep -v "^$" | sort | uniq  > local_admins.csv
```
**- linux,bash,text manipulation,loop,user information,interesting**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 7. RPCClient smb show users and groups
```
rpcclient -U '[DOMAIN]\[USER]'%'[PASS]' '[TARGET]' -c enumdomusers,enumdomgroups
```
**- linux,enumeration,user information,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages/rpcclient.1.html
__________
### 8. Domain Admins windows
```
net group "Domain Admins" /domain
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 9. harvester
```
/data/hacking/theHarvester/theHarvester.py -h -d [domain] -l 1000 -b all | tee harvester-search-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 10. harvester linkedin
```
/data/hacking/theHarvester/theHarvester.py -d [domain] -l 1000 -b linkedin | tee harvester-people-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 11. Add a domain user from the CLI
```
net user [user] [pass] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx
__________
### 12. Add [User] to the domain admins group
```
net group "Domain Admins" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 13. Add user to enterprise admins
```
net group "Enterprise Admins" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 14. Add user to the RDP group
```
net localgroup "Remote Desktop Users" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 15. Add a user to the local admin group, not as useful any more
```
net localgroup "Administrators" [user] /add /domain
```
**- user information,Windows,privilege escalation**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/cc754051(v=ws.11).aspx
__________
### 16. Get a listing of all users and groups for targeting your post exploitation
```
enum4linux.pl -a -u [USER] -p [PASS] [TARGET] | tee [CLIENTNAME].domainenum
```
**- linux,enumeration,user information,smb**
#### References:

https://labs.portcullis.co.uk/tools/enum4linux/
__________
### 17. Get a list of all the users in the domain from a full dump
```
cat [CLIENTNAME].domainenum | grep "^user" | cut -d ":" -f 2 | cut -d "]" -f 1 | cut -d "[" -f 2 > userlist.txt
```
**- linux,enumeration,user information,smb**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 18. Convert a user list in format "first last" to flast
```
cat users | awk '{print substr ($0, 1, 1),$2}' | tr [A-Z] [a-z] | sort | uniq
```
**- linux,bash,enumeration,user information,recon**
#### References:

https://necurity.co.uk
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 19. create medusa or hydra password list from cracked hashes
```
cat DC_dump.txt | awk -F : '{print $1":"$4}' | sort -k 2 -t : > sorted_hash; cat ntlm_cracked | sort -k 1 > sorted_cracked; join -t : -1 2 sorted_hash -2 1 sorted_cracked  >> pass_info
```
**- pivoting,passwords,enumeration,user information,cracking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 20. list users without password
```
logins -p
```
**- enumeration,user information,solaris**
#### References:

http://www.net.uom.gr/Books/Manuals/usail/man/solaris/logins.1.html
__________
### 21. get logged in users from the remote host
```
wmic /node:[victim] computersystern get username
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 22. How many times has someone logged in
```
wmic netlogin where (name like "%[user]%") get numberoflogons
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 23. list users
```
dsquery user -limit 0
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 24. List groups for domain.com
```
dsquery group "cn=users,dc=[domain],dc=[tld]"
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 25. Get Domain admins (prefer net groups "domain Admins")
```
dsquery group -name "domain admins" | dsget group -members -expand
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 26. get groups for user (net groups [user])
```
dsquery user -name [user] | dsget user -memberof -expand
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 27. get user login name
```
dsquery user -name [user] | dsget user -samid
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 28. List accounts that have been inactive for two weeks
```
dsquery user -inactive 2
```
**- enumeration,user information,Windows**
#### References:

https://technet.microsoft.com/fr-fr/library/cc725702(v=ws.10).aspx
__________
### 29. generate user list from PDF's, you can get more info to such as pdf maker
```
for i in *; do pdfinfo $i | egrep -i "Auth"; done  | sort
```
**- loop,enumeration,user information,interesting,recon**
#### References:

http://linuxcommand.org/man_pages/pdfinfo1.html
__________
### 30. Check for accounts that don't have password expiry set
```
Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol | export-csv U-DONT_EXPIRE_PASSWORD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 31. Check for accounts that have no password requirement
```
Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol | export-csv U-PASSWD_NOTREQD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 32. Accounts that have the password stored in a reversibly encrypted format
```
Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol | export-csv U-ENCRYPTED_TEXT_PWD_ALLOWED.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 33. List users that are trusted for Kerberos delegation
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
### 34. List accounts that don't require pre-authentication
```
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | export-csv U-DONT_REQUIRE_PREAUTH.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 35. List accounts that have credentials encrypted with DES
```
Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol | export-csv U-USE_DES_KEY_ONLY.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 36. Dump Ldap structure
```
ldapsearch -x -LLL -E pr=200/noprompt -h [victim] -D "[domain]\\[user]" -w '[password]' -b "dc=[fqdn],dc=co,dc=uk"
```
**- enumeration,user information,ldap**
#### References:

https://www.centos.org/docs/5/html/CDS/ag/8.0/Finding_Directory_Entries-Using_ldapsearch.html
https://access.redhat.com/documentation/en-US/Red_Hat_Directory_Server/8.2/html/Administration_Guide/Examples-of-common-ldapsearches.html
https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_9.0.1/admin/conf_examplesofusingldapsearch_t.html
__________
