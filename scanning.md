### 1. syn scan port range with hping
```
hping3 -8 [port]-[port] -S [ip] -V
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 2. ACK scan on port
```
hping3 -A [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 3. Xmas' scan
```
hping3 -F -p -U [ip] -p [port]
```
**- linux,bash,networking,scanning**
#### References:

http://wiki.hping.org/
__________
### 4. Quick scan to set us off
```
nmap -sS -P0 -T4 -n -iL info/ips.txt -oA nmap/quick-scan
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 5. Quick scan of all the hosts (ignore pinging)
```
nmap -sS -P0 -T4 -Pn -n -iL info/ips.txt -oA nmap/quick-scan
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 6. Source port spoofing
```
nmap -sS -P0 -T4 -p0-65535 -n -g 80 -iL info/ips.txt -oA nmap/source-port
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 7. All port scan : assume up
```
nmap -sS -sU -T4 -Pn -p0-65535 -n -iL info/ips.txt -oA nmap/all-ports
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 8. OS Detection
```
nmap -sS -P0 -T4 -n -A -iL info/ips.txt -oA nmap/os-discovery
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 9. Find sql servers
```
nmap -sS -P0 -T5 -n -p 1433 -iL info/ips.txt -oA nmap/internal-sqls
```
**- networking,scanning**
#### References:

https://wiki.archlinux.org/index.php/Nmap
__________
### 10. Skipfish scanner
```
skipfish -O -MEU -o results-nonauth -W ~/pentest/wordlists/skipfish.wl -k 00:30:00 https://[ip]
```
**- scanning,web application**
#### References:

https://github.com/spinkham/skipfish
__________
### 11. Default community string in SNMP
```
snmpwalk -v 1 -c public [TARGET]
```
**- linux,bash,scanning,brute**
#### References:

http://net-snmp.sourceforge.net/docs/man/snmpwalk.html
__________
### 12. Fierce (v0.9) - DNS bruteforcer
```
fierce -threads 10 -dns [domain] -wordlist [wordlist] -dnsserver 8.8.8.8 -file fierce.txt
```
**- linux,networking,scanning,dns**
#### References:

https://github.com/mschwager/fierce
ha.ckers.org/fierce/
__________
### 13. Yaps windows portscan, upload first duh
```
yaps.exe -start -start_address [victim] -stop_address [victim] -start_port [port] -stop_port [port] -timeout 5 -resolve n
```
**- networking,scanning,Windows**
#### References:

http://www.steelbytes.com/?mid=19
__________
### 14. harvester
```
/data/hacking/theHarvester/theHarvester.py -h -d [domain] -l 1000 -b all | tee harvester-search-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 15. harvester linkedin
```
/data/hacking/theHarvester/theHarvester.py -d [domain] -l 1000 -b linkedin | tee harvester-people-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 16. Single Nessus Module
```
/opt/nessus/bin/nessuscmd -U -O -p[port] -V -i [plugin ID] [target IP]
```
**- scanning,nessus**
#### References:

https://yg.ht
https://docs.tenable.com/nessus/6_7/Content/Command_Line/nessuscli.htm
__________
### 17. IKE Agressive
```
ike-scan -A -v -id=test -f [input file] -P[PSK output file]
```
**- linux,scanning**
#### References:

https://github.com/royhills/ike-scan
http://carnal0wnage.attackresearch.com/2011/12/aggressive-mode-vpn-ike-scan-psk-crack.html
__________
### 18. ARPing
```
arping -I em1 [TARGET IP]
```
**- linux,networking,scanning**
#### References:

https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 19. ARPing sweep network
```
for a in {0..254}; do arping -D -c 1 -I eth0 [NETWORK].$a; done | tee arping-[NET].txt
```
**- linux,networking,loop,scanning**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-duplicate-address-detection-with-arping/
__________
### 20. NBTScan
```
nbtscan -v -s : 192.168.0.0/24 >> nbtscan-[SUBNET].txt
```
**- linux,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 21. NBTScan en masse
```
for a in {0..254}; do nbtscan -v -s : 192.168.$a.0/24 >> nbtscan-192.168.$a.txt; done
```
**- linux,loop,scanning,smb**
#### References:

https://yg.ht
http://unixwiz.net/tools/nbtscan.html
__________
### 22. network discovery RDNS
```
for a in {0..255}; do host -t ns $a.168.192.in-addr.arpa | grep -v "name server"; done >> networks.txt
```
**- networking,loop,scanning,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 23. network discovery RDNS
```
nmap -sS -n -v -T5 -iL networks-sorted.txt -oA nmapScan-ARP
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 24. network discovery RDNS
```
cat nmapScan-ARP.gnmap | grep "Status: Up" | awk {'print $2'} | awk -F "." {'print $1"."$2"."$3".0/24"'} | sort -u > networks-withlivehosts.txt
```
**- linux,networking,scanning**
#### References:

https://yg.ht
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 25. load balance detection
```
halberd -v -p 10 [URL]
```
**- linux,networking,scanning,web application**
#### References:

https://github.com/jmbr/halberd
__________
### 26. Check for vlans that you can hop to : may need to change the grep for interfaces
```
frogger.sh
```
**- bash,networking,scanning**
#### References:

https://github.com/nccgroup/vlan-hopping---frogger
__________
### 27. sslscan, you will want to git clone and make static if your in kali
```
for a in $(cat ../nmap/IPs-HTTPS.txt); do sslscan $a; done | tee sslscan-[NET].txt
```
**- loop,scanning,certificates**
#### References:

https://yg.ht
https://github.com/rbsec/sslscan
__________
### 28. nmap outbound tcp
```
nmap -sS -Pn --open -T5 -p- [portspoofip] | tee nmap-tcp-outbound.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 29. nmap outbound upd
```
nmap -Pn --open -T5 -sU -p- [portspoofip]| tee nmap-udp-outbound.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 30. nmap smb signing
```
nmap --script smb-security-mode.nse -p445 -iL [hostsfile] -oA nmap-SMBSigning
```
**- linux,networking,scanning,smb,MitM**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 31. nmap devicemap all tcp
```
nmap -sS -n -v -T4 -P0 -p- -oA nmap-tcp-scan -iL subnets.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 32. nmap devicemap top 1000 udp
```
nmap -sU -n -v -T4 -P0 --top-ports 1000 -oA nmap-udp-scan -iL subnets.txt
```
**- linux,networking,scanning**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 33. Take a screenshot of a HTTP service
```
nmap -iL hosts -sC --script http-screenshot -p 80,443,8080,8081,8443,8843,8000,9000,9090,9081,9091,8194,9103,9102,8192,6992,16993,16994,16995,623,664 -v -n
```
**- linux,networking,scanning**
#### References:

https://necurity.co.uk/netsec/2015-04-20-Screenshots-with-Nmap/
https://github.com/SpiderLabs/Nmap-Tools/commit/36d74325f5ed5a057f954c1f9dd962631766ca10
__________
### 34. Take a screenshot of a RDP server (provided by rdpy)
```
rdpy-rdpscreenshot.py 1.1.1.1
```
**- linux,scanning,recon**
#### References:

https://github.com/citronneur/rdpy
__________
### 35. take a screenshot from a open X11 and convert it to a jpg
```
xwd -display [victim] :0 -root -out /tmp/[victim].xpm;xwd -display ip :0 -root -out /tmp/[victim].xpm; convert /tmp/[victim]; xpm -resize 1280x1024 /tmp/[victim].jpg
```
**- linux,bash,pivoting,scanning**
#### References:

http://unix.stackexchange.com/questions/44821/how-do-i-screencap-another-xorg-display
__________
### 36. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 37. Reverse look up on range
```
dnsrecon -t rvs -i 10.0.0.1,10.0.0.255
```
**- linux,scanning,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 38. brute names
```
dnsrecon -t std -d [domain]
```
**- linux,scanning,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 39. tcp port scanning from bash, just wireshark on the ip, useful if you have cmd execution on web app
```
for i in {1..65000}; do echo 1 > /dev/tcp/[ip]/$i; echo $i; done
```
**- linux,bash,networking,loop,interesting,scanning**
#### References:

http://tldp.org/LDP/abs/html/devref1.html
__________
### 40. Do a netbios name query.
```
nmblookup [name]
```
**- linux,scanning,smb**
#### References:

http://linuxcommand.org/man_pages/nmblookup1.html
__________
### 41. Try to brute the remote group name : cisco
```
./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1
```
**- cisco,scanning,brute**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
https://github.com/SpiderLabs/ikeforce
https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-1)/
__________
### 42. Brute force PPTP password
```
thc-pptp-bruter -u [username] -W -w /usr/share/wordlists/nmap.lst
```
**- scanning,brute**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 43. Grab Succsessfull passwords from a tee'd medusa, bah to spaces in usernames
```
cat [file]  | grep "ACCOUNT FOUND" | grep -v 0x000072:STATUS_ACCOUNT_DISABLED | awk  -F User: '{print $2}' | awk -F : '{print $1, $2}' | awk -F \\[SUC '{print $1}' | awk -F " Password  " '{print $1":"$2}' | sort | sed s/' '/''/| uniq 
```
**- scanning,hashes**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
http://foofus.net/goons/jmk/medusa/medusa.html
__________
### 44. Take the active users output and create filled in CMD's, course it can be anything, not just TSQL
```
for i in `cat ../clean_creds`; do echo $i | awk -F : '{print "tsql -S [IP] -p 1433 -U [domain]\\\\"$2" -P "$3}'; done
```
**- bash,loop,scanning**
#### References:

https://www.cyberciti.biz/faq/bash-for-loop/
__________
