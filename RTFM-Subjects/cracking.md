### 1. KeePass2 Cracking
```
wine KeeCracker.exe -w /data/hacking/dictionaries/rockyou.dic -t 4 Database.kdbx
```
**- linux,passwords,Windows,cracking**
#### References:

https://yg.ht
http://www.cervezhack.fr/2013/02/12/bruteforce-a-keepass-file/?lang=en
__________
### 2. IKE Agressive
```
psk-crack -d [word list e.g. rockyou.txt] [input key file]
```
**- linux,cracking**
#### References:

http://carnal0wnage.attackresearch.com/2011/12/aggressive-mode-vpn-ike-scan-psk-crack.html
__________
### 3. WIFI WPA handshake prep
```
wpaclean [OUTPUT] [INPUT]
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 4. WIFI WPA handshake prep
```
aircrack-ng [INPUT.cap] -J [OUTPUT]
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=cracking_wpa
__________
### 5. wep crack : 1) start capturing IV's
```
airodump-ng -c 11 --bssid [VICTIM MAC] -w [OUTPUT] mon0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 6. wep crack 2) De auth clients
```
aireplay-ng -0 0 --ignore-negative-one -e [SSID] -a [AP MAC] -c [VICTIM MAC] mon0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 7. wep crack 3) Create a fake auth to the AP
```
aireplay-ng -1 0 -e [VICTIM SSID] -a [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,networking,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 8. wep cracking
```
aireplay-ng -3 -b [VICTIM MAC] -h [OurMac] wlan0
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 9. wep cracking
```
aircrack-ng -b [VICTIM MAC] [OUTPUT]*cap
```
**- linux,wireless,wifi,cracking**
#### References:

https://www.aircrack-ng.org/doku.php?id=simple_wep_crack
__________
### 10. Word list generator
```
./mp64.bin -o custom.dic -1 tT -2 eE3 -3 ?s ?1qq?2qqq?2?2qq?2?3?3
```
**- linux,passwords,Windows,cracking**
#### References:

https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 11. Word list generator
```
/data/hacking/hashcat-0.49/hashcat-cli64.bin -m 99999 wordseed.dic -r /data/hacking/hashcat-0.49/rules/leetspeak.rule --stdout | sort -u > custom.dic
```
**- linux,Windows,cracking**
#### References:

https://yg.ht
https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 12. hashcat cpu
```
./hashcat-cli64.bin --session=[SESSIONNAME] -m[hash ID] [input file] [dict file] --rules rules/[rule file e.g. best64.rule d3ad0ne.rule etc]
```
**- linux,Windows,cracking**
#### References:

https://hashcat.net/wiki/
__________
### 13. hashcat assuming that hc is an alias (kraken | pablo)
```
hc --gpu-temp-abort=100 --remove -m5500 netntlmv1.hash -a3 -1 '?u?l?d' '?1?1?1?1?1?1?1?1' -o hash.crack
```
**- linux,hashes,cracking**
#### References:

https://hashcat.net/wiki/
__________
### 14. hashcat types
```
500  MD5 Crypt $1 | 7400 SHA256 Crypt $5 | 1800 Sha512 Crypt $6
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 15. hashcat types
```
1000 NTLM | 3000 LM
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 16. hashcat types
```
1100 MScashv1 | 2100 MScashv2 (802.1X)
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 17. hashcat types
```
2500 WPA/WPA2
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 18. hashcat types
```
5600 NetNTLMv2 | 5500 NetNTLMv1 | 5400 = IKE-PSK SHA1 | 5300 = IKE-PSK MD5 |
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 19. create medusa or hydra password list from cracked hashes
```
cat DC_dump.txt | awk -F : '{print $1":"$4}' | sort -k 2 -t : > sorted_hash; cat ntlm_cracked | sort -k 1 > sorted_cracked; join -t : -1 2 sorted_hash -2 1 sorted_cracked  >> pass_info
```
**- pivoting,passwords,enumeration,user information,cracking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 20. Crack a ZIP file with a wordlist
```
fcrackzip -D -p 'x' -u test.zip
```
**- cracking**
#### References:

http://allanfeid.com/content/cracking-zip-files-fcrackzip
__________
### 21. Crack a zip, brute force a 4 char password 
```
fcrackzip -D -p 'x' -u test.zip
```
**- cracking**
#### References:

http://allanfeid.com/content/cracking-zip-files-fcrackzip
__________
### 22. Crack a zip file, Note: Older enc only
```
patator.py unzip_pass zipfile=[file] password=FILE0 0=[pass.txt] -x ignore:code!=0
```
**- cracking,brute force**
#### References:

https://github.com/lanjelot/patator
__________
