### 1. hashcat types
```
500  MD5 Crypt $1 | 7400 SHA256 Crypt $5 | 1800 Sha512 Crypt $6
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 2. hashcat types
```
1000 NTLM | 3000 LM
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 3. hashcat types
```
1100 MScashv1 | 2100 MScashv2 (802.1X)
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 4. hashcat types
```
2500 WPA/WPA2
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 5. hashcat types
```
5600 NetNTLMv2 | 5500 NetNTLMv1 | 5400 = IKE-PSK SHA1 | 5300 = IKE-PSK MD5 |
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 6. Networking Time to Live
```
Window Size: 5840 = Linux | 5720 = Google Nix | 65535 = XP or BSD | 8192 = Visa and above | 4128 = Cisco Router
```
**- networking,interesting,reference**
#### References:

https://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/
__________
### 7. please use ipcalc, there is no l33tness in doing it in your head
```
Subnet ranges : /20 255.255.240.0 4096 hosts
```
**- networking,subnets,reference**
#### References:

https://www.aelius.com/njh/subnet_sheet.html
__________
### 8. Ip subnets
```
ipcalc -bnmp 10.0.0.1/20
```
**- linux,networking,subnets,reference**
#### References:

https://www.cyberciti.biz/tips/perform-simple-manipulation-of-ip-addresse.html
__________
### 9. Hash byte lengths
```
hash lengths : MD5=16 | SHA1=20 | SHA256=32 | SHA512=64
```
**- hashes,reference**
#### References:

https://en.wikipedia.org/wiki/List_of_hash_functions
__________
### 10. Common operations on data
```
https://gchq.github.io/CyberChef/
```
**- interesting,reference,web address**
#### References:

https://gchq.github.io/CyberChef/
__________
### 11. Internal Address ranges, 100 is for routing
```
10.0.0.0/8 (10.255.255.255) | 172.16.0.0/12 (172.31.255.255) | 192.168.0.0/16 | 100.64.0.0/10 (10.127.255.255)
```
**- networking,reference**
#### References:

https://tools.ietf.org/html/rfc1918
__________
### 12. Show a compact ascii table
```
man -P 'less -p ".*Tables"' ascii
```
**- reference,encoding,ascii,web app**
#### References:

http://man7.org/linux/man-pages/man7/ascii.7.html
__________
