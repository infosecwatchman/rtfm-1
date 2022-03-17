### 1. Fierce (v0.9) - DNS bruteforcer
```
fierce -threads 10 -dns [domain] -wordlist [wordlist] -dnsserver 8.8.8.8 -file fierce.txt
```
**- linux,networking,scanning,dns**
#### References:

https://github.com/mschwager/fierce
ha.ckers.org/fierce/
__________
### 2. dump dns zone on DC
```
dnscmd 127.0.0.1 /ZoneExport [FQDN] [OUT].zone
```
**- enumeration,dns,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc772069(v=ws.11).aspx
__________
### 3. DNS zone transfer
```
dig -t AXFR [FQDN] @[SERVER IP]
```
**- linux,networking,dns**
#### References:

http://www.thegeekstuff.com/2012/02/dig-command-examples
__________
### 4. network discovery RDNS
```
for a in {0..255}; do host -t ns $a.168.192.in-addr.arpa | grep -v "name server"; done >> networks.txt
```
**- networking,loop,scanning,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 5. network discovery RDNS
```
cat networks-dirty.txt | grep "^[0-9]" | awk {'print $1'} | awk -F "." {'print $3"."$2"."$1".0/24"'} | sort -u > nets.txt
```
**- networking,loop,enumeration,dns**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 6. show hosts in the current domain or add a domain for searching
```
net view /domain
```
**- networking,enumeration,dns,Windows,recon**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490719.aspx
__________
### 7. show dnscache
```
ipconfig /displaydns
```
**- networking,enumeration,dns,Windows,forensics**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 8. get dns addr tab after :: for more choices
```
[Net.DNS]::GetHostEntry("ip")
```
**- dns,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/ms143998(v=vs.110).aspx
__________
### 9. list hostname and ip for domain pc's
```
Get-WmiObject -ComputerName [DC] -Namesapce root\microsoftDNS -class MicrosoftDNS_ResourceRecord -Filter "domainname='[domain]' | select textrepresentation
```
**- enumeration,dns,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 10. Typed Urls
```
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```
**- enumeration,dns,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 11. list servers within site
```
dsquery server -site [site] -o rdn
```
**- enumeration,dns,Windows**
#### References:

https://technet.microsoft.com/en-us/library/cc732885(v=ws.11).aspx
__________
### 12. list DC's
```
host [domain]
```
**- linux,enumeration,dns**
#### References:

https://www.cyberciti.biz/faq/linux-unix-host-command-examples-usage-syntax/
__________
### 13. Reverse look up on range
```
dnsrecon -t rvs -i 10.0.0.1,10.0.0.255
```
**- linux,scanning,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 14. brute names
```
dnsrecon -t std -d [domain]
```
**- linux,scanning,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 15. do a zone transfer request (just use host . . .)
```
dnsrecon -t axfr -d [domain]
```
**- linux,networking,enumeration,dns**
#### References:

https://github.com/darkoperator/dnsrecon
__________
### 16. look for a free short domain, good luck
```
for a in {a..z}; do for b in {a..z}; do for c in {a..z}; do for d in {a..z}; do whois $a$b.$c$d; done; done;done;done
```
**- linux,networking,loop,dns**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 17. Generate and test domain typos and variations to detect and perform typo squatting, URL hijacking, phishing, and corporate espionage.
```
urlcrazy [domain]
```
**- web application,dns,recon**
#### References:

https://www.morningstarsecurity.com/research/urlcrazy
__________
