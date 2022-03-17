### 1. Do a quick nmap of the top 1000 UDP, all TCP, and common HTTP ports
```
nmap -sU --top-ports 1000 -oA clientname_udp -iL scope -v --open & nmap -A -oA clientname_ce -p- -iL scope -v --open & nmap -A -oA clientname_ce_quick --script /usr/share/nmap/scripts/http-screenshot.nse -p 80,443,21,22,23,25,109,110,990,465,1194,1723,8080,8081,8443,8843,8000,9000,9090,9081,9091,8194,9103,9102,8192 -iL scope -v --open;
```
**- Cyber Essentials,tools**
#### References:

https://necurity.co.uk
https://www.ncsc.gov.uk/content/files/scheme_downloads/cyber-essentials-test-specs.pdf
__________
