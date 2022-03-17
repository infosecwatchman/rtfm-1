### 1. harvester
```
/data/hacking/theHarvester/theHarvester.py -h -d [domain] -l 1000 -b all | tee harvester-search-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 2. harvester linkedin
```
/data/hacking/theHarvester/theHarvester.py -d [domain] -l 1000 -b linkedin | tee harvester-people-[DETAIL].txt
```
**- linux,user information,scanning,recon**
#### References:

https://yg.ht
http://www.edge-security.com/theharvester.php
__________
### 3. Convert a user list in format "first last" to flast
```
cat users | awk '{print substr ($0, 1, 1),$2}' | tr [A-Z] [a-z] | sort | uniq
```
**- linux,bash,enumeration,user information,recon**
#### References:

https://necurity.co.uk
http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 4. Take a screenshot of a RDP server (provided by rdpy)
```
rdpy-rdpscreenshot.py 1.1.1.1
```
**- linux,scanning,recon**
#### References:

https://github.com/citronneur/rdpy
__________
### 5. show hosts in the current domain or add a domain for searching
```
net view /domain
```
**- networking,enumeration,dns,Windows,recon**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490719.aspx
__________
### 6. generate user list from PDF's, you can get more info to such as pdf maker
```
for i in *; do pdfinfo $i | egrep -i "Auth"; done  | sort
```
**- loop,enumeration,user information,interesting,recon**
#### References:

http://linuxcommand.org/man_pages/pdfinfo1.html
__________
### 7. Generate and test domain typos and variations to detect and perform typo squatting, URL hijacking, phishing, and corporate espionage.
```
urlcrazy [domain]
```
**- web application,dns,recon**
#### References:

https://www.morningstarsecurity.com/research/urlcrazy
__________
