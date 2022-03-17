### 1. Execute GroovyScript on Jenkins, You can also execute commands when ReBuilding projects. Also user addition has a path traversal vuln allowing you to override users when registering.
```
def process = "ls -l".execute();println "Found text ${process.text}"
```
**- linux,web application,Windows,code execution,Groovy**
#### References:

https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/
https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/
https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console
__________
