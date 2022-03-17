### 1. Windows process list
```
tasklist /v
```
**- enumeration,Windows,process management,privilege escalation**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 2. Windows force kill process
```
taskkill /f /im [PROCESS]
```
**- Windows,process management**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 3. list services
```
svsc -a
```
**- process management,solaris**
#### References:

http://www.oracle.com/technetwork/articles/servers-storage-admin/intro-smf-basics-s11-1729181.html
__________
### 4. list processes
```
prstat -a
```
**- process management,solaris**
#### References:

http://docs.oracle.com/cd/E19253-01/816-5166/prstat-1m/index.html
http://solaris.reys.net/prstat-a-great-tool-for-process-monitoring/
__________
### 5. list all processes
```
wmic process list full
```
**- Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 6. kill process
```
wmic process where name="[cmd]" call terminate
```
**- Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 7. list remote processes every second
```
wmic /node:[victim] process list brief /every:1
```
**- enumeration,Windows,process management**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 8. powershell services
```
get-service
```
**- Windows,powershell,process management**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-service
__________
