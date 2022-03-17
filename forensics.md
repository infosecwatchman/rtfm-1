### 1. list drives
```
fsutil fsinfo drives
```
**- Windows,forensics**
#### References:

https://technet.microsoft.com/en-us/library/cc753059(v=ws.11).aspx
__________
### 2. search for text in the reg
```
reg query HKLM /f [text]  /t REG SZ /s
```
**- enumeration,Windows,privilege escalation,forensics**
#### References:

http://www.fuzzysecurity.com/tutorials/16.html
https://technet.microsoft.com/en-us/library/cc742028(v=ws.11).aspx
__________
### 3. show dnscache
```
ipconfig /displaydns
```
**- networking,enumeration,dns,Windows,forensics**
#### References:

https://technet.microsoft.com/en-gb/library/bb490921.aspx
__________
### 4. txt files changed after the 13 Jan 2017
```
Get-ChildItem -Path c:\ -Force -Recurse -Filter *.txt -ErrorAction SilentlyContinue | where {$_.LastWriteTime -gt "2017-01-13"}
```
**- files,Windows,powershell,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 5. Windows information in the reg
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion
```
**- enumeration,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 6. Mapped drives in reg
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
```
**- enumeration,smb,Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 7. Mounted devices
```
HKLM\System\MountedDevices
```
**- Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 8. USB Devices
```
HKLM\System\CurrentControlSet\Enum\USBStor
```
**- Windows,forensics**
#### References:

https://www.offensive-security.com/metasploit-unleashed/msfvenom/
__________
### 9. Audit policy
```
HKLM\Security\Policy\PolAdTev
```
**- Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 10. Machine or User software
```
HKLM|HKCU\Software
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 11. Recent Documents
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 12. Recent user location (MRU Most Recntly used)
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU & \OpenSaveMRU
```
**- enumeration,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 13. Typed Urls
```
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```
**- enumeration,dns,Windows,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
