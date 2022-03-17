### 1. Mount Sysvol share (hosted on the DC)
```
mount -t cifs \\\\[victim]\\SYSVOL -o username=[user],password=[password] mount/; nautilus mount/;
```
**- linux,files,smb,filesystem**
#### References:

https://www.cyberciti.biz/faq/linux-mount-cifs-windows-share/
__________
### 2. moount VDI disk image
```
modprobe nbd  max_part=16;  qemu-nbd -c /dev/nbd0 [File]; fdisk -l /dev/nbd0
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 3. Mount LVM filesytem / image
```
losetup /dev/loop0 [file]; kpartx -a /dev/loop0; vgscan; vgchange -ay changethishostname-vg; mount /dev/changethishostname-vg/root mnt/
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 4. Ecrypt FS mounting
```
printf "%s" $i | ecryptfs-unwrap-passphrase .ecryptfs/victim/.ecryptfs/wrapped-passphrase -; ecryptfs-add-passphrase -fnek; mount -t ecryptfs .ecryptfs/victim/.Private/ test/
```
**- linux,filesystem**
#### References:

https://necurity.co.uk/osprog/2016-04-09-mount-cheatsheat/
__________
### 5. view logical shares
```
wmic logicaldisk get description,name
```
**- enumeration,Windows,filesystem**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
