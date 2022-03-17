### 1. list installed programs
```
rpm -qa | less
```
**- linux,bash,package management**
#### References:

https://www.linux.com/blog/rpm-commands
__________
### 2. Equivlent of Yum whatprovides : What provides what file
```
apt-file update; apt-file search [xfreerdp]
```
**- package management**
#### References:

http://kvz.io/blog/2008/11/08/search-for-a-package-with-aptfile/
__________
### 3. Equivlent of apt-file search : What provides what file
```
yum whatproivdes 
```
**- package management**
#### References:

http://stackoverflow.com/questions/1133495/how-do-i-find-which-rpm-package-supplies-a-file-im-looking-for
__________
