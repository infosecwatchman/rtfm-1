### 1. Mount a NFS share (check for root squash)
```
mount -t nfs 10.0.0.2:[/their/share] [/Mount/point] -o nolock
```
**- nfs,fileshare**
#### References:

https://www.centos.org/docs//4/4.5/Reference_Guide/s2-nfs-client-config-options.html
__________
