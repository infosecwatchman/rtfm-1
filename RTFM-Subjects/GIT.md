### 1. GitUp : Update all the opt gits
```
for i in $(ls -alh /data/shares/opt/ | grep "^drw" | awk '{print $9}'); do cd /data/shares/opt/$i; git pull; echo $i;done | grep -v fatal
```
**- linux,interesting,GIT**
#### References:

https://yg.ht
__________
