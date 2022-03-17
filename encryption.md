### 1. OpenSSL Encypt, add -a if input is b64, 
```
openssl aes-256-cbc -in some_file.enc -out some_file.unenc -e -pass pass:somepassword
```
**- linux,bash,encryption**
#### References:

http://tombuntu.com/index.php/2007/12/12/simple-file-encryption-with-openssl/
__________
### 2. OpenSSL decrypt, add -a if input is b64, 
```
openssl aes-256-cbc -in some_file.enc -out some_file.unenc -d -pass pass:somepassword
```
**- linux,bash,encryption**
#### References:

http://tombuntu.com/index.php/2007/12/12/simple-file-encryption-with-openssl/
__________
