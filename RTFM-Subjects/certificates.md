### 1. # Verify the certificate / private key association
```
openssl x509 -noout -modulus -in [CERT] | openssl md5
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 2. https://www.sslshopper.com/article-most-common-openssl-commands.html
```
openssl x509 -in certificate.crt -text
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 3. Grab the hostname in the certificate
```
echo "" | openssl s_client -connect [ip]:443 2>/dev/null| grep ^subject | sed 's/^.*CN=//'
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
__________
### 4. Create Self-signed cert / key
```
name=sslfile;openssl genrsa -out $name.key 2048;openssl req -new -key $name.key -out $name.csr; openssl x509 -req -days 10 -in $name.csr -signkey $name.key -out $name.crt;openssl pkcs12 -export -clcerts -in $name.crt -inkey $name.key -out $name.p12;openssl pkcs12 -in $name.p12 -out $name.pem -clcerts
```
**- linux,bash,certificates**
#### References:

https://yg.ht
https://www.sslshopper.com/article-how-to-create-a-self-signed-certificate.html
__________
### 5. 'Telnet' s_client to SSL
```
openssl s_client -connect [domain]:443
```
**- linux,certificates**
#### References:

https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 6. sslscan, you will want to git clone and make static if your in kali
```
for a in $(cat ../nmap/IPs-HTTPS.txt); do sslscan $a; done | tee sslscan-[NET].txt
```
**- loop,scanning,certificates**
#### References:

https://yg.ht
https://github.com/rbsec/sslscan
__________
### 7. sslscan cert checks
```
openssl s_client -connect victim.com:443 (this shows the chain)
```
**- linux,certificates**
#### References:

http://security.stackexchange.com/questions/70733/how-do-i-use-openssl-s-client-to-test-for-absence-of-sslv3-support
__________
### 8. sslscan cert checks
```
openssl s_client -showcerts -connect victim.com:443 2>/dev/null | awk '$0=="-----BEGIN CERTIFICATE-----" {p=1}; p; $0=="-----END CERTIFICATE-----" {p=0}' (this pulls just the certificates for each in the chain)
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
### 9. sslscan cert checks
```
openssl x509 -noout -text | grep -i "signature algorithm\|before\|after\|issuer\|subject:" (split the above commands output and stick in here, then manually analyse)
```
**- linux,bash,certificates**
#### References:

https://www.sslshopper.com/article-most-common-openssl-commands.html
https://yg.ht
https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
__________
