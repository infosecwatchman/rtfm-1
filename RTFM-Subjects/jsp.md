### 1. Echo hello world, test for RCE in JSP application.
```
<%="Hello Word"%>
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 2. Echo hello world, test for RCE in JSP application.
```
out.print("Hello World");
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
### 3. Echo hello world, test for RCE in JSP application.
```
<c:out value="${[variableName]}" />
```
**- web application,code execution,jsp**
#### References:

https://stackoverflow.com/questions/5713013/echo-instruction-in-jsp
__________
