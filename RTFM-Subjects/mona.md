### 1. Work out if there are any juicy targets to look for a jmp esp in (imunity debuger)
```
!mona modules
```
**- buffer overflow,mona**
#### References:

https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/
https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/
https://github.com/corelan/mona
__________
### 2. Look for a JMP ESP in the DLL found in the mona modules
```
!mona find '\xff\xef' -m [dll]
```
**- buffer overflow,mona**
#### References:

https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/
https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/
https://github.com/corelan/mona
__________
