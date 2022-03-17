### 1. Use only the lines that match a given RegEX [TERM]
```
awk /^[TERM]/ '{print "See the",$1,"at the",$3}' words.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 2. Calculations using AWK. AWK is a huge language, not just for printing columns
```
awk '{print "Avg for",$1,"is",($2+$3+$4)/3}' grades.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 3. Print first and last lines of a file
```
awk 'NR==1;END{print}' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 4. Split the file on ; instead of space
```
awk -F ";" '{print $2}' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 5. Print a portion of the text
```
awk '/start_pattern/,/stop_pattern/' file.txt
```
**- linux,bash,text manipulation**
#### References:

http://www.thegeekstuff.com/2010/01/awk-introduction-tutorial-7-awk-print-examples
https://www.cyberciti.biz/faq/bash-scripting-using-awk/
__________
### 6. remove 4 chars
```
echo "hello fredrick" | sed 's/.\{4\}$//'
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 7. add space after each line
```
cat db.schema | sed G
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 8. convert a list into a multi line CSV
```
sed 's/ *$//;s/$/;/' linkedin.txt | paste - - - - | tr -d '\t'
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 9. # Add to the beginning of the line starting with a pattern
```
sed -i '/^[0-9]/ s/^/sshd: /' /etc/hosts.allow
```
**- linux,bash,text manipulation**
#### References:

http://www.grymoire.com/Unix/Sed.html
http://www.thegeekstuff.com/tag/sed-examples/
https://www.cyberciti.biz/faq/tag/sed-command/
__________
### 10. Fix nano <3 ;)
```
# rm -rf `which nano`; ln -s `which vim` /usr/bin/nano
```
**- bash,text manipulation,files,interesting**
#### References:

https://xkcd.com/378/
__________
### 11. Burpify JSON request
```
cat json.txt | sed "s/false/§false§/g" | sed "s/true/§true§/g" | sed "s/null/§null§/g" | sed "s/:\"/:\"§/g" | sed "s/\",/§\",/g" | sed "s/\"}/§\"}/g" | sed "s/\\[\\]/\\[§§\\]/g"
```
**- bash,text manipulation,interesting,web application**
#### References:

https://www.yg.ht/
__________
### 12. turn loop for local admins into csv
```
egrep -v "(\*\] T|\[\*\] F|[\*\] C|[\*\] U|[\*\] S|[\*\] R)" local_admin_information | egrep -v "(\[\*\] P|\[\*\] R|\[\*\] S|\[\*\] O|\[\*\] U)" | grep -v "Alias name" | grep -v "Administrators have complete" | grep -v \[\!\] | grep -v \[-\] | dos2unix | grep -v "^$" | sed s/"\[\*\] Creating service.*on"/''/g | grep -v Members | sed s/\\.\\.\\.\\.\\./','/g | sed s/"^ "/"€"/g | sed s/'The command completed successfully.'/€/g | tr "\n" "," | tr € "\n" | grep -v "^$" | sort | uniq  > local_admins.csv
```
**- linux,bash,text manipulation,loop,user information,interesting**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 13. nmap devicemap
```
grep "Discovered open port" nmap-udp-scan.txt | sed "s/\// /g" | sed "s/ /\t/g" | awk -F "\t" {'print $7"\t"$5"\t"$4"\topen"'} > devicemap-udp.tsv
```
**- linux,bash,text manipulation,networking**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 14. nmap service discovery
```
for file in $( ls -lash | grep ".gnmap" | awk {'print $10'} ); do cat $file | grep "Ports" | grep "open" | awk {'print $2'} | sort -u > IPs-`echo $file | cut -d "-" -f 2 | cut -d "." -f 1;`.txt; done
```
**- bash,text manipulation,loop**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 15. nmap service discovery
```
cat nmapScan-[SERVICE].gnmap | grep "Ports" | grep "open" | grep -v "open|filtered" | awk {'print $2'} | sort -u > IPs-[SERVICE].txt
```
**- linux,bash,text manipulation**
#### References:

http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
__________
### 16. Remove trailing whitespace
```
sed -i 's/[[:space:]]*$//' [input]
```
**- linux,bash,text manipulation**
#### References:

http://ask.xmodulo.com/remove-trailing-whitespaces-linux.html
__________
