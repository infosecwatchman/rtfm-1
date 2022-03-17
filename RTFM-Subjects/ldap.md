### 1. Dump Ldap structure
```
ldapsearch -x -LLL -E pr=200/noprompt -h [victim] -D "[domain]\\[user]" -w '[password]' -b "dc=[fqdn],dc=co,dc=uk"
```
**- enumeration,user information,ldap**
#### References:

https://www.centos.org/docs/5/html/CDS/ag/8.0/Finding_Directory_Entries-Using_ldapsearch.html
https://access.redhat.com/documentation/en-US/Red_Hat_Directory_Server/8.2/html/Administration_Guide/Examples-of-common-ldapsearches.html
https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_9.0.1/admin/conf_examplesofusingldapsearch_t.html
__________
