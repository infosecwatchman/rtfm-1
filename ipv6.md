### 1. Piped to tee for later manipulation
```
ping6 -c1 -I < [Interface] ff02::1 | tee ipv6-hosts
```
**- enumeration,ipv6**
#### References:

https://superuser.com/questions/840767/ipv6-multicast-address-for-all-nodes-on-network
__________
### 2. SNMPGet supports ipv6
```
snmpget udp6:[ipv6 address] [OID]
```
**- ipv6,snmp**
#### References:

https://serverfault.com/questions/305448/snmpget-over-ipv6
__________
