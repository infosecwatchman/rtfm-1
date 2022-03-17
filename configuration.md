### 1. WIFI enable USB2 before USB3 : helps with passthrough
```
echo 1 > /sys/module/usbcore/parameters/old_scheme_first
```
**- linux,wireless,wifi,configuration**
#### References:

http://forums.fedoraforum.org/archive/index.php/t-30868.html
__________
### 2. manual vlans
```
vconfig add em1 [VLANID]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/tips/howto-configure-linux-virtual-local-area-network-vlan.html
__________
### 3. dhcp client
```
dhclient -d -v -4 -pf /tmp/dhclient.pid -lf /tmp/dhclient.lease em1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/tag/dhclient-command/
__________
### 4. route table add
```
route add -net [CIDR] gw [IP] [INTERFACE]
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 5. route table del
```
route del -net 0.0.0.0 gw [GW] eth1
```
**- linux,bash,networking,configuration**
#### References:

https://yg.ht
https://www.cyberciti.biz/faq/linux-route-add/
http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch03_:_Linux_Networking
__________
### 6. set static ip
```
netsh interface ip set address local static [ip] [mask] [gw] [ID]
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 7. set DNS server
```
netsh interface ip set dns local static [ip]
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 8. enable DHCP
```
netsh interface ip set address local dhcp
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
__________
### 9. disable local firewall
```
netsh advfirewall set currentprofile state off;netsh advfirewall set allprofiles state off;
```
**- networking,Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/bb490939.aspx
https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx
__________
### 10. re-enable CMD
```
reg add HKCU\Software\Policies\microsoft\Windows\System /v DisableCHD /t
```
**- pivoting,Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 11. enable RDP
```
reg add "HKEY LOCAL MACHINE\SYSTEM\CurentControlSet\Control \TerminalServer" /v DenyTSConnections /t REG_DWORD /d 0 /f
```
**- Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 12. Disable NLA on RDP
```
reg add "HKEY LOCAL MACHINE\SYSTEM\CurentControlSet\Control \TerminalServer\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d "0" /f
```
**- Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
### 13. enble rdp on remote host
```
wmic /node:"[victim]" path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"
```
**- Windows,configuration**
#### References:

https://technet.microsoft.com/en-us/library/cc754534(v=ws.11).aspx
https://blogs.technet.microsoft.com/askperf/2012/02/17/useful-wmic-queries/
__________
### 14. list of drives : cd Env:\ . . . mind . . . blown
```
get-psdrive
```
**- enumeration,interesting,Windows,configuration,powershell**
#### References:

https://msdn.microsoft.com/en-us/powershell/reference/5.0/microsoft.powershell.management/get-psdrive
__________
### 15. enable ip routing in windows, use as GW
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter
```
**- Windows,configuration**
#### References:

https://www.amazon.co.uk/Rtfm-Red-Team-Field-Manual/dp/1494295504
__________
