### 1. Anoy a co-worker by rotating their screen
```
xrandr   --output `xrandr -q | grep "connected" | grep -v dis | awk '{print $1}' | head -n 1` --rotate  inverted
```
**- Troll,interseting**
#### References:

https://www.faqforge.com/linux/rotating-screen-in-ubuntu-and-linux-mint/
__________
