### Network Config
```shell
M - 10.9.0.105 - 02:42:0a:09:00:69
A - 10.9.0.5   - 02:42:0a:09:00:05
B - 10.9.0.6   - 02:42:0a:09:00:06
```

## Task 1: Implementing a Simple Firewall
### 1.A Implement a Simple Kernel Module
For this task, we need to compile the simple kernel module that prints "Hello World" on load and "Bye Bye World" on removal. In order to compile the C code, we use the ```$ make``` command. The contents of the Makefile are:
```
obj-m += hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
```shell
seed@VM:~/.../kernel_module$ make 
make -C /lib/modules/5.4.0-54-generic/build M=/home/seed/Labsetup/Files/kernel_module modules
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-54-generic'
  CC [M]  /home/seed/Labsetup/Files/kernel_module/hello.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC [M]  /home/seed/Labsetup/Files/kernel_module/hello.mod.o
  LD [M]  /home/seed/Labsetup/Files/kernel_module/hello.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-54-generic'

seed@VM:~/.../kernel_module$ ls
hello.c  hello.ko  hello.mod  hello.mod.c  hello.mod.o  hello.o  Makefile  modules.order  Module.symvers
```
Now that hello.ko kernel module has been generated, we can load and check the functionality of the module like so:
```shell
seed@VM:~/.../kernel_module$ sudo insmod hello.ko
seed@VM:~/.../kernel_module$ dmesg | tail -n 1
[ 3715.138122] Hello World!
```
Looks like it worked! Now for removal:
```shell
seed@VM:~/.../kernel_module$ sudo rmmod hello
seed@VM:~/.../kernel_module$ dmesg | tail -n 1
[ 3982.948167] Bye-bye World!.
```

### 1.B Implement a Simple Firewall Using Netfilter
#### Kernel Module Compilation and DNS Testing
Compiling and loading the netfilter kernel module:
```shell
eed@VM:~/.../packet_filter$ make
make -C /lib/modules/5.4.0-54-generic/build M=/home/seed/Labsetup/Files/packet_filter modules
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-54-generic'
  CC [M]  /home/seed/Labsetup/Files/packet_filter/seedFilter.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC [M]  /home/seed/Labsetup/Files/packet_filter/seedFilter.mod.o
  LD [M]  /home/seed/Labsetup/Files/packet_filter/seedFilter.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-54-generic'
```
The default behavior of this netfilter should drop any UDP:53 (DNS) traffic towards 8.8.8.8 (one of Google's DNS servers). Let's test the default behavior:
```shell
seed@VM:~/.../packet_filter$ dig @8.8.8.8 www.example.com
[...]
;; ANSWER SECTION:
www.example.com.	1718	IN	A	93.184.215.14
[...]
```
Looking good, now let's see what happens when we load the kernel module:
```shell
seed@VM:~/.../packet_filter$ sudo insmod seedFilter.ko
seed@VM:~/.../packet_filter$ dig @8.8.8.8 www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> @8.8.8.8 www.example.com
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached
```
Seems to have done its job!

----

#### printInfo Hooking
```c
int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

  // hook2.hook = blockUDP;
  // hook2.hooknum = NF_INET_POST_ROUTING;
  // hook2.pf = PF_INET;
  // hook2.priority = NF_IP_PRI_FIRST;
  // nf_register_net_hook(&init_net, &hook2);

   hook3.hook = printInfo;
   hook3.hooknum = NF_INET_PRE_ROUTING;
   hook3.pf = PF_INET;
   hook3.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook3);

   hook4.hook = printInfo;
   hook4.hooknum = NF_INET_LOCAL_IN;
   hook4.pf = PF_INET;
   hook4.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook4);

   hook5.hook = printInfo;
   hook5.hooknum = NF_INET_FORWARD;
   hook5.pf = PF_INET;
   hook5.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook5);

   hook6.hook = printInfo;
   hook6.hooknum = NF_INET_POST_ROUTING;
   hook6.pf = PF_INET;
   hook6.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook6);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   //nf_unregister_net_hook(&init_net, &hook2);
   nf_unregister_net_hook(&init_net, &hook3);
   nf_unregister_net_hook(&init_net, &hook4);
   nf_unregister_net_hook(&init_net, &hook5);
   nf_unregister_net_hook(&init_net, &hook6);
}
```
```shell
seed@VM:~/.../packet_filter$ ping 127.0.0.1
seed@VM:~/.../packet_filter$ dmesg
[ 6196.784831] Registering filters.
[ 6203.533004] *** LOCAL_OUT
[ 6203.533007]     127.0.0.1  --> 127.0.0.1 (ICMP)
[ 6203.533016] *** POST_ROUTING
[ 6203.533017]     127.0.0.1  --> 127.0.0.1 (ICMP)
[ 6203.533028] *** PRE_ROUTING
[ 6203.533029]     127.0.0.1  --> 127.0.0.1 (ICMP)
[ 6203.533030] *** LOCAL_IN
[ 6203.533031]     127.0.0.1  --> 127.0.0.1 (ICMP)
[...]
```
When performing a ping request, LOCAL_OUT, LOCAL_IN, POST_ROUTING, and PRE_ROUTING hook numbers are utilized.
```
LOCAL_OUT: packet is queued for output by local machine
POST_ROUTING: packet routing has been calculated and is ready to be sent out
PRE_ROUTING: packet is queued for input, before routing decisions have been made
LOCAL_IN: packet destined for local machine has been registered
FORWARD: packets not destined for local machine but are being forwarded to another host
```

----

#### Prevent Ping and Telnet
Below is the C code for the kernel module that blocks incoming ICMP Echo (ping) requests and TCP port 23 (Telnet) requests:
```c
unsigned int blockPingTelnet(void *priv, struct sk_buff *skb,
                             const struct nf_hook_state *state)
{
   struct iphdr *ip_header;
   struct icmphdr *icmp_header;
   struct tcphdr *tcp_header;
   u16  port   = 23;

   if (!skb) return NF_ACCEPT;

   // Block ping requests
   ip_header = ip_hdr(skb);
   if (ip_header->protocol == IPPROTO_ICMP) {
       icmp_header = icmp_hdr(skb);
       if (icmp_header->type == ICMP_ECHO) {
            printk(KERN_INFO "*** Blocked ICMP Echo Request\n");
            return NF_DROP;
       }
   }


   // Block Telnet requests
   if (ip_header->protocol == IPPROTO_TCP) {
       tcp_header = tcp_hdr(skb);
       if (ntohs(tcp_header->dest) == port){
            printk(KERN_WARNING "*** Blocked Telnet Request\n");
            return NF_DROP;
        }
   }

   return NF_ACCEPT;
}

int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_PRE_ROUTING;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   hook2.hook = blockPingTelnet;
   hook2.hooknum = NF_INET_LOCAL_IN;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}
```

Here is the demo of the ping requests being blocked:
```shell
seed@VM:~/.../packet_filter$ sudo insmod seedFilter.ko
[12/04/24]seed@VM:~/.../packet_filter$ ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
^C
--- 127.0.0.1 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9210ms

seed@VM:~/.../packet_filter$ dmesg
[...]
 8386.306791] *** PRE_ROUTING
[ 8386.306793]     127.0.0.1  --> 127.0.0.1 (ICMP)
[ 8386.306795] *** Blocked ICMP Echo Request
[ 8387.331908] *** PRE_ROUTING
[ 8387.331915]     127.0.0.1  --> 127.0.0.1 (ICMP)
[ 8387.331920] *** Blocked ICMP Echo Request
[ 8388.355764] *** PRE_ROUTING
[ 8388.355771]     127.0.0.1  --> 127.0.0.1 (ICMP)
[ 8388.355776] *** Blocked ICMP Echo Request
```

Here is the demo of the Telnet requests being blocked:
```shell
seed@VM:~/.../packet_filter$ telnet localhost
Trying 127.0.0.1...
^C

seed@VM:~/.../packet_filter$ dmesg
[ 8515.244035] *** PRE_ROUTING
[ 8515.244038]     127.0.0.1  --> 127.0.0.1 (TCP)
[ 8515.244040] *** Blocked Telnet Request
[ 8516.279834] *** PRE_ROUTING
[ 8516.279841]     127.0.0.1  --> 127.0.0.1 (TCP)
[ 8516.279847] *** Blocked Telnet Request
[ 8518.517830] *** PRE_ROUTING
[ 8518.517890]     127.0.0.1  --> 127.0.0.1 (TCP)
[ 8518.517921] *** Blocked Telnet Request
```

## Task 2: Experimenting with Stateless Firewall Rules
### Docker Config
```shell
seed@VM:~$ dockps
e9f4cdfd25ae  host1-192.168.60.5
de3799584b1f  hostA-10.9.0.5
378db28a79b1  host2-192.168.60.6
9b0f684bb371  host3-192.168.60.7
954f931756c4  seed-router
```
### Task 2.A: Protecting the Router
```shell
seed@VM:~$ docksh 954
root@954f931756c4:/# iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
// allows incoming icmp echo (ping) requests
root@954f931756c4:/# iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
// allows outgoing icmp replies
root@954f931756c4:/# iptables -P OUTPUT DROP
// sets default output behavior to drop everything aside from existing rules
root@954f931756c4:/# iptables -P INPUT DROP
// sets default input behavior to drop everything aside from existing rules
```

```shell
seed@VM:~$ docksh de3
root@de3799584b1f:/# ping seed-router
PING seed-router (10.9.0.11) 56(84) bytes of data.
^C
--- seed-router ping statistics ---
8 packets transmitted, 0 received, 100% packet loss, time 7167ms

root@de3799584b1f:/# telnet seed-router
Trying 10.9.0.11...
^C
```

I am unable to ping the router from 10.9.0.5, nor am I able to telnet into the router

----

### Task 2.B: Protecting the Internal Network
```shell
seed@VM:~$ docksh seed-router
root@954f931756c4:/# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
61: eth0@if62: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:09:00:0b brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.9.0.11/24 brd 10.9.0.255 scope global eth0
       valid_lft forever preferred_lft forever
63: eth1@if64: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c0:a8:3c:0b brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.60.11/24 brd 192.168.60.255 scope global eth1
       valid_lft forever preferred_lft forever
```
From the above ```$ ip a``` command, we know that eth0@if62 is the external interface while eth1@if64 is the internal interface.

```shell
root@954f931756c4:/# iptables -P INPUT DROP
root@954f931756c4:/# iptables -P FORWARD DROP
// default the INPUT and FORWARD policies to block unwanted traffic
// keep the default OUTPUT policy to accept connections, allowing router to send replies

root@954f931756c4:/# iptables -A FORWARD -i eth1 -o eth0 -p icmp --icmp-type echo-request -j ACCEPT
// allow echo requests from the internal network to the external network
root@954f931756c4:/# iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-reply -j ACCEPT
// allow echo replies from the external network to the internal network

root@954f931756c4:/# iptables -A INPUT -p icmp --icmp-type echo-request -i eth0 -j ACCEPT
// allow ping requests from external network to the router

root@954f931756c4:/# iptables -A FORWARD -p icmp --icmp-type echo-request -i eth0 -o eth1 -j DROP
// block ping requests from external hosts to internal hosts

root@954f931756c4:/# iptables -L -n -v
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    2   168 ACCEPT     icmp --  eth0   *       0.0.0.0/0            0.0.0.0/0            icmptype 8

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    3   252 ACCEPT     icmp --  eth1   eth0    0.0.0.0/0            0.0.0.0/0            icmptype 8
    3   252 ACCEPT     icmp --  eth0   eth1    0.0.0.0/0            0.0.0.0/0            icmptype 0
    2   168 DROP       icmp --  eth0   eth1    0.0.0.0/0            0.0.0.0/0            icmptype 8
```

**Ping request from external host to internal host**
```shell
seed@VM:~/.../packet_filter$ docksh hostA-10.9.0.5
root@de3799584b1f:/# ping 192.168.60.5
PING 192.168.60.5 (192.168.60.5) 56(84) bytes of data.
^C
--- 192.168.60.5 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3077ms
```

**Ping request from external host to router**
```shell
root@de3799584b1f:/# ping 10.9.0.11
PING 10.9.0.11 (10.9.0.11) 56(84) bytes of data.
64 bytes from 10.9.0.11: icmp_seq=1 ttl=64 time=0.091 ms
64 bytes from 10.9.0.11: icmp_seq=2 ttl=64 time=0.161 ms
64 bytes from 10.9.0.11: icmp_seq=3 ttl=64 time=0.169 ms
^C
--- 10.9.0.11 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2098ms
rtt min/avg/max/mdev = 0.091/0.140/0.169/0.035 ms
```

**Ping request from internal host to external host**
```shell
seed@VM:~/.../packet_filter$ docksh host1-192.168.60.5
root@e9f4cdfd25ae:/# ping 10.9.0.5
PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
64 bytes from 10.9.0.5: icmp_seq=1 ttl=63 time=0.190 ms
64 bytes from 10.9.0.5: icmp_seq=2 ttl=63 time=0.331 ms
64 bytes from 10.9.0.5: icmp_seq=3 ttl=63 time=0.272 ms
^C
--- 10.9.0.5 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2028ms
rtt min/avg/max/mdev = 0.190/0.264/0.331/0.057 ms
```

**Ping request from internal host to internal host**
```shell
root@e9f4cdfd25ae:/# ping 192.168.60.6
PING 192.168.60.6 (192.168.60.6) 56(84) bytes of data.
64 bytes from 192.168.60.6: icmp_seq=1 ttl=64 time=0.129 ms
64 bytes from 192.168.60.6: icmp_seq=2 ttl=64 time=0.163 ms
64 bytes from 192.168.60.6: icmp_seq=3 ttl=64 time=0.158 ms
^C
--- 192.168.60.6 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2163ms
rtt min/avg/max/mdev = 0.129/0.150/0.163/0.015 ms
```

**Telnet request from external host to internal host**
```shell
seed@VM:~/.../packet_filter$ docksh hostA-10.9.0.5
root@de3799584b1f:/# telnet 192.168.60.5
Trying 192.168.60.5...
^C
```

----

### Task 2.C: Protecting Internal Servers
```shell
seed@VM:~/.../packet_filter$ docksh seed-router
root@954f931756c4:/# iptables -P INPUT DROP
root@954f931756c4:/# iptables -P FORWARD DROP
root@954f931756c4:/# iptables -P OUTPUT ACCEPT

root@954f931756c4:/# iptables -A FORWARD -i eth1 -o eth0 -s 192.168.60.5 -p tcp --sport 23 -j ACCEPT
// allow telnet packets to route from 192.168.60.5 to the external network

root@954f931756c4:/# iptables -A FORWARD -i eth0 -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT
// allow telnet packets to route from the external network to 192.168.60.5

root@954f931756c4:/# iptables -A FORWARD -i eth1 -o eth1 -j ACCEPT
// allow hosts in the internal network to communicate with one another

root@954f931756c4:/# iptables -L -n -v
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
   62  3934 ACCEPT     tcp  --  eth1   eth0    192.168.60.5         0.0.0.0/0            tcp spt:23
   77  4118 ACCEPT     tcp  --  eth0   *       0.0.0.0/0            192.168.60.5         tcp dpt:23
    0     0 ACCEPT     all  --  eth1   eth1    0.0.0.0/0            0.0.0.0/0           

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
```

**Connecting to 192.168.60.5:23 From External Host**
```shell
seed@VM:~/.../packet_filter$ docksh de3
root@de3799584b1f:/# telnet 192.168.60.5
Trying 192.168.60.5...
Connected to 192.168.60.5.
Escape character is '^]'.
Ubuntu 20.04.1 LTS
e9f4cdfd25ae login: seed
Password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-54-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Wed Dec  4 21:43:53 UTC 2024 on pts/1
seed@e9f4cdfd25ae:~$
```

**Connecting to 192.168.60.6:23 From External Host**
```shell
root@de3799584b1f:/# telnet 192.168.60.6
Trying 192.168.60.6...
^C
```

**Accessing External Host from Internal Host**
```shell
seed@VM:~/.../packet_filter$ docksh host1-192.168.60.5
root@e9f4cdfd25ae:/# ping 10.9.0.5
PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
^C
--- 10.9.0.5 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3083ms
```

**Accessing Internal Host From Internal Host**
```shell
seed@VM:~/.../packet_filter$ docksh host1-192.168.60.5
root@e9f4cdfd25ae:/# ping 192.168.60.6
PING 192.168.60.6 (192.168.60.6) 56(84) bytes of data.
64 bytes from 192.168.60.6: icmp_seq=1 ttl=64 time=0.135 ms
64 bytes from 192.168.60.6: icmp_seq=2 ttl=64 time=0.259 ms
^C
--- 192.168.60.6 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1013ms
rtt min/avg/max/mdev = 0.135/0.197/0.259/0.062 ms
```

## Task 3: Connection Tracking and Stateful Firewall
### Task 3.A: Experiment with the Connection Tracking

#### ICMP Experiment
```shell
seed@VM:~/.../packet_filter$ docksh hostA-10.9.0.5                                                                                 
root@de3799584b1f:/# ping 192.168.60.5
[...]

seed@VM:~/.../packet_filter$ docksh seed-router
root@954f931756c4:/# conntrack -L
icmp     1 29 src=10.9.0.5 dst=192.168.60.5 type=8 code=0 id=121 src=192.168.60.5 dst=10.9.0.5 type=0 code=0 id=121 mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
```

For as long as host A was sending ping requests to 192.168.60.5, the seed-router was able to observe the icmp connection. Once the last ping request is sent, it seems to remain in the conntrack buffer for around 30 seconds.

----

#### UDP Experiment
```shell
seed@VM:~/.../packet_filter$ docksh host1-192.168.60.5
root@e9f4cdfd25ae:/# nc -lu 9090
[...]

seed@VM:~/.../packet_filter$ docksh hostA-10.9.0.5
root@de3799584b1f:/# nc -u 192.168.60.5 9090
hello

[...]
seed@VM:~$ docksh seed-router
root@954f931756c4:/# conntrack -L
udp      17 25 src=10.9.0.5 dst=192.168.60.5 sport=33372 dport=9090 [UNREPLIED] src=192.168.60.5 dst=10.9.0.5 sport=9090 dport=33372 mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
root@954f931756c4:/# conntrack -L
conntrack v1.4.5 (conntrack-tools): 0 flow entries have been shown.
```

The UDP connection state is only kept within a short period of time (~ 30 seconds) that a message is sent over the listener. If enough time elapses, conntrack can no longer observe a connection

----

#### TCP experiment
```shell
seed@VM:~/.../packet_filter$ docksh host1-192.168.60.5
root@e9f4cdfd25ae:/# nc -l 9090
[...]

seed@VM:~/.../packet_filter$ docksh hostA-10.9.0.5
root@de3799584b1f:/# nc 192.168.60.5 9090
hello
[...]

seed@VM:~$ docksh seed-router
tcp      6 431985 ESTABLISHED src=10.9.0.5 dst=192.168.60.5 sport=57846 dport=9090 src=192.168.60.5 dst=10.9.0.5 sport=9090 dport=57846 [ASSURED] mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.

// killed listener
root@954f931756c4:/# conntrack -L
tcp      6 117 TIME_WAIT src=10.9.0.5 dst=192.168.60.5 sport=57846 dport=9090 src=192.168.60.5 dst=10.9.0.5 sport=9090 dport=57846 [ASSURED] mark=0 use=1
```

Once the TCP connection is killed, it seems to remain in the conntrack listener for around 2 minutes

----

### Task 3.B: Setting Up a Stateful Firewall

1. All the internal hosts run a telnet server (listening to port 23). Outside hosts can only access the telnet
server on 192.168.60.5, not the other internal hosts.
2. Outside hosts cannot access other internal servers.
3. Internal hosts can access all the internal servers.
4. Internal hosts cannot access external servers.
5. In this task, the connection tracking mechanism is not allowed. It will be used in a later task.

```shell
seed@VM:~$ docksh seed-router
root@954f931756c4:/# iptables -P INPUT DROP
root@954f931756c4:/# iptables -P FORWARD DROP
root@954f931756c4:/# iptables -P OUTPUT ACCEPT
root@954f931756c4:/# iptables -A FORWARD -i eth1 -o eth0 -s 192.168.60.5 -p tcp --sport 23 -j ACCEPT
root@954f931756c4:/# iptables -A FORWARD -i eth0 -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT
root@954f931756c4:/# iptables -A FORWARD -i eth1 -o eth1 -j ACCEPT
// same suite of rules from 2.C

root@954f931756c4:/# iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
root@954f931756c4:/# iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
// allow established and related connections in the INPUT and FORWARD chains

root@954f931756c4:/# iptables -A FORWARD -i eth1 -o eth0 -m conntrack --ctstate NEW -j ACCEPT
// allow new connections from the internal network to the external network

root@954f931756c4:/# iptables -L -n -v
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
   17  1023 ACCEPT     tcp  --  eth1   eth0    192.168.60.5         0.0.0.0/0            tcp spt:23
   17   973 ACCEPT     tcp  --  eth0   *       0.0.0.0/0            192.168.60.5         tcp dpt:23
    0     0 ACCEPT     all  --  eth1   eth1    0.0.0.0/0            0.0.0.0/0           
    5   420 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
    1    84 ACCEPT     all  --  eth1   eth0    0.0.0.0/0            0.0.0.0/0            ctstate NEW

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
```

**Ping From Internal Host to External Host**
```shell
seed@VM:~/.../packet_filter$ docksh host1-192.168.60.5
root@e9f4cdfd25ae:/# ping 10.9.0.5
PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
64 bytes from 10.9.0.5: icmp_seq=1 ttl=63 time=0.125 ms
64 bytes from 10.9.0.5: icmp_seq=2 ttl=63 time=0.214 ms
64 bytes from 10.9.0.5: icmp_seq=3 ttl=63 time=0.186 ms
^C
--- 10.9.0.5 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2127ms
rtt min/avg/max/mdev = 0.125/0.175/0.214/0.037 ms
```

## Task 4: Limiting Network Traffic

## Task 5: Load Balacing

## Task 6: Write-Up
