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
3607e31516bc  host3-192.168.60.7
0fc6ae0088a0  host1-192.168.60.5
1deffe30b8c4  seed-router
63811895d89f  host2-192.168.60.6
b3aa69e3ae5a  hostA-10.9.0.5
```
### Task 2.A: Protecting the Router
```shell
seed@VM:~$ docksh 1de
root@1deffe30b8c4:/# iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
// allows incoming icmp echo (ping) requests
root@1deffe30b8c4:/# iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
// allows outgoing icmp replies
root@1deffe30b8c4:/# iptables -P OUTPUT DROP
// sets default output behavior to drop everything aside from existing rules
root@1deffe30b8c4:/# iptables -P INPUT DROP
// sets default input behavior to drop everything aside from existing rules
```

```shell
seed@VM:~$ docksh b3aa
root@b3aa69e3ae5a:/# ping seed-router
PING seed-router (10.9.0.11) 56(84) bytes of data.
^C
--- seed-router ping statistics ---
8 packets transmitted, 0 received, 100% packet loss, time 7167ms

root@b3aa69e3ae5a:/# telnet seed-router
Trying 10.9.0.11...
^C
```

I am unable to ping the router from 10.9.0.5, nor am I able to telnet into the router

### Task 2.B: Protecting the Internal Network

### Task 2.C: Protecting Internal Servers

## Task 3: Connection Tracking and Stateful Firewall

### Task 3.A: Experiment with the Connection Tracking

### Task 3.B: Setting Up a Stateful Firewall

## Task 4: Limiting Network Traffic

## Task 5: Load Balacing

## Task 6: Write-Up
