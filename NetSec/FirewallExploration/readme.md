### Network Config
```shell
M - 10.9.0.105 - 02:42:0a:09:00:69
A - 10.9.0.5   - 02:42:0a:09:00:05
B - 10.9.0.6   - 02:42:0a:09:00:06
```

## Task 1: Implementing a Simple Firewall
### Docker Config
```shell
seed@VM:~$ dockps
50d7415fb4c7  hostA-10.9.0.5
674b136edb37  seed-router
cad7ea28c884  host1-192.168.60.5
b6677121fdb5  host2-192.168.60.6
b3579d62e8f8  host3-192.168.60.7
```

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
LOCAL_OUT: packet is queued for output by local machine
POST_ROUTING: packet routing has been calculated and is ready to be sent out
PRE_ROUTING: packet is queued for input, before routing decisions have been made
LOCAL_IN: packet destined for local machine has been registered
FORWARD: packets not destined for local machine but are being forwarded to another host

#### Prevent Ping and Telnet
```c
unsigned int blockPingTelnet(void *priv, struct sk_buff *skb,
                             const struct nf_hook_state *state)
{
   if (!skb) return NF_ACCEPT;

   struct iphdr *ip_header;
   struct icmphdr *icmp_header;

   // Block ping requests
   ip_header = ip_hdr(skb);
   if (ip_header->protocol == IPPROTO_ICMP) {
       icmp_header = icmp_hdr(skb);
       if (icmp_header->type == ICMP_ECHO) {
            printk(KERN_INFO "*** Blocked ICMP Echo Request\n");
            return NF_DROP;
       }
   }

   struct tcphdr *tcp_header;
   u16  port   = 23;

   // Block Telnet requests
   if (iph->protocol == IPPROTO_TCP) {
       tcp_header = tcp_hdr(skb);
       if (ntohs(tcp_header->dest) == port){
            printk(KERN_WARNING "*** Blocked Telnet Request\n");
            return NF_DROP;
        }
   }

   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   //skb is the pointer to the actual packet
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}

int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_IN;
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

## Task 2: Experimenting with Stateless Firewall Rules

### Task 2.A: Protecting the Router

### Task 2.B: Protecting the Internal Network

### Task 2.C: Protecting Internal Servers

## Task 3: Connection Tracking and Stateful Firewall

### Task 3.A: Experiment with the Connection Tracking

### Task 3.B: Setting Up a Stateful Firewall

## Task 4: Limiting Network Traffic

## Task 5: Load Balacing

## Task 6: Write-Up
