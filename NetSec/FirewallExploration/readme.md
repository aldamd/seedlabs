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
