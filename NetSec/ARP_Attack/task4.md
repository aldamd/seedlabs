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
