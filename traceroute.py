#!/usr/bin/env python3
from scapy.all import *

print("Starting Traceroute...")
currentTTL = 1
found = False

while found == False:
    pkt = IP(dst = '8.8.8.8', ttl = currentTTL)/ICMP()
    replyPkt = sr1(pkt, verbose = 0, timeout = 2)
    if replyPkt is None:
        currentTTL += 1
        found = False
        continue
    elif replyPkt[ICMP].type == 0:
        print("%d hops away: " %currentTTL, replyPkt[IP].src)
        print("Done", replyPkt[IP].src)
        found = True
        break
    else:
        print("%d hops away: " %currentTTL, replyPkt[IP].src)
        currentTTL += 1 
        found = False
        continue
       
        
