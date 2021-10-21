#!/usr/bin/env python3
from scapy.all import *

def sniff_spoof(pkt): 
    if ICMP in pkt and pkt[ICMP].type == 8:  
        print('spoofRequest: src ', pkt[IP].src, ' dst ', pkt[IP].dst, ' type ', pkt[ICMP].type)
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
        icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
        data = pkt[Raw].load
        spoofedPkt = ip/icmp/data
        print('spoofReply: src ', spoofedPkt[IP].src, ' dst ', spoofedPkt[IP].dst, ' type ', spoofedPkt[ICMP].type)
        send(spoofedPkt, verbose = 0)

pkt = sniff(filter='icmp', prn=sniff_spoof)