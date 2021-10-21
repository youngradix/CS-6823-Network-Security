#!/usr/bin/env python3
from scapy.all import *

print("Sniffing Packets...")

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-b762a03f75c6', filter='icmp', prn=print_pkt)
#pkt = sniff(iface='br-b762a03f75c6', filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)
#pkt = sniff(iface='br-b762a03f75c6',filter='icmp and dst net 128.230.0.0/16', prn=print_pkt)

a = IP()
a.show()