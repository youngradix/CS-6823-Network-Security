#!/usr/bin/env python3
from scapy.all import *

print("Spoofing packet")
a = IP()
a.src = '8.8.8.8'
a.dst = '10.9.0.5'
b = ICMP()
p = a/b
send(p)