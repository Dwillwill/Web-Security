#!/usr/bin/python3

from scapy.all import *

a = IP(src='1.2.3.4', dst='10.9.0.5')
b = UDP(sport=1234, dport=1020)
c = 'hello world'
pkt = a/b/c

pkt.show()
send(pkt, verbose=0)