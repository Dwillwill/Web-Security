#!/usr/bin/python3

from scapy.all import *

def process_packet(pkt):
    pkt.show()
    print("-----------------------------------")

# For the ICMP packet:
f1 = 'icmp'
# For the TCP packet from a specific IP and destined for port 23:
f2 = 'tcp and src host 192.168.1.10 and dst port 23'
# For packets related to the 128.230.0.0/16 subnet:
f3 = 'net 128.230.0.0/16'
sniff(iface='br-56180034b99d', filter='icmp', prn=process_packet)