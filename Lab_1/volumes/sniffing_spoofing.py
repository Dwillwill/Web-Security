#!/usr/bin/python3

from scapy.all import *

def process_packet(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original Packet...")
        print("Source IP:", pkt[IP].src)
        print("Destination IP:", pkt[IP].dst)

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        ip.ttl = 99
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            newpkt = ip/icmp/data
        else:
            newpkt = ip/icmp
        
        print("Spoofed Packet...")
        print("Source IP:", newpkt[IP].src)
        print("Destination IP:", newpkt[IP].dst)
        send(newpkt, verbose=0)

# For the ICMP packet:
f1 = 'icmp'
# For the TCP packet from a specific IP and destined for port 23:
f2 = 'tcp and src host 192.168.1.10 and dst port 23'
# For packets related to the 128.230.0.0/16 subnet:
f3 = 'net 128.230.0.0/16'
sniff(iface='br-56180034b99d', filter=f1, prn=process_packet)