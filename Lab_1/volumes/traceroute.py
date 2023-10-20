#!/usr/bin/python3
from scapy.all import *

def traceroute(destination, max_hops=99):
    ttl = 1
    while ttl <= max_hops:
        # 创建IP和ICMP包
        a = IP()
        a.dst = destination
        a.ttl = ttl
        b = ICMP()

        # 发送数据包并获取响应
        reply = sr1(a/b, verbose=0, timeout=10)

        if reply is None:
            print(f"{ttl} *")
        elif reply.type == 3:  # "Destination Unreachable"
            print(f"{ttl} {reply.src}")
            if reply.src == destination:
                break
        elif reply.type == 11:  # "Time Exceeded"
            print(f"{ttl} {reply.src}")
        else:
            print(f"{ttl} {reply.src}")
            break

        ttl += 1

destination_ip = "8.8.8.8"
print(f"Traceroute to {destination_ip}")
traceroute(destination_ip)





