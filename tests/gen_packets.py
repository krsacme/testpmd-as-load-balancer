from scapy.all import *
import time

iface = ["vnet4", "vnet5", "vnet6", "vnet7"]
loop = 0
while True:
    sport = 10102 + loop
    dport = 10101 + loop
    a = Ether(dst="52:54:00:2D:29:47")/IP()/TCP(dport=dport,sport=sport)
    sendp(a, iface=iface[0])
    time.sleep(1)
    a = Ether(dst="52:54:00:F6:67:9E")/IP()/TCP(dport=dport,sport=sport)
    sendp(a, iface=iface[1])
    time.sleep(1)
    a = Ether(dst="52:54:00:99:7E:FF")/IP()/TCP(dport=dport,sport=sport)
    sendp(a, iface=iface[2])
    time.sleep(1)
    a = Ether(dst="52:54:00:FB:BE:BF")/IP()/TCP(dport=dport,sport=sport)
    sendp(a, iface=iface[3])
    time.sleep(5)
    loop += 1
    if loop == 10:
        break;

