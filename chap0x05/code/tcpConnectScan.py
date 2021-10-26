
#! /usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "172.16.222.111"
client_port = 8888
dst_port=80

tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport = client_port,dport = dst_port,flags = "S"),timeout = 10)

if(tcp_connect_scan_resp==None):
    print("Flitered")
elif(tcp_connect_scan_resp.haslayer(TCP)):
    if(tcp_connect_scan_resp.getlayer(TCP).flags==0x12):
        send_rst = sr1(IP(dst=dst_ip)/TCP(sport = client_port,dport = dst_port,flags=0x14),timeout = 10)
        print("Open")
    elif(tcp_connect_scan_resp.getlayer(TCP).flags==0x14):
        print("Closed")