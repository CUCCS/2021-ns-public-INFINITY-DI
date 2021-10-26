

#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*

dst_ip = "172.16.222.111"
src_port = 8888
dst_port = 53

udp_scan_resp=sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=5,verbose=0)
if(udp_scan_resp==None):
    print("open | filtered | closed")
elif(udp_scan_resp.haslayer(ICMP)):
    if(udp_scan_resp.getlayer(ICMP).type==3 and udp_scan_resp.getlayer(ICMP).code==3):
        print("closed")