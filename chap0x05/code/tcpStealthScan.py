
#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "172.16.222.111"
src_port = 8888
dst_port = 80

stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
if(stealth_scan_resp==None):
    print ("filtered: no response")
elif(stealth_scan_resp.getlayer(TCP)):
    if(stealth_scan_resp.getlayer(TCP).flags==0x12):
        send_rst=sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
        print ("open")
    elif(stealth_scan_resp.getlayer(TCP).flags==0x14):
        print ("closed")
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("filtered: receive ICMP but destination inreachable")