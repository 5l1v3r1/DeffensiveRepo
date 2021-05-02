#!/usr/bin/env python

import scapy.all as scapy
import os
if os.getuid() != 0:
    print("this script need root permission")
    exit()
else:
    pass
interface = input("entre the interface to listen on:")

def getmacaddr(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def sniffing(interface):
    scapy.sniff(iface=interface, store=False, prn=checksniffedpackets)

def checksniffedpackets(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = getmacaddr(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("someone doing ARPspoofing in the networ:)")
        except IndexError:
            pass

sniffing(interface)
