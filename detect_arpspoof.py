#!/usr/bin/env python3
# Import scapy for sniffing
from scapy.all import Ether, ARP, srp, sniff, conf
# Import Info to make everything little easier
import os, time, sys, logging
#from sys import platform

# setup the startup and check args
# The script must be run by root so lets check
if os.geteuid() !=0:
    exit("Root Permisions is required to use network interface for monitoring\n")

# Setup Logging Get log file name first
# Prompt to select log file
filename = input("Please input desired log file name. [spoof.log]")
# If none specified, set to default
if filename == "":
    filename = "spoof.log"

# Set logging structure
logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)

def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def process(packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # if they're different, definetely there is an attack
                if real_mac != response_mac:
                # Original Line below that fails
                    print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, Attacker FAKE-MAC: {response_mac.upper()}")
		#print("[!] You are under attack, " + REAL-MAC: {real_mac.upper()}, + " FAKE-MAC: " + {response_mac.upper()} + "")
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass

# Start of Main
if __name__ == "__main__":
    import sys
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface
    print("Starting Sniffing")
    sniff(store=False, prn=process, iface=iface)
