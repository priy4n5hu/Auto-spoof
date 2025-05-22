#!/usr/bin/env python3
import scapy.all as scapy

def scan(ip):
    """
    Scans the network for active devices.
    Returns a list of dictionaries with 'ip' and 'mac' keys.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    clients = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client_dict)

    return clients

def output(results):
    """
    Prints the results of the network scan in a formatted table.
    """
    print("\nIP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results:
        print(f"{client['ip']}\t\t{client['mac']}")
