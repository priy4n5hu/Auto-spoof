# autospoof.py
"""
Autospoof Toolkit - Interactive Menu
"""
import sys
import time
import threading
from networkscanner import scan, output
from arp_spoof import run_spoofer, restore
from clone_sites import clone_site
from dns_spoof import dns_spoofer

# Domains to clone
CLONE_LIST = [
    "example.com",
    "testphp.vulnweb.com"
]

arp_thread = None
arp_running = False
target_ip = ""
gateway_ip = ""

def network_scanner():
    ip = input("Enter IP address or IP range to scan: ").strip()
    results = scan(ip)
    output(results)

def start_arp_spoofer():
    global arp_thread, arp_running, target_ip, gateway_ip

    if arp_running:
        print("[!] ARP Spoofer is already running.")
        return

    target_ip = input("Enter Target IP Address (Victim): ").strip()
    gateway_ip = input("Enter Gateway IP Address (Router): ").strip()

    def spoof_loop():
        global arp_running
        try:
            run_spoofer(target_ip, gateway_ip, quiet=True)
        finally:
            arp_running = False

    print(f"[+] Launching ARP Spoofer in background...")
    arp_running = True
    arp_thread = threading.Thread(target=spoof_loop, daemon=True)
    arp_thread.start()

def stop_arp_spoofer():
    global arp_running
    if not arp_running:
        print("[!] ARP Spoofer is not running.")
        return
    print("[*] Stopping ARP Spoofer and restoring ARP tables...")
    arp_running = False
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] ARP Spoofer stopped.")

def website_cloner():
    try:
        num = int(input("How many websites do you want to clone? ").strip())
    except ValueError:
        print("[!] Invalid number.")
        return

    if num <= 0:
        print("[!] No websites to clone.")
        return

    domains = []
    for i in range(num):
        domain = input(f"Enter domain {i+1} (e.g. example.com): ").strip()
        if domain:
            domains.append(domain)

    print("[+] Starting Website Cloner...")
    for domain in domains:
        clone_site(domain)
    print("[+] Website Cloning Complete.")

def dns_spoofing():
    print("[+] Starting DNS Spoofer... Press CTRL+C to stop.")
    try:
        dns_spoofer()
    except KeyboardInterrupt:
        print("\n[+] DNS Spoofing stopped.")

def main():
    global arp_running
    while True:
        menu = (
            "\nAutospoof Toolkit - Menu:\n"
            "  1) Network Scanner\n"
            f"  2) ARP Spoofer{' [running]' if arp_running else ''}\n"
            "  3) Website Cloner\n"
            "  4) DNS Spoofer\n"
            "  5) Stop ARP Spoofer\n"
            "  6) Quit\n"
        )
        print(menu)
        choice = input("Select an option: ").strip().lower()
        if choice == '1':
            network_scanner()
        elif choice == '2':
            start_arp_spoofer()
        elif choice == '3':
            website_cloner()
        elif choice == '4':
            dns_spoofing()
        elif choice == '5':
            stop_arp_spoofer()
        elif choice == '6':
            if arp_running:
                stop_arp_spoofer()
            print("Exiting Autospoof Toolkit. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice, please try again.")

if __name__ == '__main__':
    main()
