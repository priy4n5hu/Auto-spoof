# 🛠️ AutoSpoof — Offensive Cybersecurity Toolkit

AutoSpoof is an automated offensive cybersecurity tool for ethical hacking and penetration testing. It performs network scanning, ARP spoofing, DNS spoofing, and HTTP website cloning to simulate Man-in-the-Middle (MITM) attacks in local networks. Ideal for cybersecurity research and educational demonstrations.

> ⚠️ Disclaimer: Use only in authorized, controlled environments. Unauthorized use is illegal.

## 📌 Features

- 🔍 Network Scanner: Discovers live hosts and their MAC/IP addresses.
- 🕵️‍♂️ ARP Spoofer: Redirects network traffic through your machine.
- 🌐 DNS Spoofer: Intercepts and modifies DNS responses.
- 🪞 Website Cloner: Automatically clones specified HTTP websites.
- 🔁 Auto Mode: Chains all modules for full attack automation.

## 🔧 Installation

1. Clone this repository:
   ```
   git clone https://github.com/priy4n5hu/Auto-spoof.git
   cd Auto-spoof
   ```
2. Install dependencies:
   ```
   pip install scapy colorama requests beautifulsoup4
   ```
3. Grant root privileges for packet operations:
   ```bash
   sudo bash
   ```

## 🚀 Usage

- Run the full automated chain:
  ```bash
  sudo python3 auto_spoof.py
  ```
- Or run modules individually:
  - Network Scanner:
    ```bash
    sudo python3 network_scanner.py
    ```
  - ARP Spoofer:
    ```bash
    sudo python3 arp_spoofer.py -t <target_ip> -g <gateway_ip>
    ```
  - DNS Spoofer:
    ```bash
    sudo python3 dns_spoofer.py
    ```
  - Website Cloner:
    ```bash
    sudo python3 clone_sites.py
    ```

## ⚠️ Ethical Notice

This tool is for educational and authorized penetration tests only. Always obtain permission before use. Misuse may lead to legal consequences.

## 📚 Project Status

- ✅ Core modules (scanner, ARP/DNS spoofing, HTTP clone) tested.
- 🔄 Planned: HTTPS downgrade detection.
- 🚧 Future: Real-time monitoring UI.

## 🤝 Contributions

Contributions welcome! Open issues and submit pull requests.

## 📄 License

MIT License. See the LICENSE file for details.
