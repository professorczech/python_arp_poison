
# ARP Poisoning Lab with Responder and Key Exchange Capture

## 🔍 Overview
This lab demonstrates an ARP poisoning attack using Python and Scapy, combined with Responder to capture NTLM hashes and packet sniffing to identify encryption key exchanges in common protocols.

## 🧪 Lab Goals
- Poison ARP tables between two hosts.
- Launch Responder to capture NTLM challenge/response hashes.
- Sniff traffic and identify protocols: HTTP, HTTPS, SSH, Telnet, FTP, SMB, NetBIOS, LDAP.
- Capture and log key exchange packets (e.g., TLS, SSH, NTLM, etc.)
- Save both full traffic and key exchange packets to PCAP files.

## 🧰 Requirements
- Kali Linux or Debian-based environment
- Python 3.x
- Root privileges (`sudo`)
- Scapy: `pip install scapy`
- Responder: Automatically installed if missing

## 🖥️ Topology
```
[Host 1] <--> [Kali (Attacker)] <--> [Host 2]
192.168.100.101        eth1         192.168.100.1
```

## 🚀 Running the Script

1. Ensure your lab is running and network interfaces are correct.
2. Run the script as root:
   ```bash
   sudo python3 arp_poisoner_lab.py
   ```

## 📁 Output Files
- `arp_poison_capture.pcap` – Full traffic capture
- `key_exchange_only.pcap` – Filtered packets with TLS/SSH/NTLM/LDAP key exchange
- NTLM hashes – Captured by Responder and saved to `/usr/share/responder/logs/`

## 📌 Tips for Analysis

### 🧠 Key Exchange Filters in Wireshark:
- TLS: `tls.handshake`
- SSH: `tcp.port == 22 && ssh`
- NTLM (SMB): `ntlmssp`
- FTP creds: `ftp.request.command == "USER" || ftp.request.command == "PASS"`
- Telnet: `telnet`

## 🛑 Cleanup
The script automatically restores ARP tables and stops Responder when terminated (Ctrl+C).

## 🔒 Legal Notice
This script is for educational use **in isolated lab environments only**. Unauthorized use on production networks may be illegal.

## 👨‍🏫 Instructor Notes
- Students can analyze `.pcap` files using Wireshark.
- Bonus: Try cracking captured NTLM hashes with `hashcat` or `john`.

---

Happy hacking, and always hack ethically!
