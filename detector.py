import json
import math
import os
from datetime import datetime
from collections import defaultdict
from scapy.all import IFACES, sniff, IP, TCP, UDP, DNS, ARP
# File where alerts get saved for the dashboard
ALERTS_FILE = "alerts.json"
# Track connections per source IP to detect port scans
connection_tracker = defaultdict(list)


def load_alerts():
    """Read existing alerts from the JSON file."""
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            return json.load(f)
    return []


def save_alert(alert):
    """Append a new alert to the JSON file and print it."""
    alerts = load_alerts()
    alerts.append(alert)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)
    severity = alert["severity"]
    rule = alert["rule"]
    technique = alert["technique"]
    detail = alert["detail"]
    print(f"  [{severity}] {rule} | {technique} | {detail}")
def calculate_entropy(text):
    # Return 0 for empty strings
    if not text:
        return 0.0
    # Count how often each character appears
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    # Sum -p * log2(p) for each character's probability
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy    
    
def detect_port_scan(packet):
    # Only look at TCP SYN packets (connection attempts)
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None
    if packet[TCP].flags != "S":
        return None

    # Record this connection attempt from the source IP
    src = packet[IP].src
    now = datetime.now().timestamp()
    connection_tracker[src].append({"port": packet[TCP].dport, "time": now})

    # Keep only connections from the last 10 seconds
    recent = [c for c in connection_tracker[src] if now - c["time"] < 10]
    connection_tracker[src] = recent
    unique_ports = len(set(c["port"] for c in recent))

    # Flag if more than 5 unique ports probed in 10 seconds
    if unique_ports > 5:
        connection_tracker[src] = []
        return {
            "timestamp": datetime.now().isoformat(),
            "rule": "Port Scan Detected",
            "technique": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "severity": "High",
            "src_ip": src,
            "dst_ip": packet[IP].dst,
            "detail": f"{unique_ports} unique ports probed in 10s from {src}",
        }
    return None


def detect_suspicious_dns(packet):
    # Only look at DNS query packets
    if not packet.haslayer(DNS):
        return None
    if not packet.haslayer(IP):
        return None
    if packet[DNS].qr != 0:
        return None
    if packet[DNS].qd is None:
        return None

    query_name = packet[DNS].qd.qname.decode(errors="ignore")

    # Flag queries longer than 50 characters
    if len(query_name) > 50:
        return {
            "timestamp": datetime.now().isoformat(),
            "rule": "Suspicious Long DNS Query",
            "technique": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "severity": "Medium",
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "detail": f"Long query ({len(query_name)} chars): {query_name[:60]}",
        }
    return None
def detect_dns_tunneling(packet):
    # Only process DNS queries with an IP layer
    if not packet.haslayer(DNS):
        return None
    if not packet.haslayer(IP):
        return None
    if packet[DNS].qr != 0:
        return None
    if packet[DNS].qd is None:
        return None

    # Extract the first subdomain label from the query
    query_name = packet[DNS].qd.qname.decode(errors="ignore").rstrip(".")
    parts = query_name.split(".")
    if len(parts) < 2:
        return None
    # Flag long subdomains with high character randomness
    subdomain = parts[0]
    if len(subdomain) > 15:
        entropy = calculate_entropy(subdomain)
        # Entropy above 3.5 suggests encoded data, not natural language
        if entropy > 3.5:
            return {
                "timestamp": datetime.now().isoformat(),
                "rule": "Possible DNS Tunneling",
                "technique": "T1071.004",
                "technique_name": "Application Layer Protocol: DNS",
                "tactic": "Command and Control",
                "severity": "Critical",
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "detail": f"High entropy ({entropy:.2f}) subdomain: {subdomain[:40]}",
            }
    return None

def detect_unusual_port(packet):
    # Only look at TCP SYN packets
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None
    if packet[TCP].flags != "S":
        return None

    # Ports commonly used by attack tools and backdoors
    suspicious_ports = [4444, 5555, 1234, 31337, 8443, 9001]
    dst_port = packet[TCP].dport

    if dst_port in suspicious_ports:
        return {
            "timestamp": datetime.now().isoformat(),
            "rule": "Connection to Suspicious Port",
            "technique": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "severity": "Critical",
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "detail": f"Outbound SYN to port {dst_port} on {packet[IP].dst}",
        }
    return None


def detect_arp_spoof(packet):
    # Only look at ARP reply packets
    if not packet.haslayer(ARP):
        return None
    if packet[ARP].op != 2:
        return None

    return {
        "timestamp": datetime.now().isoformat(),
        "rule": "ARP Reply Detected",
        "technique": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "severity": "Low",
        "src_ip": packet[ARP].psrc,
        "dst_ip": packet[ARP].pdst,
        "detail": f"ARP reply: {packet[ARP].psrc} is at {packet[ARP].hwsrc}",
    }


# Run every packet through each detection rule
RULES = [detect_port_scan, detect_suspicious_dns, detect_dns_tunneling, detect_unusual_port, detect_arp_spoof]


def process_packet(packet):
    for rule in RULES:
        alert = rule(packet)
        if alert:
            save_alert(alert)
            

def main():
    print("=" * 60)
    print("  Network Threat Detector")
    print("  Monitoring live traffic... Press Ctrl+C to stop.")
    print("=" * 60)
    print()

    # Clear old alerts on startup
    if os.path.exists(ALERTS_FILE):
        os.remove(ALERTS_FILE)

    # Resolve the loopback interface at Index 1
    loopback_iface = IFACES.dev_from_index(1)

    # Sniff explicitly on the loopback interface object
    sniff(iface=loopback_iface, prn=process_packet, store=False)


if __name__ == "__main__":
    main()
