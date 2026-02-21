from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from redaction import mask_ip, redact_sensitive
import sys
import platform

# Dictionary to track protocol statistics
stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0,
    "Total": 0
}

def process_packet(packet):
    if IP in packet:
        stats["Total"] += 1
        
        # 1. Capture and Redact IPs (Ethical Guardrail)
        src_ip = mask_ip(packet[IP].src)
        dst_ip = mask_ip(packet[IP].dst)
        pkt_len = len(packet)

        # 2. Identify Protocol
        protocol_name = "Other"
        if packet.haslayer(TCP):
            protocol_name = "TCP"
            stats["TCP"] += 1
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            stats["UDP"] += 1
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
            stats["ICMP"] += 1
        else:
            stats["Other"] += 1

        print(f"[{protocol_name}] {src_ip} -> {dst_ip} | {pkt_len} bytes")

        # 3. Layer 7 Decoding: DNS Queries (Requirement B)
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode(errors='ignore')
            print(f"    └── [DNS Query] Domain: {redact_sensitive(query)}")

        # 4. Layer 7 Decoding: HTTP Requests (Requirement B)
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode(errors='ignore')
                    if any(verb in payload for verb in ["GET", "POST", "HTTP/1.1"]):
                        http_line = payload.splitlines()[0] if payload.splitlines() else ""
                        print(f"    └── [HTTP Data] {redact_sensitive(http_line)}")
                except Exception:
                    pass
