from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from redaction import mask_ip, redact_sensitive
import sys

# Dictionary to track protocol statistics
stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0,
    "Total": 0
}

def process_packet(packet):
    """
    Callback function to extract, decode, and redact details from each packet.
    """
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

        # Print basic packet info
        print(f"[{protocol_name}] {src_ip} -> {dst_ip} | {pkt_len} bytes")

        # 3. Layer 7 Decoding: DNS Queries
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode(errors='ignore')
            print(f"    └── [DNS Query] Domain: {redact_sensitive(query)}")

        # 4. Layer 7 Decoding: HTTP Requests (Unencrypted Port 80)
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode(errors='ignore')
                    if any(verb in payload for verb in ["GET", "POST", "PUT", "DELETE"]):
                        # Capture only the first line (Request Line)
                        http_line = payload.splitlines()[0]
                        print(f"    └── [HTTP Request] {redact_sensitive(http_line)}")
                except Exception:
                    pass

def main():
    # CONFIGURATION
    # 'tcp or udp or icmp' ensures we see the required protocol types
    capture_filter = "ip" 
    capture_count = 25  # Rubric requirement: 25 packets
    interface = "lo"    # Rubric requirement: Loopback/Lab interface
    
    print(f"--- Starting Copilot-Assisted Sniffer ---")
    print(f"Target Interface: {interface} | Packet Limit: {capture_count}")
    print("Ethical Guardrails: IP Masking and PII Redaction Enabled.\n")
    
    try:
        # Start sniffing
        sniff(iface=interface, filter=capture_filter, prn=process_packet, count=capture_count)
    except PermissionError:
        print("Error: Please run with sudo / root privileges.")
        sys.exit(1)

    # Summary Output
    print("\n" + "="*35)
    print("        CAPTURE SUMMARY")
    print("="*35)
    print(f"Total Packets Captured: {stats['Total']}")
    print(f"  - TCP Packets:  {stats['TCP']}")
    print(f"  - UDP Packets:  {stats['UDP']}")
    print(f"  - ICMP Packets: {stats['ICMP']}")
    print(f"  - Other:        {stats['Other']}")
    print("="*35)

if __name__ == "__main__":
    main()
