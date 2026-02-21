import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

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
    Callback function to extract and print details from each captured packet.
    """
    # Check if the packet has an IP layer to avoid errors with ARP/Layer 2 traffic
    if IP in packet:
        stats["Total"] += 1
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)

        # Identify protocol name and update stats
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

        print(f"[{protocol_name}] {src_ip} -> {dst_ip} | Length: {pkt_len} bytes")

def main():
    # CONFIGURATION
    # Filter: 'tcp' captures only TCP; 'port 80' captures HTTP; '' captures everything
    capture_filter = "tcp" 
    capture_count = 20  # Limit to 20 packets for this demonstration
    
    print(f"--- Starting Sniffer (Filter: '{capture_filter}') ---")
    print("Note: Ensure you are running as sudo/Administrator.")
    
    # Start sniffing
    # prn: function to run on each packet
    # filter: BPF (Berkeley Packet Filter) syntax
    # count: number of packets to capture before stopping
    sniff(filter=capture_filter, prn=process_packet, count=capture_count)

    # Summary Output
    print("\n" + "="*30)
    print("       CAPTURE SUMMARY")
    print("="*30)
    print(f"Total Packets Captured: {stats['Total']}")
    print(f"  - TCP Packets:  {stats['TCP']}")
    print(f"  - UDP Packets:  {stats['UDP']}")
    print(f"  - ICMP Packets: {stats['ICMP']}")
    print(f"  - Other:        {stats['Other']}")
    print("="*30)

if __name__ == "__main__":
    main()