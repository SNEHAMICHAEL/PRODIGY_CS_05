from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Initialize variables for protocol-specific info
        protocol_name = ""
        src_port = dst_port = None

        # Determine the protocol
        if protocol == 6:  # TCP
            protocol_name = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

        # Display packet information
        print(f"IP Src: {ip_src} -> IP Dst: {ip_dst}")
        print(f"Protocol: {protocol_name}")
        if src_port and dst_port:
            print(f"Src Port: {src_port} -> Dst Port: {dst_port}")

        # Display payload data
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")
        print("="*50)

# Capture packets
def start_sniffer(interface="Wi-Fi"):
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    print("Starting packet sniffer...")
    start_sniffer()
