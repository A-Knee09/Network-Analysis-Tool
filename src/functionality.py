from scapy.all import sniff, IP, TCP, UDP, wrpcap, rdpcap
from collections import defaultdict
import csv
import threading


class PacketCapture:
    def __init__(self):
        self.packets = []  # Store raw Scapy packets
        self.capturing = False
        self.lock = threading.Lock()

    def start_capture(self, packet_handler):
        """Start capturing packets in real-time."""
        self.capturing = True
        sniff(prn=packet_handler, stop_filter=lambda _: not self.capturing)

    def stop_capture(self):
        """Stop capturing packets."""
        self.capturing = False

    def process_packet(self, packet):
        """Process each captured packet and extract relevant information."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "Unknown"
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif packet[IP].proto == 1:  # ICMP
                protocol = "ICMP"

            with self.lock:
                self.packets.append(packet)  # Store the raw packet
            return src_ip, dst_ip, protocol
        return None, None, None

    def filter_packets(self, protocol):
        """Filter packets based on the selected protocol."""
        if protocol == "All":
            return self.packets
        return [pkt for pkt in self.packets if self._get_packet_protocol(pkt) == protocol]

    def _get_packet_protocol(self, packet):
        """Get the protocol of a packet."""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif packet[IP].proto == 1:  # ICMP
            return "ICMP"
        return "Unknown"

    def filter_by_ip(self, ip):
        """Filter packets by IP address."""
        return [pkt for pkt in self.packets if ip in (pkt[IP].src, pkt[IP].dst)]

    def get_statistics(self):
        """Generate statistics for the captured packets."""
        protocol_count = defaultdict(int)
        for packet in self.packets:
            protocol = self._get_packet_protocol(packet)
            protocol_count[protocol] += 1
        return protocol_count

    def save_to_pcap(self, filename):
        """Save captured packets to a PCAP file."""
        wrpcap(filename, self.packets)

    def load_from_pcap(self, filename):
        """Load packets from a PCAP file."""
        self.packets = rdpcap(filename)

    def save_to_csv(self, filename):
        """Save captured packets to a CSV file."""
        with open(filename, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Source IP", "Destination IP", "Protocol"])
            for packet in self.packets:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = self._get_packet_protocol(packet)
                    writer.writerow([src_ip, dst_ip, protocol])

    def load_from_csv(self, filename):
        """Load packets from a CSV file."""
        self.packets = []
        with open(filename, mode="r") as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                # CSV loading is not supported for raw packets
                pass


