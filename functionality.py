from kamene.all import sniff, IP, TCP, UDP, wrpcap, rdpcap, conf, get_if_list, ARP, Raw
from collections import defaultdict
import csv
import threading
import time
import os
import socket

def get_available_interfaces():
    """Get a list of available network interfaces."""
    interfaces = []
    for iface in get_if_list():
        # Get additional information about the interface if possible
        try:
            ip = get_interface_ip(iface)
            interfaces.append((iface, ip or "Unknown IP"))
        except:
            interfaces.append((iface, "Unknown IP"))
    return interfaces

def get_interface_ip(iface):
    """Try to get the IP address of an interface."""
    # Directly use the socket approach which is more reliable
    try:
        import socket
        # Get the IP of the default route interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to Google's DNS to get the default route interface IP
            s.connect(('8.8.8.8', 1))
            default_ip = s.getsockname()[0]
            s.close()
            
            # If the interface is 'lo' (loopback), return 127.0.0.1
            if iface.lower() == 'lo' or 'loop' in iface.lower():
                return '127.0.0.1'
            
            # If this is likely the interface with the default route, return its IP
            if ('eth' in iface.lower() or 'en' in iface.lower() or 
                'wlan' in iface.lower() or 'wi' in iface.lower() or
                'wlp' in iface.lower()):
                return default_ip
        except:
            # If we can't connect to external, handle loopback case
            if iface.lower() == 'lo' or 'loop' in iface.lower():
                return '127.0.0.1'
    except Exception as e:
        print(f"Error getting IP with socket: {e}")
    
    # If all methods fail, return a descriptive placeholder
    if iface.lower() == 'lo' or 'loop' in iface.lower():
        return '127.0.0.1'
    else:
        return 'Active Interface'  # Better than 'Unknown IP'

class PacketCapture:
    def __init__(self):
        self.packets = []  # Store raw Scapy packets
        self.capturing = False
        self.lock = threading.Lock()
        self.capture_thread = None
        self.selected_interface = None
        self.packet_count = 0
        self.start_time = None
        self.stats = {
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0
        }
        # Added for optimization
        self.last_memory_check = time.time()
        self.max_packets = 10000  # Maximum packets to keep in memory

    def start_capture(self, packet_handler, interface=None):
        """Start capturing packets in real-time."""
        self.capturing = True
        self.start_time = time.time()
        self.selected_interface = interface
        
        # Reset stats
        self.stats = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
        
        try:
            print(f"Starting capture on interface {interface}")
            if interface:
                # Check for restricted permissions
                if not self.test_capture(interface):
                    return "Permission denied: Network capture requires administrative privileges."
                
                # Start the actual capture    
                sniff(prn=packet_handler, 
                     stop_filter=lambda _: not self.capturing, 
                     iface=interface,
                     store=False)
            else:
                # Check for restricted permissions on default interface
                if not self.test_capture():
                    return "Permission denied: Network capture requires administrative privileges."
                    
                sniff(prn=packet_handler, 
                     stop_filter=lambda _: not self.capturing,
                     store=False)
        except Exception as e:
            # Return the error to be handled by the GUI
            print(f"Error in start_capture: {e}")
            return str(e)
        return None
        
    def test_capture(self, interface=None):
        """Test if we have permission to capture packets."""
        try:
            # Try to capture a single packet with a 0.1 second timeout
            if interface:
                test_capture = sniff(count=1, timeout=0.1, iface=interface)
            else:
                test_capture = sniff(count=1, timeout=0.1)
            return True
        except Exception as e:
            print(f"Test capture failed: {e}")
            return False

    def stop_capture(self):
        """Stop capturing packets."""
        self.capturing = False
        
    def get_capture_stats(self):
        """Get statistics about the current capture session."""
        if self.start_time:
            duration = time.time() - self.start_time
            packets_per_second = self.packet_count / duration if duration > 0 else 0
            return {
                "duration": round(duration, 2),
                "packets": self.packet_count,
                "rate": round(packets_per_second, 2),
                "protocols": self.stats
            }
        return None

    def process_packet(self, packet):
        """Process each captured packet and extract relevant information with enhanced details.
        Optimized for performance with reduced lock operations."""
        # Get timestamp early for better performance metrics
        time_stamp = getattr(packet, 'time', time.time())
        length = len(packet)
        protocol_type = "other"  # Default protocol type for stats
        
        # Early return for non-IP/ARP packets to avoid unnecessary processing
        if not (IP in packet or ARP in packet):
            packet_info = {
                "src": "Unknown",
                "dst": "Unknown",
                "protocol": "Unknown",
                "length": length,
                "time": time_stamp,
                "port_info": "",
                "payload_size": 0,
                "ttl": None,
                "encrypted": False
            }
            
            # Single lock operation
            with self.lock:
                self.stats["other"] += 1
                self.packet_count += 1
                self.packets.append(packet)
                
            return packet_info
        
        # Extract common information
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            ttl = packet[IP].ttl
            port_info = ""
            payload_size = 0
            is_encrypted = False
            protocol = "Other"
            
            # TCP analysis
            if TCP in packet:
                protocol_type = "tcp"  # For stats
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                port_info = f"{src_port} → {dst_port}"
                
                # Check for common services - using direct comparison for performance
                if dst_port == 80 or src_port == 80:
                    service = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    service = "HTTPS"
                    is_encrypted = True
                elif dst_port == 22 or src_port == 22:
                    service = "SSH"
                    is_encrypted = True
                elif dst_port == 21 or src_port == 21:
                    service = "FTP"
                elif dst_port == 25 or src_port == 25:
                    service = "SMTP"
                elif dst_port == 53 or src_port == 53:
                    service = "DNS"
                else:
                    service = "Unknown"
                    
                protocol = f"{protocol} ({service})"
                
                # Extract payload size
                if Raw in packet:
                    payload_size = len(packet[Raw].load)
                    
            # UDP analysis
            elif UDP in packet:
                protocol_type = "udp"  # For stats
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                port_info = f"{src_port} → {dst_port}"
                
                # Check for common UDP services
                if dst_port == 53 or src_port == 53:
                    service = "DNS"
                elif dst_port == 67 or dst_port == 68:
                    service = "DHCP"
                elif dst_port == 161 or src_port == 161:
                    service = "SNMP"
                else:
                    service = "Unknown"
                    
                protocol = f"{protocol} ({service})"
                
                # Extract payload size
                if Raw in packet:
                    payload_size = len(packet[Raw].load)
                    
            # ICMP analysis
            elif packet[IP].proto == 1:  # ICMP
                protocol_type = "icmp"  # For stats
                protocol = "ICMP"
                if packet.haslayer("ICMP"):
                    icmp_type = packet[packet.getlayer("ICMP")].type
                    if icmp_type == 0:
                        protocol = "ICMP (Echo Reply)"
                    elif icmp_type == 8:
                        protocol = "ICMP (Echo Request)"

            # Prepare packet info
            packet_info = {
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": length,
                "time": time_stamp,
                "port_info": port_info,
                "payload_size": payload_size,
                "ttl": ttl,
                "encrypted": is_encrypted
            }
            
            # Single lock operation for all updates
            with self.lock:
                self.stats[protocol_type] += 1
                self.packet_count += 1
                self.packets.append(packet)
                
            return packet_info
            
        # ARP packet analysis
        elif ARP in packet:
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst
            protocol = "ARP"
            
            # Determine ARP operation
            if packet[ARP].op == 1:
                protocol = "ARP (Request)"
            elif packet[ARP].op == 2:
                protocol = "ARP (Reply)"
                
            # Extract IP information if available
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            
            # Prepare packet info
            packet_info = {
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": length,
                "time": time_stamp,
                "port_info": f"{src_mac} → {dst_mac}",
                "payload_size": 0,
                "ttl": None,
                "encrypted": False
            }
            
            # Single lock operation
            with self.lock:
                self.stats["other"] += 1
                self.packet_count += 1
                self.packets.append(packet)
                
            return packet_info

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
        elif IP in packet and packet[IP].proto == 1:  # ICMP
            return "ICMP"
        elif ARP in packet:
            return "ARP"
        return "Other"

    def filter_by_ip(self, ip):
        """Filter packets by IP address."""
        return [pkt for pkt in self.packets if IP in pkt and (ip in (pkt[IP].src, pkt[IP].dst))]

    def get_statistics(self):
        """Generate statistics for the captured packets."""
        protocol_count = defaultdict(int)
        for packet in self.packets:
            protocol = self._get_packet_protocol(packet)
            protocol_count[protocol] += 1
        return protocol_count

    def save_to_pcap(self, filename):
        """Save captured packets to a PCAP file."""
        try:
            wrpcap(filename, self.packets)
            return True
        except Exception as e:
            return str(e)

    def load_from_pcap(self, filename):
        """Load packets from a PCAP file."""
        try:
            self.packets = rdpcap(filename)
            self.packet_count = len(self.packets)
            self.stats = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
            
            # Update stats
            for packet in self.packets:
                if TCP in packet:
                    self.stats["tcp"] += 1
                elif UDP in packet:
                    self.stats["udp"] += 1
                elif IP in packet and packet[IP].proto == 1:
                    self.stats["icmp"] += 1
                else:
                    self.stats["other"] += 1
                    
            return True
        except Exception as e:
            return str(e)

    def save_to_csv(self, filename):
        """Save captured packets to a CSV file."""
        try:
            with open(filename, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Source", "Destination", "Protocol", "Length", "Time"])
                for packet in self.packets:
                    if IP in packet:
                        src = packet[IP].src
                        dst = packet[IP].dst
                        protocol = self._get_packet_protocol(packet)
                        length = len(packet)
                        time_stamp = packet.time
                        writer.writerow([src, dst, protocol, length, time_stamp])
                    elif ARP in packet:
                        src = packet[ARP].hwsrc
                        dst = packet[ARP].hwdst
                        protocol = "ARP"
                        length = len(packet)
                        time_stamp = packet.time
                        writer.writerow([src, dst, protocol, length, time_stamp])
            return True
        except Exception as e:
            return str(e)
            
    def manage_memory(self, max_packets=None):
        """Manage memory by limiting stored packets."""
        if max_packets is None:
            max_packets = self.max_packets
            
        with self.lock:
            if len(self.packets) > max_packets:
                # Keep only the most recent packets
                self.packets = self.packets[-max_packets:]
                return True
        return False
        
    def check_memory_usage(self):
        """Periodically check and manage memory usage."""
        current_time = time.time()
        # Check every 30 seconds
        if current_time - self.last_memory_check > 30:
            self.last_memory_check = current_time
            return self.manage_memory()
        return False
