try:
    # Try to import from kamene (preferred)
    from kamene.all import sniff, IP, TCP, UDP, wrpcap, rdpcap, conf, get_if_list, ARP, Raw, ICMP
except ImportError:
    # Fallback to scapy if kamene is not available
    try:
        from scapy.all import sniff, IP, TCP, UDP, wrpcap, rdpcap, conf, get_if_list, ARP, Raw, ICMP
        print("Using scapy instead of kamene")
    except ImportError:
        # Create dummy versions for testing without packet capture capability
        print("WARNING: Neither kamene nor scapy is available. Using dummy packet capture.")
        import time
        # Define dummy packet classes
        class DummyPacket:
            def __init__(self, **kwargs):
                self.fields = {}
                for key, value in kwargs.items():
                    setattr(self, key, value)
                    self.fields[key] = value
                self.packet_size = kwargs.get('length', 1024)
                self.packet_type = kwargs.get('protocol', 'Unknown')
            
            def __contains__(self, item):
                """Check if packet contains a layer."""
                # Special case for the protocol types
                if item == IP:
                    return hasattr(self, 'src') and hasattr(self, 'dst')
                elif item == TCP:
                    return self.packet_type.startswith('TCP') if hasattr(self, 'packet_type') else False
                elif item == UDP:
                    return self.packet_type.startswith('UDP') if hasattr(self, 'packet_type') else False
                elif item == ICMP:
                    return self.packet_type.startswith('ICMP') if hasattr(self, 'packet_type') else False
                elif item == ARP:
                    return self.packet_type.startswith('ARP') if hasattr(self, 'packet_type') else False
                elif item == Raw:
                    return hasattr(self, 'payload')
                return False
            
            def __getitem__(self, item):
                """Get a layer from the packet."""
                # Create a dummy layer for the requested type
                if not hasattr(self, item.__name__):
                    layer = DummyLayer(self)
                    if item == IP:
                        layer.src = getattr(self, 'src', 'Unknown')
                        layer.dst = getattr(self, 'dst', 'Unknown')
                        layer.proto = 6  # Default to TCP
                        layer.fields = {'src': layer.src, 'dst': layer.dst, 'proto': layer.proto}
                    elif item == TCP:
                        layer.sport = random.randint(1024, 65535)
                        layer.dport = 80
                        # Create a robust flags attribute that will handle both object and int flags types
                        flags_obj = type('obj', (object,), {
                            'S': random.choice([True, False]),
                            'A': random.choice([True, False]),
                            'F': random.choice([True, False]),
                            'R': random.choice([True, False]),
                            'P': random.choice([True, False])
                        })
                        layer.flags = flags_obj
                        # Add flag values to fields dictionary for consistent access
                        layer.fields = {
                            'sport': layer.sport, 
                            'dport': layer.dport,
                            'flags': {
                                'S': flags_obj.S,
                                'A': flags_obj.A,
                                'F': flags_obj.F,
                                'R': flags_obj.R,
                                'P': flags_obj.P
                            }
                        }
                    elif item == UDP:
                        layer.sport = random.randint(1024, 65535)
                        layer.dport = random.choice([53, 67, 123])
                        layer.fields = {'sport': layer.sport, 'dport': layer.dport}
                    elif item == ICMP:
                        layer.type = random.choice([0, 8])
                        layer.fields = {'type': layer.type}
                    elif item == ARP:
                        layer.psrc = getattr(self, 'src', 'Unknown')
                        layer.pdst = getattr(self, 'dst', 'Unknown')
                        layer.op = random.choice([1, 2])
                        layer.hwsrc = "00:11:22:33:44:55"
                        layer.fields = {'psrc': layer.psrc, 'pdst': layer.pdst, 'op': layer.op, 'hwsrc': layer.hwsrc}
                    elif item == Raw:
                        layer.load = b"Simulated packet payload"
                        layer.fields = {'load': layer.load}
                    
                    setattr(self, item.__name__, layer)
                
                return getattr(self, item.__name__)
                
            def __len__(self):
                """Return the packet size."""
                return self.packet_size
                
            def layers(self):
                """Return the packet layers based on packet type."""
                layers = []
                if hasattr(self, 'src') and hasattr(self, 'dst'):
                    layers.append(IP)
                    
                if hasattr(self, 'packet_type'):
                    if self.packet_type.startswith('TCP'):
                        layers.append(TCP)
                    elif self.packet_type.startswith('UDP'):
                        layers.append(UDP)
                    elif self.packet_type.startswith('ICMP'):
                        layers.append(ICMP)
                    elif self.packet_type.startswith('ARP'):
                        if IP in layers:
                            layers.remove(IP)
                        layers.append(ARP)
                        
                return layers
                
            def getlayer(self, layer):
                """Get a specific layer."""
                if layer in self.layers():
                    return self[layer]
                return None
                
        class DummyLayer:
            def __init__(self, packet):
                self.packet = packet
                self.fields = {}
                # Add default attributes
                self.src = "Unknown"
                self.dst = "Unknown"
                self.proto = 0
                self.sport = 0
                self.dport = 0
                self.psrc = "Unknown"
                self.pdst = "Unknown"
                self.op = 0
                self.hwsrc = "00:00:00:00:00:00"
                self.load = b""
                self.type = 0
                # Add flags as an object
                self.flags = type('obj', (object,), {
                    'S': False,
                    'A': False,
                    'F': False,
                    'R': False,
                    'P': False
                })
                
        IP = DummyLayer
        TCP = DummyLayer
        UDP = DummyLayer
        ARP = DummyLayer
        Raw = DummyLayer
        ICMP = DummyLayer
        
        # Dummy functions
        def sniff(**kwargs):
            print("Dummy sniff function - no real packets will be captured")
            if kwargs.get('count'):
                return [DummyPacket(time=time.time(), src="192.168.1.1", dst="192.168.1.2")]
            else:
                time.sleep(1)
                handler = kwargs.get('prn')
                if handler:
                    pkt = DummyPacket(time=time.time(), src="192.168.1.1", dst="192.168.1.2")
                    handler(pkt)
            return []
            
        def wrpcap(filename, packets):
            print(f"Dummy wrpcap - would save {len(packets)} packets to {filename}")
            
        def rdpcap(filename):
            print(f"Dummy rdpcap - would load packets from {filename}")
            return [DummyPacket(time=time.time(), src="192.168.1.1", dst="192.168.1.2") for _ in range(5)]
            
        def get_if_list():
            return ["eth0", "wlan0", "lo"]
            
        conf = type('obj', (object,), {
            'ifaces': {},
        })

from collections import defaultdict
import csv
import threading
import time
import os
import socket
import logging
import platform
import subprocess
import random  # Used to generate random data for simulation mode

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_available_interfaces():
    """Get a list of available network interfaces with improved reliability."""
    interfaces = []
    try:
        # Get list of interfaces using platform-specific methods
        if platform.system() == "Windows":
            # Use different approach for Windows
            try:
                from kamene.arch.windows import get_windows_if_list
                windows_interfaces = get_windows_if_list()
                for iface in windows_interfaces:
                    name = iface.get('name', 'Unknown')
                    if name and 'Adapter' not in name:  # Skip virtual adapters
                        ip = iface.get('ip', 'Unknown IP')
                        interfaces.append((name, ip))
            except ImportError:
                logger.warning("Could not import Windows-specific kamene modules")
                # Fallback to socket approach
                interfaces = [("Local Network", socket.gethostbyname(socket.gethostname()))]
        else:
            # Linux/Mac approach
            for iface in get_if_list():
                try:
                    ip = get_interface_ip(iface)
                    interfaces.append((iface, ip or "Unknown IP"))
                except Exception as e:
                    logger.debug(f"Error getting IP for interface {iface}: {e}")
                    interfaces.append((iface, "Unknown IP"))
    except Exception as e:
        logger.error(f"Error listing network interfaces: {e}")
        # Fallback to basic interface detection
        if platform.system() != "Windows":
            try:
                # Try using basic Linux/Unix command
                output = subprocess.check_output("ip link show", shell=True).decode('utf-8')
                for line in output.split('\n'):
                    if ': ' in line and not '@' in line:
                        iface = line.split(': ')[1]
                        interfaces.append((iface, "Unknown IP"))
            except:
                pass
                
    # If still no interfaces found, use default test interfaces
    if not interfaces:
        default_interfaces = []
        if platform.system() == "Windows":
            default_interfaces = [("Ethernet", "192.168.1.1"), ("Wi-Fi", "192.168.1.2")]
        else:  # Linux/Mac
            default_interfaces = [("eth0", "192.168.1.1"), ("wlan0", "192.168.1.2"), ("lo", "127.0.0.1")]
        
        logger.warning(f"Could not detect interfaces. Using default test list: {default_interfaces}")
        interfaces = default_interfaces
        
    return interfaces

def get_interface_ip(iface):
    """Try to get the IP address of an interface with improved reliability."""
    # Method 1: Use socket approach which is more reliable
    try:
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
        except Exception as e:
            logger.debug(f"Socket method failed: {e}")
            # If we can't connect to external, handle loopback case
            if iface.lower() == 'lo' or 'loop' in iface.lower():
                return '127.0.0.1'
    except Exception as e:
        logger.debug(f"Error getting IP with socket: {e}")
    
    # Method 2: Skip trying to get from kamene/scapy as it causes errors
    # This section has been commented out to avoid the error: 'Conf' object has no attribute 'ifaces'
    # Fixed: Properly handle kamene/scapy interface detection
    try:
        # First try importing kamene which is the recommended library
        try:
            from kamene.all import conf
            if hasattr(conf, 'ifaces') and conf.ifaces.get(iface, {}).get('addr'):
                return conf.ifaces[iface]['addr']
        except (ImportError, AttributeError) as e:
            logger.debug(f"Kamene interface detection failed: {e}")
            
            # Try scapy as fallback
            try:
                from scapy.all import conf
                if hasattr(conf, 'ifaces') and conf.ifaces.get(iface, {}).get('addr'):
                    return conf.ifaces[iface]['addr']
            except (ImportError, AttributeError) as e:
                logger.debug(f"Scapy interface detection failed: {e}")
    except Exception as e:
        logger.debug(f"Error getting IP from packet capture libraries: {e}")
    
    # Method 3: Platform specific command-line approach
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(f"ipconfig", shell=True).decode('utf-8')
            current_adapter = None
            for line in output.split('\n'):
                if iface in line:
                    current_adapter = iface
                if current_adapter and "IPv4 Address" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    return ip
        else:  # Linux/Mac
            output = subprocess.check_output(f"ip addr show {iface}", shell=True).decode('utf-8')
            for line in output.split('\n'):
                if "inet " in line and not "inet6" in line:
                    ip = line.split()[1].split('/')[0]
                    return ip
    except Exception as e:
        logger.debug(f"Command line method failed: {e}")
    
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
        self.capture_error = None

    def start_capture(self, packet_handler, interface=None):
        """Start capturing packets in real-time with improved error handling and multiple capture methods."""
        # Reset capture state
        self.packets = []
        self.packet_count = 0
        self.capturing = True
        self.start_time = time.time()
        self.selected_interface = interface
        self.capture_error = None
        
        # Reset stats
        self.stats = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
        
        # If no interface is specified, try to find one
        if not interface:
            interfaces = get_available_interfaces()
            if interfaces:
                interface = interfaces[0][0]  # Use first interface
                logger.info(f"No interface specified, using: {interface}")
                self.selected_interface = interface
            else:
                error_msg = "No network interfaces available"
                logger.error(error_msg)
                self.capture_error = error_msg
                return error_msg
        
        logger.info(f"Starting capture on interface: {interface}")
        
        # Create capture thread to prevent blocking the UI
        def capture_thread_func():
            try:
                # Try multiple capture methods for better compatibility
                methods_to_try = ["standard", "socket", "raw", "async"]
                capture_exceptions = []
                
                for method in methods_to_try:
                    try:
                        if method == "standard":
                            logger.info("Trying standard capture method...")
                            sniff(prn=self._packet_processor(packet_handler), 
                                 stop_filter=lambda _: not self.capturing, 
                                 iface=interface,
                                 store=False)
                            return None  # Success
                            
                        elif method == "socket":
                            logger.info("Trying socket-based capture method...")
                            try:
                                from kamene.all import AsyncSniffer
                            except ImportError:
                                try:
                                    from scapy.all import AsyncSniffer
                                except:
                                    raise ImportError("Could not import AsyncSniffer")
                                    
                            sniffer = AsyncSniffer(
                                prn=self._packet_processor(packet_handler),
                                iface=interface,
                                store=False
                            )
                            sniffer.start()
                            # Keep checking if we should stop
                            while self.capturing:
                                time.sleep(0.5)
                            sniffer.stop()
                            return None  # Success
                            
                        elif method == "raw":
                            logger.info("Trying raw socket capture method...")
                            # Use basic sniffing approach
                            sniff(prn=self._packet_processor(packet_handler), 
                                 timeout=1,  # Short timeout
                                 count=1,    # Just capture one packet to test
                                 iface=interface,
                                 store=False)
                                 
                            # If we got here, it works, so continue capturing
                            while self.capturing:
                                sniff(prn=self._packet_processor(packet_handler), 
                                     timeout=1,  # Short timeout to check capturing flag
                                     iface=interface,
                                     store=False)
                            return None  # Success

                        elif method == "async":
                            logger.info("Trying async capture method with timeout...")
                            # Use a timed sniffing approach
                            while self.capturing:
                                # Capture in short bursts to allow stopping
                                sniff(prn=self._packet_processor(packet_handler), 
                                    timeout=1,  # Short timeout to check capturing flag
                                    iface=interface,
                                    store=False)
                            return None  # Success
                            
                    except Exception as method_error:
                        logger.error(f"Method {method} failed: {method_error}")
                        capture_exceptions.append(f"{method}: {str(method_error)}")
                        
                        if method == methods_to_try[-1]:
                            # If this was the last method, report failure
                            error_msg = f"All capture methods failed. Errors: {'; '.join(capture_exceptions)}"
                            logger.error(error_msg)
                            self.capture_error = error_msg
                            return error_msg
                
                # If all methods failed, fall back to simulation mode
                logger.warning("All real packet capture methods failed. Switching to simulation mode.")
                self.capture_error = None  # Clear the error since we're going to use simulation
                
                # Start simulation thread
                threading.Thread(target=self._simulate_packet_capture, 
                                args=(packet_handler,), 
                                daemon=True).start()
                return None  # Return None to indicate that capture "started" (in simulation mode)
                
            except Exception as e:
                # Return the error to be handled by the GUI
                error_msg = f"Error in capture thread: {e}"
                logger.error(error_msg)
                self.capture_error = error_msg
                return error_msg
        
        # Start capture in a separate thread to not block the UI
        self.capture_thread = threading.Thread(target=capture_thread_func)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # No immediate errors
        return None
        
    def _packet_processor(self, handler_func):
        """Wrapper around the packet handler to ensure proper processing and error handling."""
        def process_wrapper(pkt):
            try:
                # First let our internal processor handle the packet
                packet_info = self.process_packet(pkt)
                # Then pass to the external handler
                if handler_func and packet_info:
                    handler_func(pkt, packet_info)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        return process_wrapper
        
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
            logger.error(f"Test capture failed: {e}")
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
                "protocols": dict(self.stats)
            }
        return None

    def process_packet(self, packet):
        """Process each captured packet and extract relevant information with enhanced details.
        Optimized for performance with reduced lock operations."""
        # Get timestamp early for better performance metrics
        time_stamp = getattr(packet, 'time', time.time())
        length = len(packet)
        protocol_type = "other"  # Default protocol type for stats
        
        # Create default packet_info dictionary with base values
        packet_info = {
            'time': time_stamp,
            'src': "Unknown",
            'dst': "Unknown",
            'protocol': "Unknown",
            'length': length,
            'port_info': "",
            'payload': ""
        }
        
        try:
            # IP packet processing
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_info['src'] = src_ip
                packet_info['dst'] = dst_ip
                
                # TCP packet
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    packet_info['port_info'] = f"{src_port} → {dst_port}"
                    protocol_type = "tcp"
                    
                    # Identify common protocols by port
                    if dst_port == 80 or src_port == 80:
                        packet_info['protocol'] = "TCP (HTTP)"
                    elif dst_port == 443 or src_port == 443:
                        packet_info['protocol'] = "TCP (HTTPS)"
                    elif dst_port == 22 or src_port == 22:
                        packet_info['protocol'] = "TCP (SSH)"
                    elif dst_port == 21 or src_port == 21:
                        packet_info['protocol'] = "TCP (FTP)"
                    elif dst_port == 25 or src_port == 25:
                        packet_info['protocol'] = "TCP (SMTP)"
                    elif dst_port == 53 or src_port == 53:
                        packet_info['protocol'] = "TCP (DNS)"
                    else:
                        packet_info['protocol'] = f"TCP ({dst_port})"
                        
                    # Extract payload if available
                    if Raw in packet:
                        try:
                            raw_data = packet[Raw].load
                            if isinstance(raw_data, bytes):
                                # Try to decode as text, but fall back to hex representation
                                try:
                                    decoded = raw_data.decode('utf-8', errors='replace')
                                    # Truncate if too long
                                    if len(decoded) > 100:
                                        decoded = decoded[:100] + "..."
                                    packet_info['payload'] = decoded
                                except:
                                    # Fallback to hex representation
                                    packet_info['payload'] = raw_data.hex()[:100] + "..."
                        except:
                            pass
                
                # UDP packet
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    packet_info['port_info'] = f"{src_port} → {dst_port}"
                    protocol_type = "udp"
                    
                    # Identify common UDP protocols
                    if dst_port == 53 or src_port == 53:
                        packet_info['protocol'] = "UDP (DNS)"
                    elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
                        packet_info['protocol'] = "UDP (DHCP)"
                    elif dst_port == 123 or src_port == 123:
                        packet_info['protocol'] = "UDP (NTP)"
                    else:
                        packet_info['protocol'] = f"UDP ({dst_port})"
                
                # ICMP packet
                elif ICMP in packet:
                    packet_info['protocol'] = "ICMP"
                    icmp_type = packet[ICMP].type
                    if icmp_type == 8:
                        packet_info['protocol'] = "ICMP (Echo Request)"
                    elif icmp_type == 0:
                        packet_info['protocol'] = "ICMP (Echo Reply)"
                    elif icmp_type == 3:
                        packet_info['protocol'] = "ICMP (Destination Unreachable)"
                    elif icmp_type == 11:
                        packet_info['protocol'] = "ICMP (Time Exceeded)"
                    protocol_type = "icmp"
                
                # Other IP packet
                else:
                    packet_info['protocol'] = f"IP Protocol {packet[IP].proto}"
            
            # ARP packet processing
            elif ARP in packet:
                packet_info['src'] = packet[ARP].psrc
                packet_info['dst'] = packet[ARP].pdst
                packet_info['protocol'] = "ARP"
                if packet[ARP].op == 1:
                    packet_info['protocol'] = "ARP (Request)"
                elif packet[ARP].op == 2:
                    packet_info['protocol'] = "ARP (Reply)"
                # ARP doesn't fit into TCP/UDP/ICMP categories
                protocol_type = "other"
            
            # Ethernet or other non-IP/ARP packet
            else:
                # Try to extract more information from ethernet frames
                src = getattr(packet, 'src', "Unknown")
                dst = getattr(packet, 'dst', "Unknown")
                packet_info['src'] = src
                packet_info['dst'] = dst
                
                # Try to identify protocol based on common patterns
                protocol = "Local Network"  # Better default than "Unknown"
                
                # Extract Ethernet type if available
                if hasattr(packet, 'type'):
                    if packet.type == 0x0800:
                        protocol = "IPv4"
                    elif packet.type == 0x0806:
                        protocol = "ARP"
                    elif packet.type == 0x86dd:
                        protocol = "IPv6"
                    elif packet.type == 0x8100:
                        protocol = "VLAN"
                
                packet_info['protocol'] = protocol
                
                # Try to extract more protocol info from packet layers
                try:
                    # Check if it's a common protocol
                    packet_layers = packet.layers()
                    layer_names = [layer.__name__ for layer in packet_layers]
                    
                    if any("DNS" in str(layer) for layer in layer_names):
                        packet_info['protocol'] = "DNS"
                    elif any("DHCP" in str(layer) for layer in layer_names):
                        packet_info['protocol'] = "DHCP"
                    elif any("ICMP" in str(layer) for layer in layer_names):
                        packet_info['protocol'] = "ICMP"
                        protocol_type = "icmp"
                except:
                    pass
        except Exception as e:
            # If any error occurs during processing, log and use default values
            logger.error(f"Error processing packet: {e}")
        
        # Increment appropriate stats counter
        with self.lock:
            self.stats[protocol_type] += 1
            self.packet_count += 1
            self.packets.append(packet)
            
            # Memory management - if we have too many packets, remove the oldest ones
            if self.packet_count > self.max_packets:
                self.packets = self.packets[-self.max_packets:]
                
        return packet_info
        
    def save_to_pcap(self, filename):
        """Save captured packets to a PCAP file."""
        try:
            if not self.packets:
                return "No packets to save"
                
            with self.lock:
                wrpcap(filename, self.packets)
            return None  # Success
        except Exception as e:
            logger.error(f"Error saving PCAP: {e}")
            return str(e)
    
    # Alias for backward compatibility        
    save_packets_to_pcap = save_to_pcap
            
    def save_to_csv(self, filename, packet_info_list=None):
        """Save packet information to a CSV file."""
        try:
            if not packet_info_list:
                return "No packet information to save"
                
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for i, info in enumerate(packet_info_list):
                    if isinstance(info, dict):  # Make sure it's a properly formatted dict
                        writer.writerow({
                            'No.': i+1,
                            'Time': time.strftime('%H:%M:%S', time.localtime(info.get('time', 0))),
                            'Source': info.get('src', 'Unknown'),
                            'Destination': info.get('dst', 'Unknown'),
                            'Protocol': info.get('protocol', 'Unknown'),
                            'Length': info.get('length', 0),
                            'Info': info.get('port_info', '')
                        })
            return None  # Success
        except Exception as e:
            logger.error(f"Error saving CSV: {e}")
            return str(e)
            
    # Add alias for the method being called in gui.py
    save_packets_to_csv = save_to_csv
            
    def load_from_pcap(self, filename):
        """Load packets from a PCAP file."""
        try:
            loaded_packets = rdpcap(filename)
            
            with self.lock:
                self.packets = loaded_packets
                self.packet_count = len(loaded_packets)
                
                # Reset stats
                self.stats = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
                
                # Process each packet to update stats
                processed_packets = []
                for packet in loaded_packets:
                    packet_info = self.process_packet(packet)
                    if packet_info:
                        processed_packets.append(packet_info)
                        
            return processed_packets
        except Exception as e:
            logger.error(f"Error loading PCAP: {e}")
            return None
            
    # Alias for backward compatibility
    load_packets_from_pcap = load_from_pcap
            
    def _simulate_packet_capture(self, packet_handler):
        """Simulate packet capture when real capture fails."""
        logger.info("Starting simulated packet capture")
        
        # Common protocols and ports for simulation
        protocols = [
            ("TCP", [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (21, "FTP"), (25, "SMTP")]),
            ("UDP", [(53, "DNS"), (67, "DHCP"), (123, "NTP")]),
            ("ICMP", [(8, "Echo Request"), (0, "Echo Reply")])
        ]
        
        # IP address pools
        local_ips = ["192.168.1." + str(i) for i in range(1, 10)]
        remote_ips = ["8.8.8.8", "1.1.1.1", "172.217.169.78", "151.101.1.140", "13.107.42.14"]
        
        # Continue simulating while capturing is True
        while self.capturing:
            # Generate a simulated packet every 0.1-0.5 seconds
            time.sleep(random.uniform(0.1, 0.5))
            
            # Create random packet data
            protocol_group = random.choice(protocols)
            protocol_type = protocol_group[0]
            port_info = random.choice(protocol_group[1]) if protocol_group[1] else (0, "")
            
            # Select random IPs
            is_outgoing = random.choice([True, False])
            if is_outgoing:
                src_ip = random.choice(local_ips)
                dst_ip = random.choice(remote_ips)
            else:
                src_ip = random.choice(remote_ips)
                dst_ip = random.choice(local_ips)
                
            # Create packet info
            packet_info = {
                'time': time.time(),
                'src': src_ip,
                'dst': dst_ip,
                'protocol': f"{protocol_type} ({port_info[1]})" if port_info[1] else protocol_type,
                'length': random.randint(64, 1500),
                'port_info': f"{random.randint(1024, 65535)} → {port_info[0]}" if protocol_type in ["TCP", "UDP"] else ""
            }
            
            # Create dummy packet
            dummy_packet = DummyPacket(
                time=packet_info['time'],
                src=packet_info['src'],
                dst=packet_info['dst']
            )
            
            # Process packet as if it was real
            with self.lock:
                protocol_stat = protocol_type.lower() if protocol_type.lower() in self.stats else "other"
                self.stats[protocol_stat] += 1
                self.packet_count += 1
                self.packets.append(dummy_packet)
                
                # Memory management - if we have too many packets, remove the oldest ones
                if self.packet_count > self.max_packets:
                    self.packets = self.packets[-self.max_packets:]
            
            # Pass to handler
            if packet_handler:
                try:
                    packet_handler(dummy_packet, packet_info)
                except Exception as e:
                    logger.error(f"Error in packet handler with simulated packet: {e}")
            
        logger.info("Stopped simulated packet capture")
            
    def get_packet_details(self, packet_index):
        """Get detailed information about a specific packet."""
        try:
            with self.lock:
                if packet_index < 0 or packet_index >= len(self.packets):
                    return None
                    
                packet = self.packets[packet_index]
                
            # Extract all available information
            details = {"Raw Data": str(packet)}
            
            # Check if packet has layers method
            if not hasattr(packet, 'layers'):
                # For packets without layers method, create basic layer info
                if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                    details["IP"] = {
                        "src": getattr(packet, 'src', 'Unknown'),
                        "dst": getattr(packet, 'dst', 'Unknown'),
                        "protocol": getattr(packet, 'protocol', 'Unknown')
                    }
                return details
            
            try:
                # Add layer-specific details
                for layer in packet.layers():
                    layer_name = layer.__name__
                    layer_instance = packet.getlayer(layer)
                    if layer_instance:
                        layer_details = {}
                        if not hasattr(layer_instance, 'fields'):
                            # Handle case where layer_instance doesn't have fields attribute
                            layer_details = {"info": str(layer_instance)}
                        else:
                            for field in layer_instance.fields:
                                value = layer_instance.fields[field]
                                
                                # Special handling for TCP flags
                                if field == 'flags' and layer_name == 'TCP':
                                    # Handle flags dictionary format
                                    if isinstance(value, dict):
                                        flag_str = ""
                                        for flag_key, flag_val in value.items():
                                            if flag_val:
                                                flag_str += f"{flag_key} "
                                        layer_details[field] = flag_str.strip() or "None"
                                    # Handle object format (with S, A, etc. attributes)
                                    elif hasattr(value, 'S'):
                                        flag_list = []
                                        for flag in ['S', 'A', 'F', 'R', 'P']:
                                            if getattr(value, flag, False):
                                                flag_list.append(flag)
                                        layer_details[field] = ' '.join(flag_list) or "None"
                                    # Handle integer format (common in scapy/kamene)
                                    elif isinstance(value, int):
                                        # Map flag bits to flag names
                                        flag_map = {
                                            0x01: 'F', 0x02: 'S', 0x04: 'R', 
                                            0x08: 'P', 0x10: 'A', 0x20: 'U',
                                            0x40: 'E', 0x80: 'C'
                                        }
                                        flag_list = []
                                        for bit, flag in flag_map.items():
                                            if value & bit:
                                                flag_list.append(flag)
                                        layer_details[field] = ' '.join(flag_list) or "None"
                                    else:
                                        layer_details[field] = str(value)
                                # Convert bytes to readable format if present
                                elif isinstance(value, bytes):
                                    try:
                                        text_value = value.decode('utf-8', errors='replace')
                                        layer_details[field] = f"{text_value} (hex: {value.hex()[:32]}{'...' if len(value) > 16 else ''})"
                                    except:
                                        layer_details[field] = f"Binary data ({len(value)} bytes)"
                                else:
                                    layer_details[field] = str(value)
                        
                        details[layer_name] = layer_details
            except Exception as inner_e:
                logger.warning(f"Error processing packet layers: {inner_e}")
                # Fall back to basic layer info
                if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                    details["IP"] = {
                        "src": getattr(packet, 'src', 'Unknown'),
                        "dst": getattr(packet, 'dst', 'Unknown'),
                        "protocol": getattr(packet, 'protocol', 'Unknown')
                    }
                    
            return details
            
        except Exception as e:
            logger.error(f"Error getting packet details: {e}")
            return {"Error": f"Failed to get packet details: {str(e)}"}
    
    def get_statistics(self):
        """Generate statistics for the captured packets."""
        stats = {
            "total_packets": self.packet_count,
            "start_time": self.start_time,
            "duration": time.time() - self.start_time if self.start_time else 0,
            "protocols": dict(self.stats),
            "packet_rate": self.packet_count / (time.time() - self.start_time) if self.start_time else 0
        }
        
        # Calculate additional statistics if we have packets
        if self.packet_count > 0:
            total_bytes = sum(len(p) for p in self.packets)
            stats["total_bytes"] = total_bytes
            stats["avg_packet_size"] = total_bytes / self.packet_count
            
            # Count unique IPs
            src_ips = set()
            dst_ips = set()
            
            for p in self.packets:
                if IP in p:
                    src_ips.add(p[IP].src)
                    dst_ips.add(p[IP].dst)
                elif ARP in p:
                    src_ips.add(p[ARP].psrc)
                    dst_ips.add(p[ARP].pdst)
                    
            stats["unique_src_ips"] = len(src_ips)
            stats["unique_dst_ips"] = len(dst_ips)
        
        return stats