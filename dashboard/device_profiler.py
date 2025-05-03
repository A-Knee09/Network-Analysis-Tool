"""
Device profiler module - identifies and categorizes network devices based on traffic patterns
"""

import re
from collections import defaultdict
from kamene.all import IP, TCP, UDP, DNS, ARP

class DeviceProfiler:
    """Profiles network devices based on their traffic patterns and behavior."""
    
    def __init__(self):
        # Initialize device tracking
        self.devices = {}
        self.mac_to_ip = {}
        self.ip_to_mac = {}
        
        # Device type signatures
        self.device_signatures = {
            # IoT devices
            "iot_device": {
                "ports": [80, 443, 1883, 8883, 5683],  # HTTP, HTTPS, MQTT, CoAP
                "dns_patterns": ["iot", "smart", "device", "cam", "sensor"],
                "low_traffic": True,
                "protocols": ["TCP", "UDP"]
            },
            "smart_speaker": {
                "ports": [443, 8009, 8080, 1900],  # HTTPS, Chromecast, HTTP, SSDP
                "dns_patterns": ["amazon", "alexa", "google", "goog", "home", "echo", "dot"],
                "periodic": True,
                "protocols": ["TCP", "UDP"]
            },
            "smart_tv": {
                "ports": [80, 443, 8008, 8009, 1900],  # HTTP, HTTPS, Chromecast, SSDP
                "dns_patterns": ["tv", "roku", "samsung", "lg", "sony", "hulu", "netflix", "youtube"],
                "high_bandwidth": True,
                "protocols": ["TCP", "UDP"]
            },
            "security_camera": {
                "ports": [80, 443, 554, 1935, 8000],  # HTTP, HTTPS, RTSP, RTMP
                "dns_patterns": ["cam", "camera", "ring", "nest", "arlo", "wyze", "security"],
                "high_bandwidth": True,
                "protocols": ["TCP", "UDP"]
            },
            
            # Common computing devices
            "desktop_computer": {
                "ports": [80, 443, 22, 3389],  # HTTP, HTTPS, SSH, RDP
                "varied_traffic": True,
                "high_bandwidth": True,
                "protocols": ["TCP", "UDP", "ICMP"]
            },
            "mobile_phone": {
                "ports": [80, 443, 5223, 5228],  # HTTP, HTTPS, Apple Push, Google Services
                "dns_patterns": ["apple", "icloud", "google", "android", "push"],
                "varied_traffic": True,
                "protocols": ["TCP", "UDP"]
            },
            "laptop": {
                "ports": [80, 443, 22, 5353],  # HTTP, HTTPS, SSH, mDNS
                "varied_traffic": True,
                "intermittent": True,
                "protocols": ["TCP", "UDP", "ICMP"]
            },
            
            # Network infrastructure
            "router": {
                "ports": [53, 67, 68, 80, 443],  # DNS, DHCP, HTTP, HTTPS
                "central_node": True,
                "protocols": ["TCP", "UDP", "ICMP"]
            },
            "network_storage": {
                "ports": [80, 443, 445, 139, 111],  # HTTP, HTTPS, SMB, NFS
                "dns_patterns": ["nas", "storage", "backup", "synology", "qnap"],
                "high_bandwidth": True,
                "protocols": ["TCP"]
            }
        }
        
        # Port to service mapping
        self.port_services = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP Server",
            68: "DHCP Client",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            161: "SNMP",
            443: "HTTPS",
            445: "SMB",
            548: "AFP",
            631: "IPP (Printing)",
            1883: "MQTT",
            1900: "SSDP/UPnP",
            3306: "MySQL",
            3389: "RDP",
            5353: "mDNS",
            5222: "XMPP",
            5223: "Apple Push",
            5228: "Google Services",
            8008: "HTTP Alt",
            8009: "HTTP Alt",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt"
        }
        
        # MAC address OUI vendor database (simplified)
        self.mac_vendors = {
            "00:11:22": "Apple",
            "00:13:3B": "Apple",
            "00:14:22": "Dell",
            "00:15:5D": "Microsoft",
            "00:17:88": "Philips",
            "00:18:7D": "Samsung",
            "00:1A:79": "Cisco",
            "00:1B:63": "Apple",
            "00:1C:43": "Samsung",
            "00:1D:BA": "Sony",
            "00:21:6A": "Intel",
            "00:24:9B": "Asus",
            "00:25:00": "Apple",
            "00:26:B0": "Apple",
            "00:50:56": "VMware",
            "00:D0:F6": "Nokia",
            "18:65:90": "Apple",
            "28:CF:DA": "Apple",
            "30:10:E4": "Apple",
            "3C:D0:F8": "Apple",
            "40:4D:7F": "Apple",
            "44:00:10": "Apple",
            "44:74:6C": "Sony",
            "4C:B1:6C": "Samsung",
            "60:38:E0": "Belkin",
            "74:DA:38": "LG",
            "78:DD:08": "TP-Link",
            "88:C2:55": "Texas Instruments",
            "B0:34:95": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "C4:2C:03": "Apple",
            "D4:CA:6D": "Routerboard",
            "D8:3A:DD": "Google",
            "E0:63:DA": "Amazon",
            "E8:9F:6D": "Raspberry Pi",
            "EC:0E:C4": "Amazon",
            "FC:F1:36": "Samsung"
        }
    
    def process_packet(self, packet):
        """
        Process a packet to gather device information.
        
        Args:
            packet: A scapy/kamene packet
        """
        # Extract MAC addresses from ARP packets
        if ARP in packet:
            self._process_arp(packet)
            
        # Process IP packets for device profiling
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Initialize device records if needed
            for ip in [src_ip, dst_ip]:
                if ip not in self.devices:
                    self.devices[ip] = self._create_device_record(ip)
            
            # Update device records
            self._update_device_from_packet(packet, src_ip, dst_ip)
    
    def _process_arp(self, packet):
        """Process ARP packet to extract MAC-IP mappings."""
        if packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            # Update MAC-IP mappings
            self.mac_to_ip[mac] = ip
            self.ip_to_mac[ip] = mac
            
            # Initialize device if needed
            if ip not in self.devices:
                self.devices[ip] = self._create_device_record(ip)
                
            # Update MAC address in device record
            self.devices[ip]['mac_address'] = mac
            
            # Get vendor information
            mac_prefix = mac[:8].upper()
            if mac_prefix in self.mac_vendors:
                self.devices[ip]['vendor'] = self.mac_vendors[mac_prefix]
    
    def _create_device_record(self, ip):
        """Create a new device record structure."""
        return {
            'ip_address': ip,
            'mac_address': self.ip_to_mac.get(ip, 'Unknown'),
            'vendor': 'Unknown',
            'device_type': 'Unknown',
            'confidence': 0,
            'first_seen': None,
            'last_seen': None,
            'ports_used': set(),
            'protocols': set(),
            'dns_queries': set(),
            'packet_sizes': [],
            'traffic_volume': 0,
            'connection_count': 0
        }
    
    def _update_device_from_packet(self, packet, src_ip, dst_ip):
        """Update device records based on packet information."""
        # Get timestamp
        timestamp = getattr(packet, 'time', 0)
        size = len(packet)
        
        # Update source device
        src_device = self.devices[src_ip]
        src_device['last_seen'] = timestamp
        if not src_device['first_seen']:
            src_device['first_seen'] = timestamp
        
        src_device['traffic_volume'] += size
        src_device['packet_sizes'].append(size)
        src_device['connection_count'] += 1
        
        # Update destination device
        dst_device = self.devices[dst_ip]
        dst_device['last_seen'] = timestamp
        if not dst_device['first_seen']:
            dst_device['first_seen'] = timestamp
            
        # Update protocols
        if IP in packet:
            protocol = "IP"
            if TCP in packet:
                protocol = "TCP"
                
                # Record ports
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                src_device['ports_used'].add(src_port)
                dst_device['ports_used'].add(dst_port)
                
            elif UDP in packet:
                protocol = "UDP"
                
                # Record ports
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                src_device['ports_used'].add(src_port)
                dst_device['ports_used'].add(dst_port)
                
                # Check for DNS queries
                if DNS in packet and dst_port == 53:
                    self._process_dns(packet, src_device)
                    
            elif packet[IP].proto == 1:
                protocol = "ICMP"
            
            src_device['protocols'].add(protocol)
            dst_device['protocols'].add(protocol)
    
    def _process_dns(self, packet, device):
        """Process DNS packet to extract query information."""
        if hasattr(packet[DNS], 'qd') and packet[DNS].qd:
            try:
                qname = packet[DNS].qd.qname.decode() if hasattr(packet[DNS].qd, 'qname') else ""
                if qname:
                    device['dns_queries'].add(qname.lower())
            except:
                pass
    
    def _guess_device_type(self, device_data):
        """Attempt to identify the device type based on traffic patterns."""
        best_match = None
        highest_score = 0
        
        for device_type, signature in self.device_signatures.items():
            score = 0
            match_reason = []
            
            # Check port usage
            if 'ports' in signature:
                device_ports = device_data['ports_used']
                matching_ports = [p for p in signature['ports'] if p in device_ports]
                if matching_ports:
                    port_score = len(matching_ports) / len(signature['ports'])
                    score += port_score * 30  # 30% weight
                    if port_score > 0.4:  # At least 40% match
                        port_names = [f"{p} ({self.port_services.get(p, '')})" for p in matching_ports]
                        match_reason.append(f"Uses ports: {', '.join(port_names)}")
            
            # Check DNS patterns
            if 'dns_patterns' in signature and device_data['dns_queries']:
                matching_queries = []
                for query in device_data['dns_queries']:
                    if any(pattern in query for pattern in signature['dns_patterns']):
                        matching_queries.append(query)
                
                if matching_queries:
                    dns_score = min(1.0, len(matching_queries) / 5)  # Cap at 5 matches for 100%
                    score += dns_score * 40  # 40% weight
                    if dns_score > 0:
                        match_reason.append(f"DNS lookups match {device_type} patterns")
            
            # Check traffic volume characteristics
            if 'high_bandwidth' in signature and signature['high_bandwidth']:
                if device_data['traffic_volume'] > 100000:  # More than 100KB
                    score += 0.15 * 10  # 10% weight
                    match_reason.append("High bandwidth usage")
            
            if 'low_traffic' in signature and signature['low_traffic']:
                if device_data['traffic_volume'] < 10000:  # Less than 10KB
                    score += 0.15 * 10  # 10% weight
                    match_reason.append("Low bandwidth usage")
            
            # Check protocol diversity
            if 'varied_traffic' in signature and signature['varied_traffic']:
                if len(device_data['protocols']) >= 2:
                    score += 0.1 * 10  # 10% weight
                    match_reason.append(f"Uses multiple protocols: {', '.join(device_data['protocols'])}")
            
            # Check if device appears to be a central node (many connections)
            if 'central_node' in signature and signature['central_node']:
                if device_data['connection_count'] > 50:  # More than 50 connections
                    score += 0.2 * 10  # 10% weight
                    match_reason.append("Acts as a central network node")
            
            # Apply vendor-based bonus if available
            if device_data['vendor'] != 'Unknown':
                vendor = device_data['vendor'].lower()
                if (
                    (device_type == 'mobile_phone' and ('apple' in vendor or 'samsung' in vendor)) or
                    (device_type == 'smart_tv' and ('samsung' in vendor or 'lg' in vendor or 'sony' in vendor)) or
                    (device_type == 'router' and ('cisco' in vendor or 'netgear' in vendor or 'linksys' in vendor)) or
                    (device_type == 'desktop_computer' and ('dell' in vendor or 'hp' in vendor or 'intel' in vendor))
                ):
                    score += 15  # Vendor bonus
                    match_reason.append(f"Vendor ({device_data['vendor']}) matches {device_type}")
            
            # Check if this is the best match so far
            if score > highest_score:
                highest_score = score
                confidence_pct = min(95, int(score))  # Cap at 95% confidence
                best_match = {
                    'type': device_type,
                    'confidence': confidence_pct,
                    'match_reason': match_reason
                }
        
        return best_match
    
    def get_device_profiles(self):
        """Get profiles for all identified devices."""
        profiles = []
        
        for ip, device_data in self.devices.items():
            # Skip devices with very little data
            if device_data['connection_count'] < 3:
                continue
                
            # Try to identify device type if not already identified or confidence is low
            if device_data['device_type'] == 'Unknown' or device_data['confidence'] < 50:
                device_match = self._guess_device_type(device_data)
                if device_match and device_match['confidence'] > device_data['confidence']:
                    device_data['device_type'] = device_match['type']
                    device_data['confidence'] = device_match['confidence']
                    device_data['match_reason'] = device_match['match_reason']
            
            # Create a summary for this device
            device_summary = {
                'ip_address': device_data['ip_address'],
                'mac_address': device_data['mac_address'],
                'vendor': device_data['vendor'],
                'device_type': self._get_friendly_device_name(device_data['device_type']),
                'confidence': device_data['confidence'],
                'traffic_volume': self._format_bytes(device_data['traffic_volume']),
                'connection_count': device_data['connection_count'],
                'protocols': list(device_data['protocols']),
                'common_ports': self._get_common_services(device_data['ports_used']),
                'match_reason': device_data.get('match_reason', [])
            }
            
            profiles.append(device_summary)
        
        # Sort by traffic volume (descending)
        return sorted(profiles, key=lambda d: d['connection_count'], reverse=True)
    
    def _get_friendly_device_name(self, device_type):
        """Convert internal device type to user-friendly name."""
        friendly_names = {
            'iot_device': 'IoT Device',
            'smart_speaker': 'Smart Speaker/Assistant',
            'smart_tv': 'Smart TV or Streaming Device',
            'security_camera': 'Security Camera',
            'desktop_computer': 'Desktop Computer',
            'mobile_phone': 'Mobile Phone or Tablet',
            'laptop': 'Laptop Computer',
            'router': 'Router or Access Point',
            'network_storage': 'Network Storage (NAS)'
        }
        return friendly_names.get(device_type, device_type)
    
    def _format_bytes(self, bytes_value):
        """Format bytes into human-readable format."""
        if bytes_value < 1024:
            return f"{bytes_value} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value/1024:.1f} KB"
        else:
            return f"{bytes_value/(1024*1024):.1f} MB"
    
    def _get_common_services(self, ports):
        """Get common service names for the observed ports."""
        services = []
        for port in ports:
            if port in self.port_services:
                services.append(f"{port} ({self.port_services[port]})")
        
        # Get up to 5 most common ports
        return services[:5]
    
    def get_network_map_data(self):
        """Get data suitable for visualizing the network map."""
        nodes = []
        edges = []
        connections = defaultdict(list)
        
        # Create nodes for all devices
        for ip, device in self.devices.items():
            # Skip devices with very little data
            if device['connection_count'] < 3:
                continue
                
            device_type = device['device_type'] if device['device_type'] != 'Unknown' else 'Other'
            nodes.append({
                'id': ip,
                'label': ip,
                'device_type': device_type,
                'vendor': device['vendor'],
                'traffic': device['traffic_volume'],
                'size': min(30, 10 + (device['connection_count'] // 10))  # Size based on connections
            })
        
        # TODO: Calculate edges based on actual packet flows
        # This would require tracking the actual connections between devices
        # For now, we'll return placeholder data
        
        return {
            'nodes': nodes,
            'edges': edges
        }