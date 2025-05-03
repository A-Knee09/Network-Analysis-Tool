"""
Layman's packet summary module - provides human-readable explanations of network packets
"""

import re
from datetime import datetime
from kamene.all import IP, TCP, UDP, DNS, ICMP, ARP, Raw

class PacketTranslator:
    """Translates packet information into everyday language for non-technical users."""
    
    def __init__(self):
        # Common application patterns for more descriptive summaries
        self.application_patterns = {
            "Web Browsing": {
                "ports": {80, 443, 8080, 8443},
                "description": "Web browsing"
            },
            "Email": {
                "ports": {25, 110, 143, 465, 587, 993, 995},
                "description": "Email communication"
            },
            "File Transfer": {
                "ports": {20, 21, 22, 69, 989, 990},
                "description": "File transfer"
            },
            "Streaming": {
                "ports": {554, 1935, 8554, 1755, 1935},
                "description": "Media streaming"
            },
            "Gaming": {
                "ports": {3074, 3724, 6112, 27015, 27016},
                "description": "Online gaming"
            },
            "Voice/Video": {
                "ports": {5060, 5061, 16384, 16394},
                "description": "Voice or video call"
            }
        }
        
        # Common web services for recognition
        self.web_services = {
            r"(facebook\.com|fbcdn\.net)": "Facebook",
            r"(google\.com|googleapis\.com|gstatic\.com)": "Google",
            r"(youtube\.com|ytimg\.com|googlevideo\.com)": "YouTube",
            r"(netflix\.com|nflxvideo\.net)": "Netflix",
            r"(amazon\.com|amazonaws\.com)": "Amazon shopping",
            r"(twitter\.com|twimg\.com)": "Twitter",
            r"(instagram\.com)": "Instagram",
            r"(zoom\.us|zoom\.com)": "Zoom meeting",
            r"(office\.com|office365\.com|microsoft\.com)": "Microsoft Office",
            r"(github\.com)": "GitHub code hosting",
            r"(spotify\.com)": "Spotify music streaming",
            r"(apple\.com|icloud\.com)": "Apple services",
        }
        
    def translate_packet(self, packet):
        """Translate a packet into everyday language."""
        if IP not in packet:
            if ARP in packet:
                return self._translate_arp_packet(packet)
            return "Network management communication"
            
        # Get basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S')
        
        # Determine packet type and create appropriate translation
        if TCP in packet:
            return self._translate_tcp_packet(packet, src_ip, dst_ip, timestamp)
        elif UDP in packet:
            return self._translate_udp_packet(packet, src_ip, dst_ip, timestamp)
        elif ICMP in packet:
            return self._translate_icmp_packet(packet, src_ip, dst_ip, timestamp)
        else:
            return f"Network communication from {src_ip} to {dst_ip} at {timestamp}"
    
    def _translate_tcp_packet(self, packet, src_ip, dst_ip, timestamp):
        """Translate a TCP packet into everyday language."""
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        size = len(packet)
        
        # Determine application type based on port
        app_type = "General internet traffic"
        for app, info in self.application_patterns.items():
            if src_port in info["ports"] or dst_port in info["ports"]:
                app_type = info["description"]
                break
        
        # Check for HTTP/HTTPS traffic and identify services
        if dst_port == 80 or dst_port == 443 or src_port == 80 or src_port == 443:
            # Try to identify the web service
            service = self._identify_web_service(packet)
            if service:
                app_type = f"Connection to {service}"
        
        # Create user-friendly connection description
        if tcp.flags.S and not tcp.flags.A:  # SYN flag only
            action = "started a connection for"
        elif tcp.flags.S and tcp.flags.A:  # SYN+ACK flags
            action = "accepted a connection for"
        elif tcp.flags.F:  # FIN flag
            action = "ended a connection for"
        elif tcp.flags.R:  # RST flag
            action = "unexpectedly terminated a connection for"
        elif tcp.flags.P and tcp.flags.A:  # PSH+ACK flags
            action = "exchanged data for"
        else:
            action = "communicated for"
        
        # Create the final translation
        return f"{app_type}: A device ({src_ip}) {action} {app_type.lower()} with another device ({dst_ip}) at {timestamp}. Data size: {size} bytes"
    
    def _translate_udp_packet(self, packet, src_ip, dst_ip, timestamp):
        """Translate a UDP packet into everyday language."""
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        size = len(packet)
        
        # Check for DNS queries
        if src_port == 53 or dst_port == 53:
            if src_port == 53:
                return f"DNS response: The name server ({src_ip}) sent website address information to {dst_ip} at {timestamp}"
            else:
                return f"DNS query: A device ({src_ip}) looked up a website address at {timestamp}"
        
        # Determine application type
        app_type = "General internet traffic"
        for app, info in self.application_patterns.items():
            if src_port in info["ports"] or dst_port in info["ports"]:
                app_type = info["description"]
                break
        
        # Check for streaming or gaming
        if app_type == "Media streaming":
            return f"Streaming media: A device ({src_ip}) is streaming audio/video content at {timestamp}. Data size: {size} bytes"
        elif app_type == "Online gaming":
            return f"Online gaming: A device ({src_ip}) is playing an online game at {timestamp}. Data size: {size} bytes"
        
        return f"{app_type}: Quick data exchange between {src_ip} and {dst_ip} at {timestamp}. Data size: {size} bytes"
    
    def _translate_icmp_packet(self, packet, src_ip, dst_ip, timestamp):
        """Translate an ICMP packet into everyday language."""
        icmp_type = packet[ICMP].type
        
        if icmp_type == 8:  # Echo request
            return f"Network check: A device ({src_ip}) is checking if {dst_ip} is reachable at {timestamp}"
        elif icmp_type == 0:  # Echo reply
            return f"Network confirmation: A device ({src_ip}) confirmed it's reachable to {dst_ip} at {timestamp}"
        elif icmp_type == 3:  # Destination unreachable
            return f"Network error: A device ({src_ip}) reported that {dst_ip} couldn't be reached at {timestamp}"
        else:
            return f"Network diagnostic message between {src_ip} and {dst_ip} at {timestamp}"
    
    def _translate_arp_packet(self, packet):
        """Translate an ARP packet into everyday language."""
        if packet[ARP].op == 1:  # Request
            return f"Device lookup: A device is looking for the physical location of {packet[ARP].pdst} on the local network"
        else:  # Reply
            return f"Device identification: A device identified itself as {packet[ARP].hwsrc} on the local network"
    
    def _identify_web_service(self, packet):
        """Try to identify the web service from packet payload."""
        if Raw not in packet:
            return None
            
        payload = packet[Raw].load.decode('latin-1', errors='ignore')
        
        # Check for Host header in HTTP requests
        host_match = re.search(r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
        if host_match:
            host = host_match.group(1).strip()
            
            # Check if host matches any known service
            for pattern, service in self.web_services.items():
                if re.search(pattern, host, re.IGNORECASE):
                    return service
        
        # Check entire payload for service patterns
        for pattern, service in self.web_services.items():
            if re.search(pattern, payload, re.IGNORECASE):
                return service
                
        return None
    
    def get_security_assessment(self, packet):
        """Generate a simple security assessment for the packet."""
        security_notes = []
        
        if IP in packet:
            # Check for unencrypted web traffic
            if TCP in packet and packet[TCP].dport == 80:
                security_notes.append("This is unencrypted web traffic (HTTP) which could be intercepted.")
            
            # Check for potential port scanning
            if TCP in packet and packet[TCP].flags.S and not packet[TCP].flags.A:
                common_scan_ports = {21, 22, 23, 25, 80, 443, 3306, 3389}
                if packet[TCP].dport in common_scan_ports:
                    security_notes.append(f"This appears to be a connection attempt to port {packet[TCP].dport}, which could be part of a port scan.")
            
            # Check for unusual ICMP
            if ICMP in packet and packet[ICMP].type not in [0, 8]:
                security_notes.append("This is an unusual ICMP message that might indicate network troubleshooting or scanning activity.")
        
        if not security_notes:
            return "No obvious security concerns in this packet."
        
        return " ".join(security_notes)
    
    def get_simplified_breakdown(self, packet):
        """Create a simplified, non-technical breakdown of what's in the packet."""
        parts = []
        
        if IP in packet:
            parts.append(f"Source address: {packet[IP].src}")
            parts.append(f"Destination address: {packet[IP].dst}")
            parts.append(f"Data size: {len(packet)} bytes")
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                parts.append(f"Connection details: {src_port} → {dst_port}")
                
                # Add connection state
                flags = packet[TCP].flags
                if flags.S and not flags.A:
                    parts.append("Connection state: Starting new connection")
                elif flags.S and flags.A:
                    parts.append("Connection state: Accepting connection")
                elif flags.F:
                    parts.append("Connection state: Ending connection")
                elif flags.R:
                    parts.append("Connection state: Abruptly terminating connection")
                elif flags.P:
                    parts.append("Connection state: Sending data")
                else:
                    parts.append("Connection state: General communication")
                    
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                parts.append(f"Connection details: {src_port} → {dst_port}")
                parts.append("Connection state: Quick data exchange (no connection setup)")
                
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                if icmp_type == 8:
                    parts.append("Type: Ping request")
                elif icmp_type == 0:
                    parts.append("Type: Ping reply")
                elif icmp_type == 3:
                    parts.append("Type: Destination unreachable")
                else:
                    parts.append(f"Type: ICMP type {icmp_type}")
        
        elif ARP in packet:
            if packet[ARP].op == 1:
                parts.append(f"ARP request: Who has {packet[ARP].pdst}?")
            else:
                parts.append(f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}")
        
        return parts