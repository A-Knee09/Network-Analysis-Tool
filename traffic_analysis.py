from collections import defaultdict
import re
import time
from kamene.all import IP, TCP, UDP, DNS, HTTP, Raw

# Import our new modules
from attached_assets.layman_summary import PacketTranslator
from attached_assets.network_health import NetworkHealthMonitor
from attached_assets.device_profiler import DeviceProfiler

class TrafficAnalyzer:
    """Class for analyzing network traffic and providing human-readable insights."""
    
    def __init__(self):
        # Initialize our enhanced features
        self.packet_translator = PacketTranslator()
        self.health_monitor = NetworkHealthMonitor()
        self.device_profiler = DeviceProfiler()
        
        # Common port to service mapping
        self.port_services = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP Server",
            68: "DHCP Client",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            161: "SNMP",
            194: "IRC",
            443: "HTTPS",
            465: "SMTPS",
            514: "Syslog",
            993: "IMAPS",
            995: "POP3S",
            1080: "SOCKS Proxy",
            1194: "OpenVPN",
            1433: "MS SQL",
            1434: "MS SQL Monitor",
            1521: "Oracle DB",
            3306: "MySQL",
            3389: "RDP",
            5060: "SIP",
            5222: "XMPP",
            5432: "PostgreSQL",
            5900: "VNC",
            6660: "IRC",
            6661: "IRC",
            6662: "IRC",
            6663: "IRC",
            6664: "IRC",
            6665: "IRC",
            6666: "IRC",
            6667: "IRC",
            6668: "IRC",
            6669: "IRC",
            8000: "HTTP Alt",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt",
            8888: "HTTP Proxy",
            9100: "Printer",
        }
        
        # Application categories based on protocols and ports
        self.categories = {
            "Web Browsing": [(TCP, [80, 443, 8080, 8443]), (UDP, [80, 443])],
            "Email": [(TCP, [25, 110, 143, 465, 587, 993, 995])],
            "File Transfer": [(TCP, [20, 21, 22, 69, 115, 989, 990]), (UDP, [69])],
            "Streaming": [(TCP, [554, 1935, 8554, 8000, 1755]), (UDP, [554, 1935, 5004, 5005])],
            "Gaming": [(TCP, [1119, 3724, 6112, 6113, 27015, 27036]), (UDP, [3478, 3479, 3658, 27015, 27031, 27036])],
            "VoIP": [(TCP, [5060, 5061]), (UDP, [5060, 5061, 16384, 16394])],
            "Database": [(TCP, [1433, 1521, 3306, 5432, 6379, 8529, 9042, 27017])],
            "Remote Access": [(TCP, [22, 23, 3389, 5500, 5800, 5900])],
            "Social Media": [(TCP, [80, 443]), (UDP, [])],  # Relies on hostname/domain detection
            "DNS": [(TCP, [53]), (UDP, [53])],
            "Network Management": [(TCP, [161, 162, 514, 636]), (UDP, [161, 162, 514, 636])]
        }
        
        # Initialize counters
        self.port_count = defaultdict(int)
        self.protocol_count = defaultdict(int)
        self.category_count = defaultdict(int)
        self.communication_pairs = []
        
        # HTTP signatures for common websites/services
        self.http_signatures = {
            r"(facebook\.com|fbcdn\.net)": "Facebook",
            r"(google\.com|googleapis\.com|gstatic\.com)": "Google",
            r"(youtube\.com|ytimg\.com|googlevideo\.com)": "YouTube",
            r"(netflix\.com|nflxvideo\.net)": "Netflix",
            r"(amazon\.com|amazonaws\.com)": "Amazon",
            r"(twitter\.com|twimg\.com)": "Twitter",
            r"(instagram\.com)": "Instagram",
            r"(tiktok\.com|tiktokcdn\.com)": "TikTok",
            r"(snapchat\.com)": "Snapchat",
            r"(apple\.com|icloud\.com)": "Apple",
            r"(microsoft\.com|msn\.com|live\.com)": "Microsoft",
            r"(zoom\.us|zoom\.com)": "Zoom",
            r"(twitch\.tv)": "Twitch",
            r"(reddit\.com)": "Reddit",
            r"(wikipedia\.org)": "Wikipedia",
            r"(github\.com)": "GitHub",
            r"(linkedin\.com)": "LinkedIn",
            r"(pinterest\.com)": "Pinterest",
            r"(slack\.com)": "Slack",
            r"(discord\.com|discordapp\.com)": "Discord",
            r"(spotify\.com)": "Spotify",
            r"(pandora\.com)": "Pandora",
            r"(hulu\.com)": "Hulu",
            r"(disneyplus\.com)": "Disney+",
            r"(cnn\.com)": "CNN",
            r"(bbc\.co\.uk|bbc\.com)": "BBC",
            r"(espn\.com)": "ESPN",
            r"(nytimes\.com)": "New York Times",
            r"(washingtonpost\.com)": "Washington Post",
            r"(ebay\.com)": "eBay",
            r"(paypal\.com)": "PayPal",
        }
        
    def analyze_packet(self, packet):
        """Analyze a packet and update counters."""
        # Skip packets without IP layer
        if IP not in packet:
            return
        
        # Record source-destination pair
        src = packet[IP].src
        dst = packet[IP].dst
        self.communication_pairs.append((src, dst))
        
        # Process packet with our enhanced modules
        self.health_monitor.process_packet(packet)
        self.device_profiler.process_packet(packet)
        
        # Protocol analysis
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            self.port_count[sport] += 1
            self.port_count[dport] += 1
            
            # Categorize traffic based on port
            category = self._categorize_traffic(packet, TCP, sport, dport)
            self.category_count[category] += 1
            
            # Check for HTTP(S) traffic
            if dport == 80 or sport == 80 or dport == 443 or sport == 443:
                # Try to identify the service from payload
                service = self._identify_http_service(packet)
                if service and category == "Web Browsing":
                    self.category_count["Web Browsing"] -= 1
                    
                    if "streaming" in service.lower():
                        self.category_count["Streaming"] += 1
                    elif "social" in service.lower():
                        self.category_count["Social Media"] += 1
                    else:
                        self.category_count["Web Browsing"] += 1
            
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            self.port_count[sport] += 1
            self.port_count[dport] += 1
            
            # Categorize traffic based on port
            category = self._categorize_traffic(packet, UDP, sport, dport)
            self.category_count[category] += 1
            
            # Special case for DNS
            if dport == 53 or sport == 53:
                self.protocol_count["DNS"] += 1
        
        # Update protocol counters
        protocol = self._get_packet_protocol_name(packet)
        self.protocol_count[protocol] += 1
            
    def _get_packet_protocol_name(self, packet):
        """Determine the protocol name of a packet."""
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Check common ports
            if dport == 80 or sport == 80:
                return "HTTP"
            elif dport == 443 or sport == 443:
                return "HTTPS"
            elif dport == 22 or sport == 22:
                return "SSH"
            elif dport == 21 or sport == 21:
                return "FTP"
            elif dport == 25 or sport == 25:
                return "SMTP"
            elif dport == 53 or sport == 53:
                return "DNS"
            else:
                return "TCP"
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if dport == 53 or sport == 53:
                return "DNS"
            else:
                return "UDP"
        elif IP in packet:
            if packet[IP].proto == 1:  # ICMP
                return "ICMP"
            else:
                return f"IP Protocol {packet[IP].proto}"
        else:
            # Fallback for non-IP packets
            return "Other"
    
    def _categorize_traffic(self, packet, layer, sport, dport):
        """Categorize traffic based on protocol and ports."""
        for category, protocols in self.categories.items():
            for proto, ports in protocols:
                if layer == proto and (sport in ports or dport in ports):
                    return category
        return "Other"
    
    def _identify_http_service(self, packet):
        """Try to identify the web service from HTTP headers."""
        if Raw not in packet:
            return None
            
        payload = packet[Raw].load.decode('latin-1', errors='ignore')
        
        # Check for HTTP Host header
        host_match = re.search(r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
        if host_match:
            host = host_match.group(1).strip()
            
            # Check if host matches any signature
            for pattern, service in self.http_signatures.items():
                if re.search(pattern, host, re.IGNORECASE):
                    return service
        
        # Check for common patterns in the payload
        for pattern, service in self.http_signatures.items():
            if re.search(pattern, payload, re.IGNORECASE):
                return service
                
        return None
    
    def get_human_readable_summary(self, packet):
        """Generate a human-readable summary of what a packet represents."""
        # Use our enhanced PacketTranslator for layman-friendly descriptions
        layman_summary = self.packet_translator.translate_packet(packet)
        if layman_summary:
            return layman_summary
            
        # Fallback to the original method if translator fails
        if IP not in packet:
            return "Non-IP network packet"
            
        # Basic info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = self._get_packet_protocol_name(packet)
        
        # Initialize summary
        summary = f"{protocol} communication "
        
        # TCP/UDP specific details
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            src_service = self._get_service_name(src_port)
            dst_service = self._get_service_name(dst_port)
            
            flags = ""
            if packet[TCP].flags.S:
                flags += "SYN "  # Connection initiation
            if packet[TCP].flags.A:
                flags += "ACK "  # Acknowledgment
            if packet[TCP].flags.F:
                flags += "FIN "  # Connection termination
            if packet[TCP].flags.R:
                flags += "RST "  # Connection reset
            if packet[TCP].flags.P:
                flags += "PSH "  # Push data immediately
            
            # Customize message based on flags
            if flags:
                flags = flags.strip()
                if "SYN" in flags and "ACK" not in flags:
                    action = "initiating connection to"
                elif "SYN" in flags and "ACK" in flags:
                    action = "accepting connection from"
                elif "FIN" in flags:
                    action = "closing connection with"
                elif "RST" in flags:
                    action = "forcibly closing connection with"
                elif "ACK" in flags and "PSH" in flags:
                    action = "sending data to"
                elif "ACK" in flags:
                    action = "acknowledging data from"
                else:
                    action = "communicating with"
            else:
                action = "communicating with"
            
            # Create more descriptive summary
            if src_service and dst_service:
                summary = f"{src_service} ({src_ip}:{src_port}) {action} {dst_service} ({dst_ip}:{dst_port})"
            elif src_service:
                summary = f"{src_service} ({src_ip}:{src_port}) {action} {dst_ip}:{dst_port}"
            elif dst_service:
                summary = f"{src_ip}:{src_port} {action} {dst_service} ({dst_ip}:{dst_port})"
            else:
                summary = f"{src_ip}:{src_port} {action} {dst_ip}:{dst_port}"
                
            # Check for specific HTTP traffic
            if dst_port == 80 or src_port == 80:
                http_service = self._identify_http_service(packet)
                if http_service:
                    summary += f" - {http_service}"
            
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            src_service = self._get_service_name(src_port)
            dst_service = self._get_service_name(dst_port)
            
            # Create more descriptive summary for UDP
            if src_service and dst_service:
                summary = f"{src_service} ({src_ip}:{src_port}) sending data to {dst_service} ({dst_ip}:{dst_port})"
            elif src_service:
                summary = f"{src_service} ({src_ip}:{src_port}) sending data to {dst_ip}:{dst_port}"
            elif dst_service:
                summary = f"{src_ip}:{src_port} sending data to {dst_service} ({dst_ip}:{dst_port})"
            else:
                summary = f"{src_ip}:{src_port} sending UDP data to {dst_ip}:{dst_port}"
            
            # Special case for DNS
            if dst_port == 53:
                summary = f"DNS query from {src_ip} to {dst_ip}"
            elif src_port == 53:
                summary = f"DNS response from {src_ip} to {dst_ip}"
                
        elif packet[IP].proto == 1:  # ICMP
            if hasattr(packet, 'type'):
                icmp_type = packet.type
                if icmp_type == 0:
                    summary = f"ICMP Echo Reply from {src_ip} to {dst_ip}"
                elif icmp_type == 8:
                    summary = f"ICMP Echo Request (Ping) from {src_ip} to {dst_ip}"
                elif icmp_type == 3:
                    summary = f"ICMP Destination Unreachable from {src_ip} to {dst_ip}"
                elif icmp_type == 11:
                    summary = f"ICMP Time Exceeded from {src_ip} to {dst_ip}"
                else:
                    summary = f"ICMP Type {icmp_type} from {src_ip} to {dst_ip}"
            else:
                summary = f"ICMP communication from {src_ip} to {dst_ip}"
        
        # Add packet size
        packet_len = len(packet)
        summary += f" ({packet_len} bytes)"
        
        return summary
    
    def _get_service_name(self, port):
        """Get the service name for a port."""
        return self.port_services.get(port, "")
    
    def get_visualization_data(self):
        """Get data for visualization."""
        # Get device profiles for network map
        device_profiles = self.device_profiler.get_device_profiles()
        
        # Get network health data
        health_status = self.health_monitor.get_health_status()
        
        return {
            "protocol_count": dict(self.protocol_count),
            "port_data": dict(self.port_count),
            "application_categories": dict(self.category_count),
            "communication_pairs": self.communication_pairs,
            "device_profiles": device_profiles,
            "network_health": health_status,
            "packet_sizes": [len(p) for p in self.health_monitor.packets_by_time], 
            "timestamps": [t for t, _ in self.health_monitor.packets_by_time]
        }
        
    def get_statistics(self):
        """Get statistics for display and reporting."""
        # Count total packets
        total_packets = sum(self.protocol_count.values())
        
        # Get top protocols
        top_protocols = sorted(
            self.protocol_count.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        # Get top ports
        top_ports = sorted(
            self.port_count.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        # Get top application categories
        top_categories = sorted(
            self.category_count.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        # Count unique IPs
        unique_ips = set()
        for src, dst in self.communication_pairs:
            unique_ips.add(src)
            unique_ips.add(dst)
        
        return {
            "total_packets": total_packets,
            "top_protocols": top_protocols,
            "top_ports": top_ports,
            "top_categories": top_categories,
            "unique_ips": len(unique_ips)
        }
        
    def get_insights(self):
        """Generate human-readable insights about the traffic."""
        insights = []
        stats = self.get_statistics()
        
        # Total traffic insight
        insights.append(f"Analyzed {stats['total_packets']} packets between {stats['unique_ips']} unique IP addresses.")
        
        # Get network health status
        health_status = self.health_monitor.get_health_status()
        
        # Add health score insight
        if health_status["score"] >= 90:
            insights.append(f"Your network health is excellent with a score of {health_status['score']}/100.")
        elif health_status["score"] >= 70:
            insights.append(f"Your network health is good with a score of {health_status['score']}/100.")
        elif health_status["score"] >= 50:
            insights.append(f"Your network health is fair with a score of {health_status['score']}/100.")
        else:
            insights.append(f"Your network health needs attention with a score of {health_status['score']}/100.")
            
        # Add device insights if we have any identified devices
        device_profiles = self.device_profiler.get_device_profiles()
        if device_profiles:
            device_count = len(device_profiles)
            device_types = list(set(d['device_type'] for d in device_profiles if d['confidence'] > 60))
            if device_types:
                insights.append(f"Identified {device_count} devices on your network, including: {', '.join(device_types[:3])}.")
        
        # Top protocol insight
        if stats['top_protocols']:
            top_proto, top_proto_count = stats['top_protocols'][0]
            pct = (top_proto_count / stats['total_packets']) * 100 if stats['total_packets'] > 0 else 0
            insights.append(f"Most common protocol is {top_proto} ({pct:.1f}% of traffic).")
        
        # Application usage insight
        if stats['top_categories']:
            categories = [cat for cat, _ in stats['top_categories'][:3] if cat != "Other"]
            if categories:
                insights.append(f"Main network usage: {', '.join(categories)}.")
        
        # Add health alerts as insights
        if health_status["alerts"]:
            for alert in health_status["alerts"]:
                if alert["level"] in ["critical", "error"]:
                    insights.append(f"⚠️ {alert['message']}")
                    
        # Add health recommendations
        recommendations = self.health_monitor.get_health_recommendations()
        if recommendations:
            insights.append(f"Recommendation: {recommendations[0]}")
        
        # Security insights
        if self.protocol_count.get("ICMP", 0) > stats['total_packets'] * 0.2:
            insights.append("High ICMP traffic detected - possible network scanning or ping flood.")
            
        if "DNS" in self.protocol_count and self.protocol_count["DNS"] > stats['total_packets'] * 0.3:
            insights.append("High DNS traffic - possible DNS tunneling or lookup issues.")
            
        # Performance insight
        if stats['top_categories'] and "Streaming" in dict(stats['top_categories']):
            streaming_pct = dict(stats['top_categories']).get("Streaming", 0) / stats['total_packets'] * 100
            if streaming_pct > 30:
                insights.append(f"Heavy streaming traffic detected ({streaming_pct:.1f}% of packets).")
        
        return insights
    
    def reset(self):
        """Reset all counters and data."""
        self.port_count = defaultdict(int)
        self.protocol_count = defaultdict(int)
        self.category_count = defaultdict(int)
        self.communication_pairs = []
        
        # Re-initialize our new components
        self.packet_translator = PacketTranslator()
        self.health_monitor = NetworkHealthMonitor()
        self.device_profiler = DeviceProfiler()
