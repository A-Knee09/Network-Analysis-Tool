"""
Network health monitoring module - analyzes network traffic for health and security issues
"""

import time
from collections import defaultdict, deque
from kamene.all import IP, TCP, UDP, ICMP, DNS

class NetworkHealthMonitor:
    """Monitors network traffic for health issues and security concerns."""
    
    def __init__(self, alert_threshold=5, window_size=60):
        """
        Initialize the network health monitor.
        
        Args:
            alert_threshold: Minimum number of suspicious events to trigger an alert
            window_size: Time window in seconds for monitoring
        """
        self.alert_threshold = alert_threshold
        self.window_size = window_size
        
        # Time-based sliding windows for metrics
        self.packets_by_time = deque()
        self.retransmissions = deque()
        self.errors = deque()
        self.suspicious_activities = deque()
        
        # Counters and trackers
        self.connection_tracker = defaultdict(dict)
        self.port_scan_tracker = defaultdict(list)
        self.dns_query_tracker = {}
        self.last_prune_time = time.time()
        
        # Alert status
        self.current_alerts = []
        self.resolved_alerts = []
    
    def process_packet(self, packet):
        """
        Process a packet for health monitoring.
        
        Args:
            packet: A scapy/kamene packet
        """
        current_time = time.time()
        
        # Add packet to time window
        self.packets_by_time.append((current_time, packet))
        
        # Analyze the packet for health issues
        if IP in packet:
            self._check_for_tcp_issues(packet, current_time)
            self._check_for_icmp_errors(packet, current_time)
            self._check_for_potential_port_scan(packet, current_time)
            self._check_for_dns_issues(packet, current_time)
        
        # Periodically prune old data
        if current_time - self.last_prune_time > 5:  # Prune every 5 seconds
            self._prune_old_data(current_time)
            self._generate_alerts()
            self.last_prune_time = current_time
    
    def _check_for_tcp_issues(self, packet, current_time):
        """Check for TCP-related issues like retransmissions or reset connections."""
        if TCP not in packet:
            return
            
        tcp = packet[TCP]
        ip = packet[IP]
        flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        reverse_flow_key = (ip.dst, ip.src, tcp.dport, tcp.sport)
        
        # Track connection states
        if tcp.flags.S and not tcp.flags.A:  # SYN
            self.connection_tracker[flow_key]['syn_time'] = current_time
            self.connection_tracker[flow_key]['state'] = 'SYN_SENT'
            
        elif tcp.flags.S and tcp.flags.A:  # SYN+ACK
            if reverse_flow_key in self.connection_tracker:
                # Calculate connection establishment time
                if 'syn_time' in self.connection_tracker[reverse_flow_key]:
                    syn_time = self.connection_tracker[reverse_flow_key]['syn_time']
                    latency = current_time - syn_time
                    
                    # Check for high latency
                    if latency > 1.0:  # More than 1 second
                        self.suspicious_activities.append(
                            (current_time, f"High latency ({latency:.2f}s) for connection between {ip.src}:{tcp.sport} and {ip.dst}:{tcp.dport}")
                        )
                
                self.connection_tracker[reverse_flow_key]['state'] = 'ESTABLISHED'
                
        elif tcp.flags.R:  # RST
            # Connection reset
            if flow_key in self.connection_tracker or reverse_flow_key in self.connection_tracker:
                self.errors.append(
                    (current_time, f"Connection reset between {ip.src}:{tcp.sport} and {ip.dst}:{tcp.dport}")
                )
                
                # Clean up tracker
                if flow_key in self.connection_tracker:
                    del self.connection_tracker[flow_key]
                if reverse_flow_key in self.connection_tracker:
                    del self.connection_tracker[reverse_flow_key]
        
        # Check for retransmissions (simplified)
        if not tcp.flags.S and not tcp.flags.F and not tcp.flags.R:
            if flow_key in self.connection_tracker:
                # Check if we've seen this sequence number
                seq = tcp.seq
                if 'last_seq' in self.connection_tracker[flow_key]:
                    last_seq = self.connection_tracker[flow_key]['last_seq']
                    if seq == last_seq and 'seq_time' in self.connection_tracker[flow_key]:
                        # Only count if enough time has passed to avoid misidentification
                        last_time = self.connection_tracker[flow_key]['seq_time']
                        if current_time - last_time > 0.1:  # 100ms
                            self.retransmissions.append(
                                (current_time, f"TCP retransmission detected from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}")
                            )
                
                # Update sequence tracking
                self.connection_tracker[flow_key]['last_seq'] = seq
                self.connection_tracker[flow_key]['seq_time'] = current_time
    
    def _check_for_icmp_errors(self, packet, current_time):
        """Check for ICMP error messages."""
        if ICMP not in packet:
            return
            
        icmp = packet[ICMP]
        ip = packet[IP]
        
        # Check for error types
        if icmp.type == 3:  # Destination Unreachable
            error_msg = f"Destination unreachable from {ip.src} to {ip.dst}"
            if icmp.code == 0:
                error_msg += " (Network unreachable)"
            elif icmp.code == 1:
                error_msg += " (Host unreachable)"
            elif icmp.code == 3:
                error_msg += " (Port unreachable)"
            
            self.errors.append((current_time, error_msg))
            
        elif icmp.type == 11:  # Time Exceeded
            self.errors.append(
                (current_time, f"Time exceeded from {ip.src} to {ip.dst}")
            )
    
    def _check_for_potential_port_scan(self, packet, current_time):
        """Check for patterns indicating port scanning activity."""
        if TCP not in packet:
            return
            
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Look for SYN packets
        if tcp.flags.S and not tcp.flags.A:
            self.port_scan_tracker[ip.src].append((current_time, ip.dst, tcp.dport))
            
            # Analyze recent connection attempts from this source
            recent_attempts = [
                (t, d, p) for t, d, p in self.port_scan_tracker[ip.src]
                if current_time - t < 5  # Look at last 5 seconds
            ]
            
            # Check for multiple ports to same destination
            dest_ports = defaultdict(list)
            for _, dst, dport in recent_attempts:
                dest_ports[dst].append(dport)
            
            for dst, ports in dest_ports.items():
                if len(ports) >= 5:  # 5+ ports in 5 seconds
                    self.suspicious_activities.append(
                        (current_time, f"Possible port scan from {ip.src} to {dst} ({len(ports)} ports in 5 seconds)")
                    )
    
    def _check_for_dns_issues(self, packet, current_time):
        """Check for DNS-related issues like failed lookups or unusual patterns."""
        if UDP not in packet or packet[UDP].dport != 53 and packet[UDP].sport != 53:
            return
            
        # Check if it's a DNS packet
        if DNS in packet:
            dns = packet[DNS]
            ip = packet[IP]
            
            if packet[UDP].dport == 53:  # Query
                # Store the query details
                qname = dns.qd.qname.decode() if dns.qd and hasattr(dns.qd, 'qname') else "unknown"
                query_id = dns.id
                self.dns_query_tracker[(ip.src, query_id)] = (current_time, qname)
                
            elif packet[UDP].sport == 53:  # Response
                # Check for errors in response
                if dns.rcode != 0:  # Non-zero rcode indicates error
                    error_type = "unknown error"
                    if dns.rcode == 1:
                        error_type = "format error"
                    elif dns.rcode == 2:
                        error_type = "server failure"
                    elif dns.rcode == 3:
                        error_type = "domain does not exist"
                    
                    self.errors.append(
                        (current_time, f"DNS lookup failed with {error_type} for query ID {dns.id}")
                    )
                    
                    # Add more context if we have the original query
                    if (ip.dst, dns.id) in self.dns_query_tracker:
                        _, qname = self.dns_query_tracker[(ip.dst, dns.id)]
                        self.errors[-1] = (
                            current_time, 
                            f"DNS lookup for {qname} failed with {error_type}"
                        )
    
    def _prune_old_data(self, current_time):
        """Remove data older than the monitoring window."""
        cutoff_time = current_time - self.window_size
        
        # Prune time-windowed data
        self._prune_deque(self.packets_by_time, cutoff_time)
        self._prune_deque(self.retransmissions, cutoff_time)
        self._prune_deque(self.errors, cutoff_time)
        self._prune_deque(self.suspicious_activities, cutoff_time)
        
        # Prune trackers
        for src in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[src] = [
                (t, d, p) for t, d, p in self.port_scan_tracker[src]
                if t >= cutoff_time
            ]
            if not self.port_scan_tracker[src]:
                del self.port_scan_tracker[src]
        
        # Prune connection tracker - remove entries older than 5 minutes
        connection_cutoff = current_time - 300
        for flow_key in list(self.connection_tracker.keys()):
            if 'syn_time' in self.connection_tracker[flow_key] and self.connection_tracker[flow_key]['syn_time'] < connection_cutoff:
                del self.connection_tracker[flow_key]
        
        # Prune DNS tracker - remove entries older than 1 minute
        dns_cutoff = current_time - 60
        for query_key in list(self.dns_query_tracker.keys()):
            if self.dns_query_tracker[query_key][0] < dns_cutoff:
                del self.dns_query_tracker[query_key]
    
    def _prune_deque(self, dq, cutoff_time):
        """Prune old entries from a deque object."""
        while dq and dq[0][0] < cutoff_time:
            dq.popleft()
    
    def _generate_alerts(self):
        """Generate alerts based on current network health."""
        # Reset current alerts
        self.current_alerts = []
        
        # Check for high retransmission rate
        if len(self.retransmissions) > self.alert_threshold:
            self.current_alerts.append({
                "type": "retransmission",
                "level": "warning",
                "message": f"High TCP retransmission rate detected ({len(self.retransmissions)} in the last {self.window_size} seconds)",
                "details": [msg for _, msg in self.retransmissions]
            })
        
        # Check for network errors
        if len(self.errors) > self.alert_threshold:
            self.current_alerts.append({
                "type": "error",
                "level": "error",
                "message": f"Multiple network errors detected ({len(self.errors)} in the last {self.window_size} seconds)",
                "details": [msg for _, msg in self.errors]
            })
        
        # Check for suspicious activities
        if len(self.suspicious_activities) > 0:
            self.current_alerts.append({
                "type": "security",
                "level": "critical",
                "message": f"Suspicious network activity detected ({len(self.suspicious_activities)} events in the last {self.window_size} seconds)",
                "details": [msg for _, msg in self.suspicious_activities]
            })
        
        # Check for packet rate
        packet_rate = len(self.packets_by_time) / self.window_size if self.window_size > 0 else 0
        if packet_rate > 1000:  # More than 1000 packets per second
            self.current_alerts.append({
                "type": "traffic",
                "level": "info",
                "message": f"High traffic volume detected ({packet_rate:.1f} packets/second)",
                "details": [f"High traffic volume could indicate network congestion or a DoS attack"]
            })
    
    def get_health_status(self):
        """Get the current network health status as a dictionary."""
        # Count packets in the last window
        packet_count = len(self.packets_by_time)
        
        # Calculate packet rate
        packet_rate = packet_count / self.window_size if self.window_size > 0 else 0
        
        # Calculate error rate
        error_rate = len(self.errors) / max(1, packet_count)
        
        # Calculate retransmission rate
        retransmission_rate = len(self.retransmissions) / max(1, packet_count)
        
        # Determine overall health score (0-100)
        health_score = 100
        if error_rate > 0.05:  # More than 5% errors
            health_score -= 30
        elif error_rate > 0.01:  # More than 1% errors
            health_score -= 15
            
        if retransmission_rate > 0.05:  # More than 5% retransmissions
            health_score -= 25
        elif retransmission_rate > 0.01:  # More than 1% retransmissions
            health_score -= 10
            
        if len(self.suspicious_activities) > 0:
            health_score -= min(50, len(self.suspicious_activities) * 10)
        
        health_score = max(0, min(100, health_score))
        
        # Determine health status text
        if health_score >= 90:
            status = "Excellent"
        elif health_score >= 70:
            status = "Good"
        elif health_score >= 50:
            status = "Fair"
        elif health_score >= 30:
            status = "Poor"
        else:
            status = "Critical"
        
        return {
            "score": health_score,
            "status": status,
            "packet_rate": packet_rate,
            "error_rate": error_rate * 100,  # Convert to percentage
            "retransmission_rate": retransmission_rate * 100,  # Convert to percentage
            "alerts": self.current_alerts,
            "suspicious_activities": len(self.suspicious_activities)
        }
    
    def get_health_recommendations(self):
        """Get recommendations based on the current health status."""
        health_status = self.get_health_status()
        recommendations = []
        
        if health_status["error_rate"] > 5:
            recommendations.append("Network errors are high. Check connectivity and hardware issues.")
        
        if health_status["retransmission_rate"] > 5:
            recommendations.append("High packet retransmission rate detected. This may indicate network congestion or quality issues.")
        
        if health_status["suspicious_activities"] > 0:
            recommendations.append("Suspicious network activity detected. Monitor for unauthorized access attempts.")
        
        if health_status["packet_rate"] > 1000:
            recommendations.append("Traffic volume is very high. Consider investigating for potential DoS activity or optimize network usage.")
        elif health_status["packet_rate"] < 1:
            recommendations.append("Traffic volume is unusually low. Check if network services are functioning properly.")
        
        if not recommendations:
            if health_status["score"] >= 90:
                recommendations.append("Network appears to be healthy. Continue monitoring for any changes.")
            else:
                recommendations.append("No specific issues detected, but network health could be improved. Regular monitoring recommended.")
        
        return recommendations