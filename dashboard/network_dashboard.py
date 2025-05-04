import tkinter as tk
from tkinter import ttk
import time
import threading
import logging
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import tempfile
import webbrowser
import os
import matplotlib
matplotlib.use('Agg')  # Use Agg backend to avoid GUI issues
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from collections import defaultdict
import json
import random

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class NetworkDashboard:
    """Dashboard showing network traffic visualization and health."""
    
    def __init__(self, parent):
        self.parent = parent
        
        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Split into top and bottom sections
        self.top_frame = ttk.Frame(self.frame)
        self.top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Top split into left and right
        self.left_frame = ttk.LabelFrame(self.top_frame, text="Network Traffic Overview")
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.right_frame = ttk.LabelFrame(self.top_frame, text="Network Health")
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Bottom section for protocol summary
        self.bottom_frame = ttk.LabelFrame(self.frame, text="Protocol Summary")
        self.bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # Set up each section
        self.setup_traffic_overview()
        self.setup_network_health()
        self.setup_traffic_flow()
        
        # Initialize data
        self.packet_data = []
        self.last_update_time = time.time()
        self.update_interval = 2.0  # seconds
        
        # Last update info
        self.last_update_label = ttk.Label(self.frame, text="Last update: Never")
        self.last_update_label.pack(side=tk.RIGHT, padx=5, pady=5)
        
    def setup_traffic_overview(self):
        """Set up traffic overview chart."""
        # Create frame for matplotlib figure
        self.fig_frame = ttk.Frame(self.left_frame)
        self.fig_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create initial figure
        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(5, 4))
        self.traffic_ax.set_title("Protocol Distribution")
        self.traffic_ax.set_ylabel("Packet Count")
        
        # Create canvas for figure
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, self.fig_frame)
        self.traffic_canvas.draw()
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add navigation toolbar
        self.traffic_toolbar = NavigationToolbar2Tk(self.traffic_canvas, self.fig_frame)
        self.traffic_toolbar.update()
        
    def setup_network_health(self):
        """Set up network health indicators."""
        # Create gauge indicators for network health
        self.health_canvas_frame = ttk.Frame(self.right_frame)
        self.health_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create health metrics frame
        self.metrics_frame = ttk.Frame(self.health_canvas_frame)
        self.metrics_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create health metrics with labels and progress bars
        self.health_metrics = {}
        
        metrics = [
            ("traffic_rate", "Traffic Rate", "Normal"),
            ("tcp_pct", "TCP Traffic %", "Normal"),
            ("udp_pct", "UDP Traffic %", "Normal"),
            ("error_rate", "Error Rate", "Low")
        ]
        
        for i, (key, label, status) in enumerate(metrics):
            metric_frame = ttk.Frame(self.metrics_frame)
            metric_frame.pack(fill=tk.X, pady=5)
            
            # Label
            ttk.Label(metric_frame, text=label, width=15).pack(side=tk.LEFT)
            
            # Progress bar
            progress = ttk.Progressbar(
                metric_frame, 
                mode="determinate", 
                length=200,
                value=0
            )
            progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            # Status label
            status_label = ttk.Label(metric_frame, text=status, width=10)
            status_label.pack(side=tk.LEFT)
            
            self.health_metrics[key] = {
                "progress": progress,
                "status": status_label
            }
            
        # Add refresh button
        self.refresh_button = ttk.Button(
            self.health_canvas_frame,
            text="Refresh Health Data",
            command=self.refresh_health_data
        )
        self.refresh_button.pack(pady=10)
        
    def setup_traffic_flow(self):
        """Set up protocol summary table."""
        # Create frame for the table
        self.summary_frame = ttk.Frame(self.bottom_frame)
        self.summary_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview for the summary table
        columns = ("protocol", "count", "percentage", "avg_size")
        self.protocol_tree = ttk.Treeview(self.summary_frame, columns=columns, show="headings")
        
        # Configure columns
        self.protocol_tree.heading("protocol", text="Protocol")
        self.protocol_tree.heading("count", text="Packet Count")
        self.protocol_tree.heading("percentage", text="Percentage")
        self.protocol_tree.heading("avg_size", text="Avg Size (bytes)")
        
        self.protocol_tree.column("protocol", width=100)
        self.protocol_tree.column("count", width=100, anchor="center")
        self.protocol_tree.column("percentage", width=100, anchor="center")
        self.protocol_tree.column("avg_size", width=120, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.summary_frame, orient=tk.VERTICAL, command=self.protocol_tree.yview)
        self.protocol_tree.configure(yscroll=scrollbar.set)
        
        # Pack the widgets
        self.protocol_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add initial placeholder data
        self.protocol_tree.insert("", "end", values=("No data", "", "", ""))
        
        # Add information label
        infoframe = ttk.Frame(self.bottom_frame)
        infoframe.pack(fill=tk.X, padx=10)
        
        ttk.Label(
            infoframe, 
            text="This table shows a summary of the protocols in the captured packets.",
            font=("Segoe UI", 9, "italic")
        ).pack(pady=(0, 5), anchor=tk.W)
        
    def update_dashboard(self, packet_data):
        """Update dashboard with new packet data."""
        # Skip updates that are too frequent
        current_time = time.time()
        if current_time - self.last_update_time < self.update_interval and len(packet_data) < 10:
            return
            
        self.last_update_time = current_time
        self.packet_data = packet_data
        
        # Use threading to avoid blocking UI
        threading.Thread(target=self._update_traffic_overview, daemon=True).start()
        threading.Thread(target=self._update_network_health, daemon=True).start()
        threading.Thread(target=self._update_traffic_flow, daemon=True).start()
        
        # Update last update time
        self.last_update_label.config(
            text=f"Last update: {time.strftime('%H:%M:%S', time.localtime(current_time))}"
        )
        
    def _update_traffic_overview(self):
        """Update traffic overview chart."""
        try:
            if not self.packet_data:
                return
                
            # Count protocols
            protocol_counts = defaultdict(int)
            for packet in self.packet_data:
                protocol = packet.get('protocol', 'Unknown')
                if ' ' in protocol:  # Handle protocols like "TCP (HTTP)"
                    base_protocol = protocol.split(' ')[0]
                    protocol_counts[base_protocol] += 1
                else:
                    protocol_counts[protocol] += 1
                    
            # Create a simpler protocol list
            simplified_counts = defaultdict(int)
            for protocol, count in protocol_counts.items():
                if "TCP" in protocol:
                    simplified_counts["TCP"] += count
                elif "UDP" in protocol:
                    simplified_counts["UDP"] += count
                elif "ICMP" in protocol:
                    simplified_counts["ICMP"] += count
                elif "ARP" in protocol:
                    simplified_counts["ARP"] += count
                else:
                    simplified_counts["Other"] += count
                    
            # Plot data
            self.traffic_ax.clear()
            protocols = list(simplified_counts.keys())
            counts = list(simplified_counts.values())
            
            # Set colors
            colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6']
            
            bars = self.traffic_ax.bar(protocols, counts, color=colors[:len(protocols)])
            self.traffic_ax.set_title("Protocol Distribution")
            self.traffic_ax.set_ylabel("Packet Count")
            
            # Add count labels above bars
            for bar in bars:
                height = bar.get_height()
                self.traffic_ax.text(
                    bar.get_x() + bar.get_width()/2., height + 0.1,
                    f"{int(height)}",
                    ha='center', va='bottom',
                    fontsize=9
                )
                
            # Update canvas
            self.traffic_canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating traffic overview: {e}")
            
    def _update_network_health(self):
        """Update network health indicators with real data."""
        try:
            if not self.packet_data:
                return
                
            # Calculate metrics from packet data
            packet_count = len(self.packet_data)
            
            # Get current time for rate calculation
            current_time = time.time()
            
            # Calculate time window (last 5 seconds)
            time_window = 5.0
            window_start = current_time - time_window
            
            # Count packets in the window
            recent_packets = [p for p in self.packet_data if p.get('time', 0) >= window_start]
            recent_count = len(recent_packets)
            
            # Calculate packets per second
            packets_per_second = recent_count / time_window if time_window > 0 else 0
            
            # Traffic rate - normalize to 0-100 scale (assuming 100 packets/sec is high traffic)
            max_pps = 100  # packets per second considered "high"
            traffic_rate = min(100, (packets_per_second / max_pps) * 100)
            
            # Protocol percentages
            protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
            
            for packet in self.packet_data:
                protocol = packet.get('protocol', 'Unknown')
                if "TCP" in protocol:
                    protocol_counts["TCP"] += 1
                elif "UDP" in protocol:
                    protocol_counts["UDP"] += 1
                elif "ICMP" in protocol:
                    protocol_counts["ICMP"] += 1
                elif "ARP" in protocol:
                    protocol_counts["ARP"] += 1
                else:
                    protocol_counts["Other"] += 1
            
            # Calculate TCP and UDP percentages
            tcp_pct = (protocol_counts["TCP"] / max(1, packet_count)) * 100
            udp_pct = (protocol_counts["UDP"] / max(1, packet_count)) * 100
            
            # Error rate - actual packet errors or retransmissions
            # This would normally be from TCP retransmission analysis
            error_packets = sum(1 for p in self.packet_data if "ICMP" in p.get('protocol', '') and "error" in p.get('protocol', '').lower())
            error_rate = min(100, (error_packets / max(1, packet_count)) * 100)
            
            # Update progress bars
            self._update_metric("traffic_rate", traffic_rate,
                              "Low" if traffic_rate < 30 else "Normal" if traffic_rate < 70 else "High")
                               
            self._update_metric("tcp_pct", tcp_pct,
                              "Low" if tcp_pct < 30 else "Normal" if tcp_pct < 70 else "High")
                               
            self._update_metric("udp_pct", udp_pct,
                              "Low" if udp_pct < 30 else "Normal" if udp_pct < 70 else "High")
                               
            self._update_metric("error_rate", error_rate,
                              "Low" if error_rate < 5 else "Moderate" if error_rate < 20 else "High")
                
        except Exception as e:
            logger.error(f"Error updating network health: {e}")
            
    def _update_metric(self, key, value, status_text):
        """Update a health metric with value and status."""
        if key in self.health_metrics:
            metric = self.health_metrics[key]
            metric["progress"]["value"] = value
            metric["status"].config(text=status_text)
            
            # Update color based on value
            if value < 30:  # Good
                metric["status"].config(foreground="green")
            elif value < 70:  # Warning
                metric["status"].config(foreground="orange")
            else:  # Critical
                metric["status"].config(foreground="red")
                
    def _update_traffic_flow(self):
        """Update protocol summary table."""
        try:
            if not self.packet_data:
                return
                
            # Clear existing table rows
            for item in self.protocol_tree.get_children():
                self.protocol_tree.delete(item)
                
            # Count protocols and calculate statistics
            protocol_stats = {}
            packet_count = len(self.packet_data)
            
            for packet in self.packet_data:
                protocol = packet.get('protocol', 'Unknown')
                size = packet.get('size', 0)
                
                # Extract base protocol (TCP, UDP, etc.)
                base_protocol = protocol
                if ' ' in protocol:
                    base_protocol = protocol.split(' ')[0]
                
                # Simplify to major protocols
                if "TCP" in base_protocol:
                    base_protocol = "TCP"
                elif "UDP" in base_protocol:
                    base_protocol = "UDP"
                elif "ICMP" in base_protocol:
                    base_protocol = "ICMP"
                elif "ARP" in base_protocol:
                    base_protocol = "ARP"
                elif "DNS" in base_protocol:
                    base_protocol = "DNS"
                elif "HTTP" in base_protocol:
                    base_protocol = "HTTP"
                else:
                    base_protocol = "Other"
                
                # Update statistics
                if base_protocol in protocol_stats:
                    protocol_stats[base_protocol]['count'] += 1
                    protocol_stats[base_protocol]['size'] += size
                else:
                    protocol_stats[base_protocol] = {'count': 1, 'size': size}
            
            # Sort protocols by count (descending)
            sorted_protocols = sorted(
                protocol_stats.items(), 
                key=lambda x: x[1]['count'], 
                reverse=True
            )
            
            # Add rows to the table
            for protocol, stats in sorted_protocols:
                count = stats['count']
                percentage = (count / packet_count) * 100 if packet_count > 0 else 0
                avg_size = stats['size'] / count if count > 0 else 0
                
                self.protocol_tree.insert(
                    "", "end", 
                    values=(
                        protocol, 
                        f"{count:,}", 
                        f"{percentage:.1f}%", 
                        f"{avg_size:.1f}"
                    )
                )
            
            # Add a "Total" row
            self.protocol_tree.insert(
                "", "end",
                values=(
                    "TOTAL", 
                    f"{packet_count:,}", 
                    "100.0%", 
                    f"{sum(p.get('size', 0) for p in self.packet_data) / packet_count:.1f}" if packet_count > 0 else "0.0"
                ),
                tags=("total",)
            )
            
            # Highlight the total row
            self.protocol_tree.tag_configure("total", background="#e0e0e0", font=("Segoe UI", 9, "bold"))
                
        except Exception as e:
            logger.error(f"Error updating protocol summary: {e}")
            # Make sure we see something
            self.protocol_tree.insert("", "end", values=("Error updating table", "", "", ""))
            
    def refresh_health_data(self):
        """Manually refresh health data."""
        if self.packet_data:
            threading.Thread(target=self._update_network_health, daemon=True).start()
            threading.Thread(target=self._update_traffic_flow, daemon=True).start()
            
            # Update last update time
            current_time = time.time()
            self.last_update_label.config(
                text=f"Last update: {time.strftime('%H:%M:%S', time.localtime(current_time))}"
            )
