"""
Statistics Dashboard - Real-time visualization of protocol statistics
"""

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from PIL import Image, ImageTk
import io

class StatisticsDashboard:
    """Statistics dashboard showing protocol distribution and traffic patterns."""
    
    def __init__(self, parent, packet_capture):
        """Initialize the statistics dashboard."""
        self.parent = parent
        self.packet_capture = packet_capture
        self.running = True
        
        # Create GUI
        self.create_dashboard()
        
    def create_dashboard(self):
        """Create the dashboard GUI."""
        # Main frame
        self.frame = ttk.Frame(self.parent, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Create protocol distribution panel
        self.create_protocol_panel()
        
        # Create protocol timeline panel
        self.create_timeline_panel()
        
        # Create top talkers panel
        self.create_top_talkers_panel()
        
    def create_protocol_panel(self):
        """Create protocol distribution visualization."""
        protocol_frame = ttk.LabelFrame(self.frame, text="Protocol Distribution", padding=10)
        protocol_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create matplotlib figure for the pie chart
        self.protocol_fig = Figure(figsize=(6, 4), dpi=100)
        self.protocol_ax = self.protocol_fig.add_subplot(111)
        
        # Initial empty plot
        self.protocol_ax.text(0.5, 0.5, "Start capturing packets to see protocol distribution", 
                           ha='center', va='center', fontsize=12, color='gray')
        self.protocol_ax.axis('off')
        
        # Create canvas for matplotlib figure
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, master=protocol_frame)
        self.protocol_canvas.draw()
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_timeline_panel(self):
        """Create traffic timeline visualization."""
        timeline_frame = ttk.LabelFrame(self.frame, text="Traffic Timeline", padding=10)
        timeline_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create matplotlib figure for the timeline
        self.timeline_fig = Figure(figsize=(6, 3), dpi=100)
        self.timeline_ax = self.timeline_fig.add_subplot(111)
        
        # Initial empty plot
        self.timeline_ax.text(0.5, 0.5, "Capture packets to see traffic patterns over time", 
                           ha='center', va='center', fontsize=12, color='gray')
        self.timeline_ax.axis('off')
        
        # Create canvas for matplotlib figure
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=timeline_frame)
        self.timeline_canvas.draw()
        self.timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_top_talkers_panel(self):
        """Create top talkers panel."""
        talkers_frame = ttk.LabelFrame(self.frame, text="Top Network Participants", padding=10)
        talkers_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a frame with two columns
        columns_frame = ttk.Frame(talkers_frame)
        columns_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column - Top Source IPs
        sources_frame = ttk.LabelFrame(columns_frame, text="Top Source IPs", padding=10)
        sources_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Create treeview for source IPs
        self.sources_tree = ttk.Treeview(
            sources_frame,
            columns=("IP", "Packets", "Bytes"),
            show="headings",
            height=5
        )
        
        # Configure columns
        self.sources_tree.heading("IP", text="IP Address")
        self.sources_tree.heading("Packets", text="Packets")
        self.sources_tree.heading("Bytes", text="Bytes")
        
        self.sources_tree.column("IP", width=150)
        self.sources_tree.column("Packets", width=80)
        self.sources_tree.column("Bytes", width=80)
        
        # Add scrollbar
        sources_scrollbar = ttk.Scrollbar(sources_frame, orient="vertical", command=self.sources_tree.yview)
        sources_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.sources_tree.configure(yscrollcommand=sources_scrollbar.set)
        
        self.sources_tree.pack(fill=tk.BOTH, expand=True)
        
        # Right column - Top Destination IPs
        dests_frame = ttk.LabelFrame(columns_frame, text="Top Destination IPs", padding=10)
        dests_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Create treeview for destination IPs
        self.dests_tree = ttk.Treeview(
            dests_frame,
            columns=("IP", "Packets", "Bytes"),
            show="headings",
            height=5
        )
        
        # Configure columns
        self.dests_tree.heading("IP", text="IP Address")
        self.dests_tree.heading("Packets", text="Packets")
        self.dests_tree.heading("Bytes", text="Bytes")
        
        self.dests_tree.column("IP", width=150)
        self.dests_tree.column("Packets", width=80)
        self.dests_tree.column("Bytes", width=80)
        
        # Add scrollbar
        dests_scrollbar = ttk.Scrollbar(dests_frame, orient="vertical", command=self.dests_tree.yview)
        dests_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.dests_tree.configure(yscrollcommand=dests_scrollbar.set)
        
        self.dests_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add update button
        self.update_button = ttk.Button(
            talkers_frame,
            text="Refresh Statistics",
            command=self.update_dashboard
        )
        self.update_button.pack(pady=10)
        
    def update_dashboard(self):
        """Update all dashboard elements with current data."""
        self.update_protocol_chart()
        self.update_timeline_chart()
        self.update_top_talkers()
        
    def update_protocol_chart(self):
        """Update the protocol distribution chart."""
        # Get protocol statistics
        protocol_stats = self.packet_capture.get_statistics()
        
        if not protocol_stats or sum(protocol_stats.values()) == 0:
            # No data yet
            self.protocol_ax.clear()
            self.protocol_ax.text(0.5, 0.5, "No packet data available yet", 
                               ha='center', va='center', fontsize=12, color='gray')
            self.protocol_ax.axis('off')
        else:
            # Create pie chart
            self.protocol_ax.clear()
            
            # Get labels and sizes
            labels = list(protocol_stats.keys())
            sizes = list(protocol_stats.values())
            
            # Define colors for each protocol
            colors = {
                'TCP': '#3498db',
                'UDP': '#2ecc71',
                'ICMP': '#e74c3c',
                'ARP': '#f39c12',
                'Other': '#95a5a6'
            }
            
            # Get colors for the protocols in the data
            pie_colors = [colors.get(label, '#9b59b6') for label in labels]
            
            # Create pie chart
            wedges, texts, autotexts = self.protocol_ax.pie(
                sizes, 
                labels=labels, 
                autopct='%1.1f%%',
                startangle=90,
                colors=pie_colors,
                explode=[0.05] * len(sizes)  # Explode all slices
            )
            
            # Style the text and autotext
            for text in texts:
                text.set_fontsize(10)
            for autotext in autotexts:
                autotext.set_fontsize(9)
                autotext.set_fontweight('bold')
                autotext.set_color('white')
            
            # Equal aspect ratio ensures that pie is drawn as a circle
            self.protocol_ax.axis('equal')
            
            # Add title
            self.protocol_ax.set_title(f"Protocol Distribution (Total: {sum(sizes)} packets)")
            
        # Update canvas
        self.protocol_fig.tight_layout()
        self.protocol_canvas.draw()
        
    def update_timeline_chart(self):
        """Update the traffic timeline chart."""
        packets = self.packet_capture.packets
        
        if not packets or len(packets) < 2:
            # Not enough data yet
            self.timeline_ax.clear()
            self.timeline_ax.text(0.5, 0.5, "Capture more packets to see timeline", 
                               ha='center', va='center', fontsize=12, color='gray')
            self.timeline_ax.axis('off')
        else:
            # Create timeline chart
            self.timeline_ax.clear()
            
            # Get packet times
            packet_times = [p.time for p in packets]
            min_time = min(packet_times)
            
            # Group by second
            from collections import defaultdict
            packets_by_time = defaultdict(int)
            for p_time in packet_times:
                # Round to nearest second
                second = int(p_time - min_time)
                packets_by_time[second] += 1
                
            # Sort by time
            sorted_times = sorted(packets_by_time.items())
            x_values = [t[0] for t in sorted_times]
            y_values = [t[1] for t in sorted_times]
            
            # Plot the data
            self.timeline_ax.plot(x_values, y_values, marker='o', linestyle='-', color='#3498db', linewidth=2, markersize=5)
            
            # Fill area under curve
            self.timeline_ax.fill_between(x_values, y_values, color='#3498db', alpha=0.3)
            
            # Add grid
            self.timeline_ax.grid(True, linestyle='--', alpha=0.7)
            
            # Set labels
            self.timeline_ax.set_xlabel("Seconds elapsed")
            self.timeline_ax.set_ylabel("Packets per second")
            self.timeline_ax.set_title("Traffic Volume Over Time")
            
            # Ensure we have a non-zero y range
            if max(y_values) == min(y_values):
                self.timeline_ax.set_ylim(0, max(y_values) + 1)
                
        # Update canvas
        self.timeline_fig.tight_layout()
        self.timeline_canvas.draw()
        
    def update_top_talkers(self):
        """Update the top talkers lists."""
        packets = self.packet_capture.packets
        
        if not packets:
            # No data yet, clear trees
            for item in self.sources_tree.get_children():
                self.sources_tree.delete(item)
            for item in self.dests_tree.get_children():
                self.dests_tree.delete(item)
            return
        
        # Count packets and bytes by source IP
        src_packets = {}
        src_bytes = {}
        
        # Count packets and bytes by destination IP
        dst_packets = {}
        dst_bytes = {}
        
        # Analyze packets
        for packet in packets:
            if hasattr(packet, 'haslayer') and packet.haslayer('IP'):
                # Get source IP
                src_ip = packet['IP'].src
                src_packets[src_ip] = src_packets.get(src_ip, 0) + 1
                src_bytes[src_ip] = src_bytes.get(src_ip, 0) + len(packet)
                
                # Get destination IP
                dst_ip = packet['IP'].dst
                dst_packets[dst_ip] = dst_packets.get(dst_ip, 0) + 1
                dst_bytes[dst_ip] = dst_bytes.get(dst_ip, 0) + len(packet)
        
        # Sort by packet count
        top_sources = sorted(src_packets.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dests = sorted(dst_packets.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Update source IP tree
        for item in self.sources_tree.get_children():
            self.sources_tree.delete(item)
        
        for ip, count in top_sources:
            self.sources_tree.insert("", "end", values=(ip, count, self._format_bytes(src_bytes[ip])))
        
        # Update destination IP tree
        for item in self.dests_tree.get_children():
            self.dests_tree.delete(item)
        
        for ip, count in top_dests:
            self.dests_tree.insert("", "end", values=(ip, count, self._format_bytes(dst_bytes[ip])))
    
    def _format_bytes(self, bytes_count):
        """Format bytes into KB/MB as appropriate."""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024 * 1024:
            return f"{bytes_count / 1024:.1f} KB"
        else:
            return f"{bytes_count / (1024 * 1024):.1f} MB"
            
    def stop(self):
        """Stop the dashboard."""
        self.running = False