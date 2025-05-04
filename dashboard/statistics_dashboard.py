"""
Statistics Dashboard Module
This module provides a dashboard for displaying network statistics.
"""

import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use('Agg')  # Use Agg backend to avoid GUI issues
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time
from collections import defaultdict
import logging
import platform
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class StatisticsDashboard:
    """Dashboard for displaying network statistics."""
    
    def __init__(self, parent):
        self.parent = parent
        
        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Split dashboard into sections
        self.top_frame = ttk.Frame(self.frame)
        self.top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Top left - Protocol Distribution Chart
        self.protocol_frame = ttk.LabelFrame(self.top_frame, text="Protocol Distribution")
        self.protocol_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Top right - Data Volume Chart
        self.volume_frame = ttk.LabelFrame(self.top_frame, text="Data Volume Over Time")
        self.volume_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Bottom frame - Detailed Stats
        self.bottom_frame = ttk.LabelFrame(self.frame, text="Detailed Statistics")
        self.bottom_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Set up charts
        self.setup_protocol_chart()
        self.setup_volume_chart()
        self.setup_detailed_stats()
        
        # Initial data
        self.packet_data = []
        self.last_update_time = time.time()
        self.update_interval = 2.0
        
        # State variables
        self.is_updating = False
        self.timestamps = []
        self.packet_counts = []
        self.data_volume = []
        
    def setup_protocol_chart(self):
        """Set up protocol distribution chart."""
        # Create figure for matplotlib chart
        self.protocol_fig, self.protocol_ax = plt.subplots(figsize=(5, 4))
        self.protocol_ax.set_title("Protocol Distribution")
        
        # Create canvas for figure
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, self.protocol_frame)
        self.protocol_canvas.draw()
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_volume_chart(self):
        """Set up data volume chart."""
        # Create figure for matplotlib chart
        self.volume_fig, self.volume_ax = plt.subplots(figsize=(5, 4))
        self.volume_ax.set_title("Data Volume Over Time")
        self.volume_ax.set_xlabel("Time")
        self.volume_ax.set_ylabel("Bytes")
        
        # Create canvas for figure
        self.volume_canvas = FigureCanvasTkAgg(self.volume_fig, self.volume_frame)
        self.volume_canvas.draw()
        self.volume_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_detailed_stats(self):
        """Set up detailed statistics table."""
        # Create frame for table with scrollbar
        table_frame = ttk.Frame(self.bottom_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for statistics table
        columns = ("Statistic", "Value", "Details")
        self.stats_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=10
        )
        
        # Configure columns
        self.stats_tree.heading("Statistic", text="Statistic")
        self.stats_tree.heading("Value", text="Value")
        self.stats_tree.heading("Details", text="Details")
        
        self.stats_tree.column("Statistic", width=200, anchor=tk.W)
        self.stats_tree.column("Value", width=100, anchor=tk.E)
        self.stats_tree.column("Details", width=400, anchor=tk.W)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.stats_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.stats_tree.xview)
        
        self.stats_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Position treeview and scrollbars
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.stats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add refresh button
        refresh_frame = ttk.Frame(self.bottom_frame)
        refresh_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.refresh_button = ttk.Button(
            refresh_frame,
            text="Refresh Statistics",
            command=self.refresh_stats
        )
        self.refresh_button.pack(side=tk.RIGHT)
        
        # Add timestamp label
        self.timestamp_label = ttk.Label(
            refresh_frame,
            text="Last update: Never"
        )
        self.timestamp_label.pack(side=tk.LEFT)
        
    def update_dashboard(self, packet_data, stats=None):
        """Update dashboard with new packet data and stats."""
        # Skip if already updating
        if self.is_updating:
            return
            
        # Skip if no data
        if not packet_data and not stats:
            return
            
        # Skip updates that are too frequent
        current_time = time.time()
        if current_time - self.last_update_time < self.update_interval and len(packet_data) < 10:
            return
            
        self.is_updating = True
        self.last_update_time = current_time
        self.packet_data = packet_data
        
        # Update charts and statistics in background threads
        threading.Thread(target=self._update_protocol_chart, daemon=True).start()
        threading.Thread(target=self._update_volume_chart, daemon=True).start()
        threading.Thread(target=self._update_detailed_stats, args=(stats,), daemon=True).start()
        
        # Update timestamp
        self.timestamp_label.config(
            text=f"Last update: {time.strftime('%H:%M:%S', time.localtime(current_time))}"
        )
        
    def _update_protocol_chart(self):
        """Update protocol distribution chart."""
        try:
            # Count protocols
            protocol_counts = defaultdict(int)
            
            for packet in self.packet_data:
                protocol = packet.get('protocol', 'Unknown')
                # Extract main protocol type
                if ' ' in protocol:  # Handle protocols like "TCP (HTTP)"
                    base_protocol = protocol.split(' ')[0]
                    protocol_counts[base_protocol] += 1
                else:
                    protocol_counts[protocol] += 1
                    
            # Simplify protocol list if there are too many
            if len(protocol_counts) > 6:
                simplified_counts = defaultdict(int)
                for protocol, count in protocol_counts.items():
                    if protocol in ["TCP", "UDP", "ICMP", "ARP", "DNS"]:
                        simplified_counts[protocol] += count
                    else:
                        simplified_counts["Other"] += count
                        
                protocol_counts = simplified_counts
                
            # Sort by count
            sorted_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)
            protocols = [p[0] for p in sorted_protocols]
            counts = [p[1] for p in sorted_protocols]
            
            # Clear the plot
            self.protocol_ax.clear()
            
            # Plot data as pie chart if we have data
            if sum(counts) > 0:
                # Calculate percentages for labels
                total = sum(counts)
                percentages = [(count / total) * 100 for count in counts]
                labels = [f"{p} ({c} - {p:.1f}%)" for p, c, p in zip(protocols, counts, percentages)]
                
                # Create pie chart
                self.protocol_ax.pie(
                    counts, 
                    labels=labels if len(labels) <= 6 else None,  # Only show labels if not too many
                    autopct='%1.1f%%' if len(labels) <= 6 else None,
                    startangle=140,
                    shadow=False
                )
                self.protocol_ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
                
                # Add legend if many protocols
                if len(labels) > 6:
                    self.protocol_ax.legend(labels, loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
                    
                self.protocol_ax.set_title("Protocol Distribution")
            else:
                self.protocol_ax.text(
                    0.5, 0.5, 
                    "No data available", 
                    horizontalalignment='center',
                    verticalalignment='center',
                    transform=self.protocol_ax.transAxes
                )
                
            # Update canvas
            self.protocol_canvas.draw_idle()
            
        except Exception as e:
            logger.error(f"Error updating protocol chart: {e}")
            
        finally:
            self.is_updating = False
            
    def _update_volume_chart(self):
        """Update data volume chart."""
        try:
            # If we have new data, add to time series with actual timestamps
            current_time = time.strftime('%H:%M:%S')
            
            # Get time window (last 5 seconds)
            window_size = 5.0
            current_timestamp = time.time()
            window_start = current_timestamp - window_size
            
            # Count packets and bytes in the window
            recent_packets = [p for p in self.packet_data if p.get('time', 0) >= window_start]
            total_bytes = sum(p.get('length', 0) for p in recent_packets)
            
            # Add to time series
            self.timestamps.append(current_time)
            self.data_volume.append(total_bytes)
            
            # Keep only last 10 points
            if len(self.timestamps) > 10:
                self.timestamps = self.timestamps[-10:]
                self.data_volume = self.data_volume[-10:]
                
            # Clear the plot
            self.volume_ax.clear()
            
            # Plot time series
            if len(self.timestamps) > 1:
                self.volume_ax.plot(self.timestamps, self.data_volume, marker='o')
                self.volume_ax.set_xlabel('Time')
                self.volume_ax.set_ylabel('Data Volume (bytes)')
                self.volume_ax.set_title('Data Volume Over Time')
                self.volume_ax.tick_params(axis='x', rotation=45)
                self.volume_ax.grid(True)
                
                # Format y-axis with units
                self.volume_ax.ticklabel_format(style='plain', axis='y')
                
                # Ensure plot is properly laid out
                self.volume_fig.tight_layout()
            else:
                self.volume_ax.text(
                    0.5, 0.5, 
                    "Collecting data...", 
                    horizontalalignment='center',
                    verticalalignment='center',
                    transform=self.volume_ax.transAxes
                )
                
            # Update canvas
            self.volume_canvas.draw_idle()
            
        except Exception as e:
            logger.error(f"Error updating volume chart: {e}")
            
    def _update_detailed_stats(self, stats=None):
        """Update detailed statistics table."""
        try:
            # Clear existing items
            for item in self.stats_tree.get_children():
                self.stats_tree.delete(item)
                
            # Calculate basic statistics
            total_packets = len(self.packet_data)
            
            if total_packets == 0:
                self.stats_tree.insert("", "end", values=("No Data", "", "No packets captured yet"))
                return
                
            # Add basic statistics
            self.stats_tree.insert("", "end", values=(
                "Total Packets", 
                str(total_packets),
                "Total number of packets captured or loaded"
            ))
            
            # Protocol distribution
            protocol_counts = defaultdict(int)
            for packet in self.packet_data:
                protocol = packet.get('protocol', 'Unknown')
                if ' ' in protocol:
                    base_protocol = protocol.split(' ')[0]
                    protocol_counts[base_protocol] += 1
                else:
                    protocol_counts[protocol] += 1
                    
            # Add protocol statistics
            for protocol, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                self.stats_tree.insert("", "end", values=(
                    f"{protocol} Packets",
                    f"{count} ({percentage:.1f}%)",
                    f"Number of {protocol} packets captured"
                ))
                
            # Add data volume statistics
            total_bytes = sum(p.get('length', 0) for p in self.packet_data)
            avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
            
            self.stats_tree.insert("", "end", values=(
                "Total Data Volume",
                f"{total_bytes} bytes",
                f"Total data volume of all packets ({self._format_bytes(total_bytes)})"
            ))
            
            self.stats_tree.insert("", "end", values=(
                "Average Packet Size",
                f"{avg_packet_size:.1f} bytes",
                "Average size of individual packets"
            ))
            
            # Add time statistics if available
            if stats and stats.get('duration'):
                duration = stats.get('duration', 0)
                packets_per_sec = stats.get('rate', 0)
                
                self.stats_tree.insert("", "end", values=(
                    "Capture Duration",
                    f"{duration:.2f} seconds",
                    f"Total duration of packet capture ({duration/60:.1f} minutes)"
                ))
                
                self.stats_tree.insert("", "end", values=(
                    "Packet Rate",
                    f"{packets_per_sec:.2f} packets/sec",
                    "Average number of packets captured per second"
                ))
                
                bytes_per_sec = total_bytes / duration if duration > 0 else 0
                self.stats_tree.insert("", "end", values=(
                    "Data Rate",
                    f"{bytes_per_sec:.2f} bytes/sec",
                    f"Average data throughput ({self._format_bytes(bytes_per_sec)}/sec)"
                ))
                
            # Add source/destination statistics
            src_ips = defaultdict(int)
            dst_ips = defaultdict(int)
            
            for packet in self.packet_data:
                src = packet.get('src', 'Unknown')
                dst = packet.get('dst', 'Unknown')
                src_ips[src] += 1
                dst_ips[dst] += 1
                
            # Add top sources
            top_sources = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            src_details = ", ".join([f"{ip}: {count}" for ip, count in top_sources])
            
            self.stats_tree.insert("", "end", values=(
                "Top Source IPs",
                f"{len(src_ips)} unique",
                f"Top 5: {src_details}"
            ))
            
            # Add top destinations
            top_dests = sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            dst_details = ", ".join([f"{ip}: {count}" for ip, count in top_dests])
            
            self.stats_tree.insert("", "end", values=(
                "Top Destination IPs",
                f"{len(dst_ips)} unique",
                f"Top 5: {dst_details}"
            ))
            
        except Exception as e:
            logger.error(f"Error updating detailed stats: {e}")
            
    def _format_bytes(self, size_bytes):
        """Format bytes as KB, MB, GB, etc."""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.2f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.2f} GB"
            
    def refresh_stats(self):
        """Manually refresh statistics."""
        if self.packet_data:
            self.timestamp_label.config(text="Refreshing...")
            threading.Thread(target=self._update_protocol_chart, daemon=True).start()
            threading.Thread(target=self._update_volume_chart, daemon=True).start()
            threading.Thread(target=self._update_detailed_stats, daemon=True).start()
            
            # Update timestamp
            current_time = time.time()
            self.timestamp_label.config(
                text=f"Last update: {time.strftime('%H:%M:%S', time.localtime(current_time))}"
            )
        else:
            self.timestamp_label.config(text="No data available")
