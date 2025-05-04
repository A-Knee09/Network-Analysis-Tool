"""
Device Dashboard Module
This module provides a dashboard for monitoring devices on the network.
"""

import tkinter as tk
from tkinter import ttk
import threading
import time
from collections import defaultdict, Counter
import logging
import matplotlib
matplotlib.use('Agg')  # Use Agg backend to avoid GUI issues
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import json
import random
import ipaddress

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class DeviceDashboard:
    """Dashboard for monitoring and profiling devices on the network."""
    
    def __init__(self, parent):
        self.parent = parent
        
        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Split dashboard into sections
        self.top_frame = ttk.Frame(self.frame)
        self.top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left side - Device list
        self.device_frame = ttk.LabelFrame(self.top_frame, text="Devices on Network")
        self.device_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Right side - Device Details
        self.details_frame = ttk.LabelFrame(self.top_frame, text="Device Details")
        self.details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Bottom frame - Device traffic chart
        self.chart_frame = ttk.LabelFrame(self.frame, text="Device Traffic")
        self.chart_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Set up content
        self.setup_device_list()
        self.setup_device_details()
        self.setup_traffic_chart()
        
        # Data storage
        self.packet_data = []
        self.device_profiles = {}  # Store device profiles
        self.selected_device = None
        self.last_update_time = time.time()
        self.update_interval = 2.0
        self.is_updating = False
        
        # MAC vendor database (partial, commonly seen vendors)
        self.mac_vendors = {
            "00:00:0C": "Cisco", 
            "00:1A:11": "Google",
            "00:1D:7E": "Cisco-Linksys",
            "00:50:56": "VMware",
            "00:13:3B": "Speed Dragon",
            "00:0C:29": "VMware",
            "00:1A:A0": "Dell",
            "00:14:22": "Dell",
            "00:23:AE": "Dell",
            "00:21:9B": "Dell",
            "00:25:64": "Dell",
            "00:1E:C9": "Dell",
            "78:2B:CB": "Dell",
            "B8:AC:6F": "Dell",
            "00:60:52": "Realtek",
            "00:E0:4C": "Realtek",
            "00:0A:5E": "3Com",
            "00:04:75": "3Com",
            "00:01:03": "3Com",
            "00:05:5D": "D-Link",
            "00:17:9A": "D-Link",
            "00:1B:11": "D-Link",
            "00:1C:F0": "D-Link",
            "1C:BD:B9": "D-Link",
            "28:10:7B": "D-Link",
            "00:1B:63": "Apple",
            "00:03:93": "Apple",
            "00:0A:27": "Apple",
            "00:16:CB": "Apple",
            "00:17:F2": "Apple",
            "00:19:E3": "Apple",
            "00:1D:4F": "Apple",
            "00:1E:52": "Apple",
            "00:1F:5B": "Apple",
            "00:1F:F3": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:25:00": "Apple",
            "00:25:BC": "Apple",
            "00:26:08": "Apple",
            "00:26:B0": "Apple",
            "00:26:BB": "Apple",
            "88:53:95": "Apple",
            "AC:87:A3": "Apple",
            "B4:F0:AB": "Apple",
            "B8:8D:12": "Apple",
            "D4:9A:20": "Apple",
            "D8:30:62": "Apple",
            "E0:F8:47": "Apple",
            "F4:5C:89": "Apple",
            "E8:03:9A": "Samsung",
            "00:15:5D": "Microsoft",
            "00:17:FA": "Microsoft",
            "00:50:F2": "Microsoft",
            "00:03:47": "Intel",
            "00:04:23": "Intel",
            "00:07:E9": "Intel",
            "00:0C:F1": "Intel",
            "00:0E:0C": "Intel",
            "00:11:11": "Intel",
            "00:12:F0": "Intel",
            "00:13:02": "Intel",
            "00:13:20": "Intel",
            "00:13:CE": "Intel",
            "00:13:E8": "Intel",
            "00:15:00": "Intel",
            "00:15:17": "Intel",
            "00:16:6F": "Intel",
            "00:16:76": "Intel",
            "00:16:EA": "Intel",
            "00:16:EB": "Intel",
            "00:18:DE": "Intel"
        }
        
    def setup_device_list(self):
        """Set up device list with treeview."""
        # Create frame for treeview and scrollbar
        list_frame = ttk.Frame(self.device_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for device list
        columns = ("IP Address", "MAC Address", "Device Type", "Packets")
        self.device_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure column headings
        for col in columns:
            self.device_tree.heading(col, text=col)
            
        # Configure column widths
        self.device_tree.column("IP Address", width=120)
        self.device_tree.column("MAC Address", width=130)
        self.device_tree.column("Device Type", width=100)
        self.device_tree.column("Packets", width=70)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.device_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.device_tree.xview)
        
        self.device_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Position treeview and scrollbars
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add search bar
        search_frame = ttk.Frame(self.device_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self._filter_devices)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Add refresh button
        refresh_button = ttk.Button(
            search_frame,
            text="Refresh",
            command=self.refresh_devices
        )
        refresh_button.pack(side=tk.RIGHT)
        
        # Bind selection event
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_selected)
        
    def setup_device_details(self):
        """Set up device details panel."""
        # Create canvas for device details
        self.details_canvas = tk.Canvas(self.details_frame, bg="white", highlightthickness=0)
        self.details_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add text for when no device is selected
        self.details_canvas.create_text(
            150, 100,
            text="Select a device to view details",
            fill="gray"
        )
        
        # Create frame for metrics at the bottom
        metrics_frame = ttk.Frame(self.details_frame)
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create labels for key metrics
        self.metrics = {}
        
        metric_infos = [
            ("packets_sent", "Packets Sent:", "0"),
            ("packets_received", "Packets Received:", "0"),
            ("data_sent", "Data Sent:", "0 bytes"),
            ("data_received", "Data Received:", "0 bytes")
        ]
        
        for i, (key, label_text, default_value) in enumerate(metric_infos):
            frame = ttk.Frame(metrics_frame)
            frame.grid(row=i//2, column=i%2, sticky="ew", padx=5, pady=2)
            
            label = ttk.Label(frame, text=label_text, width=15, anchor=tk.W)
            label.pack(side=tk.LEFT)
            
            value = ttk.Label(frame, text=default_value)
            value.pack(side=tk.LEFT)
            
            self.metrics[key] = value
            
    def setup_traffic_chart(self):
        """Set up traffic chart for selected device."""
        # Create matplotlib figure
        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(8, 4))
        self.traffic_ax.set_title("No Device Selected")
        self.traffic_ax.set_xlabel("Protocol")
        self.traffic_ax.set_ylabel("Packet Count")
        
        # Create canvas for figure
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, self.chart_frame)
        self.traffic_canvas.draw()
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def update_dashboard(self, packet_data):
        """Update dashboard with new packet data."""
        # Skip if already updating
        if self.is_updating:
            return
            
        # Skip if no data
        if not packet_data:
            return
            
        # Skip updates that are too frequent
        current_time = time.time()
        if current_time - self.last_update_time < self.update_interval and len(packet_data) < 10:
            return
            
        self.is_updating = True
        self.last_update_time = current_time
        self.packet_data = packet_data
        
        # Update device profiles in background thread
        threading.Thread(target=self._update_device_profiles, daemon=True).start()
        
    def _update_device_profiles(self):
        """Update device profiles based on packet data."""
        try:
            # Create device profiles from packet data
            for packet in self.packet_data:
                src_ip = packet.get('src', 'Unknown')
                dst_ip = packet.get('dst', 'Unknown')
                protocol = packet.get('protocol', 'Unknown')
                length = packet.get('length', 0)
                
                # Skip invalid IPs
                if src_ip == 'Unknown' or dst_ip == 'Unknown':
                    continue
                    
                # Update source device profile
                if src_ip not in self.device_profiles:
                    self.device_profiles[src_ip] = self._create_device_profile(src_ip)
                    
                src_profile = self.device_profiles[src_ip]
                src_profile['packets_sent'] += 1
                src_profile['data_sent'] += length
                src_profile['protocols_used'][protocol] += 1
                src_profile['destinations'].add(dst_ip)
                
                # Update destination device profile
                if dst_ip not in self.device_profiles:
                    self.device_profiles[dst_ip] = self._create_device_profile(dst_ip)
                    
                dst_profile = self.device_profiles[dst_ip]
                dst_profile['packets_received'] += 1
                dst_profile['data_received'] += length
                dst_profile['protocols_seen'][protocol] += 1
                dst_profile['sources'].add(src_ip)
                
                # Try to determine port usage if available
                port_info = packet.get('port_info', '')
                if port_info:
                    # Extract source and destination ports if available
                    try:
                        parts = port_info.split('→')
                        if len(parts) == 2:
                            src_port = parts[0].strip()
                            dst_port = parts[1].strip()
                            
                            # Update port information
                            if src_port.isdigit():
                                src_profile['ports_used'].add(int(src_port))
                            if dst_port.isdigit():
                                dst_profile['ports_used'].add(int(dst_port))
                    except Exception:
                        pass
                        
            # Update device tree
            self._update_device_tree()
            
            # Update selected device details if needed
            if self.selected_device and self.selected_device in self.device_profiles:
                self._show_device_details(self.selected_device)
                
        except Exception as e:
            logger.error(f"Error updating device profiles: {e}")
            
        finally:
            self.is_updating = False
            
    def _create_device_profile(self, ip_address):
        """Create a new device profile."""
        # Generate a random MAC address for the profile
        # In a real implementation, this would come from the ARP table or packet data
        mac = self._generate_mac_for_ip(ip_address)
        
        # Determine device type based on IP pattern or MAC OUI
        device_type = self._guess_device_type(ip_address, mac)
        
        # Create profile
        return {
            'ip': ip_address,
            'mac': mac,
            'device_type': device_type,
            'packets_sent': 0,
            'packets_received': 0,
            'data_sent': 0,
            'data_received': 0,
            'protocols_used': Counter(),
            'protocols_seen': Counter(),
            'destinations': set(),
            'sources': set(),
            'ports_used': set(),
            'last_seen': time.time()
        }
        
    def _generate_mac_for_ip(self, ip_address):
        """Generate a consistent MAC address for an IP (simulated)."""
        try:
            # Use a hash of the IP to generate a consistent pseudo-MAC
            import hashlib
            hash_obj = hashlib.md5(ip_address.encode())
            hash_digest = hash_obj.hexdigest()
            
            # Use common MAC prefixes for known IP ranges
            if ip_address.startswith('192.168.'):
                # Use common consumer router MAC prefixes
                prefixes = [
                    "00:50:F2",  # Microsoft
                    "00:1A:11",  # Google
                    "00:1D:7E",  # Cisco-Linksys
                    "00:05:5D",  # D-Link
                    "00:23:6C",  # Apple
                ]
                prefix = random.choice(prefixes)
                suffix = hash_digest[:6]
                return f"{prefix}:{suffix[:2]}:{suffix[2:4]}:{suffix[4:6]}"
            elif ip_address.startswith('10.'):
                # Use common enterprise network device MAC prefixes
                prefixes = [
                    "00:00:0C",  # Cisco
                    "00:14:22",  # Dell
                    "00:13:3B",  # Speed Dragon
                    "00:03:47",  # Intel
                ]
                prefix = random.choice(prefixes)
                suffix = hash_digest[:6]
                return f"{prefix}:{suffix[:2]}:{suffix[2:4]}:{suffix[4:6]}"
            elif ip_address == '127.0.0.1':
                # Loopback
                return "00:00:00:00:00:01"
            else:
                # External IP - randomize fully but keep it consistent for the same IP
                mac_parts = [hash_digest[i:i+2] for i in range(0, 12, 2)]
                return ':'.join(mac_parts)
                
        except Exception as e:
            logger.error(f"Error generating MAC address: {e}")
            return "00:00:00:00:00:00"
            
    def _guess_device_type(self, ip_address, mac_address):
        """Guess device type based on IP pattern and MAC OUI."""
        # Check if it's a local IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            if ip_obj.is_loopback:
                return "Loopback"
                
            if ip_obj.is_private:
                # Check MAC prefix against known vendors
                mac_prefix = mac_address[:8].upper()
                
                if mac_prefix in self.mac_vendors:
                    vendor = self.mac_vendors[mac_prefix]
                    
                    if vendor == "Apple":
                        return "Apple Device"
                    elif vendor == "Microsoft":
                        return "Windows PC"
                    elif vendor == "Dell":
                        return "Server"
                    elif "Cisco" in vendor:
                        return "Router"
                    elif "Link" in vendor:
                        return "Router"
                    else:
                        return f"{vendor} Device"
                    
                # Guess based on IP pattern
                if ip_address.startswith('192.168.1.1') or ip_address.endswith('.1'):
                    return "Router"
                elif ip_address.startswith('192.168.') or ip_address.startswith('10.'):
                    return "Local Device"
            else:
                # Public IP - could be external server
                if ip_address.startswith('8.8.8.') or ip_address.startswith('8.8.4.'):
                    return "DNS Server"
                else:
                    return "External Host"
                    
        except Exception:
            pass
            
        return "Unknown Device"
        
    def _update_device_tree(self):
        """Update the device treeview with current device profiles."""
        try:
            # Remember selected device
            selected_items = self.device_tree.selection()
            selected_ip = None
            
            if selected_items:
                item_values = self.device_tree.item(selected_items[0], 'values')
                if item_values:
                    selected_ip = item_values[0]
                    
            # Clear existing items
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
                
            # Add devices sorted by packet count (most active first)
            sorted_devices = sorted(
                self.device_profiles.items(),
                key=lambda x: x[1]['packets_sent'] + x[1]['packets_received'],
                reverse=True
            )
            
            for ip, profile in sorted_devices:
                total_packets = profile['packets_sent'] + profile['packets_received']
                
                # Apply search filter if active
                search_text = self.search_var.get().lower()
                if search_text and not (
                    search_text in ip.lower() or
                    search_text in profile['mac'].lower() or
                    search_text in profile['device_type'].lower()
                ):
                    continue
                    
                # Add device to tree
                item = self.device_tree.insert("", "end", values=(
                    ip,
                    profile['mac'],
                    profile['device_type'],
                    total_packets
                ))
                
                # Restore selection if this was the selected device
                if ip == selected_ip:
                    self.device_tree.selection_set(item)
                    self.device_tree.see(item)
                    
        except Exception as e:
            logger.error(f"Error updating device tree: {e}")
            
    def _on_device_selected(self, event):
        """Handle device selection in the treeview."""
        selection = self.device_tree.selection()
        if not selection:
            return
            
        # Get selected IP
        item = selection[0]
        values = self.device_tree.item(item, "values")
        if not values:
            return
            
        ip = values[0]
        self.selected_device = ip
        
        # Show device details
        self._show_device_details(ip)
        
    def _show_device_details(self, ip):
        """Show details for the selected device."""
        if ip not in self.device_profiles:
            return
            
        profile = self.device_profiles[ip]
        
        # Update metrics
        self.metrics["packets_sent"].config(text=str(profile['packets_sent']))
        self.metrics["packets_received"].config(text=str(profile['packets_received']))
        self.metrics["data_sent"].config(text=self._format_bytes(profile['data_sent']))
        self.metrics["data_received"].config(text=self._format_bytes(profile['data_received']))
        
        # Update details canvas
        self.details_canvas.delete("all")
        
        # Device title
        self.details_canvas.create_text(
            20, 20,
            text=f"Device: {ip} ({profile['device_type']})",
            font=("Arial", 12, "bold"),
            anchor=tk.W
        )
        
        # MAC address
        self.details_canvas.create_text(
            20, 45,
            text=f"MAC: {profile['mac']}",
            font=("Arial", 10),
            anchor=tk.W
        )
        
        # Activity summary
        self.details_canvas.create_text(
            20, 70,
            text=f"Total Activity: {profile['packets_sent'] + profile['packets_received']} packets",
            font=("Arial", 10),
            anchor=tk.W
        )
        
        # Connection information
        y_pos = 95
        
        if profile['destinations']:
            self.details_canvas.create_text(
                20, y_pos,
                text=f"Connected to {len(profile['destinations'])} devices",
                font=("Arial", 10),
                anchor=tk.W
            )
            y_pos += 20
            
        # Protocol information
        if profile['protocols_used']:
            # Show top protocols
            protocols_str = ", ".join([f"{p} ({c})" for p, c in profile['protocols_used'].most_common(3)])
            self.details_canvas.create_text(
                20, y_pos,
                text=f"Top Protocols: {protocols_str}",
                font=("Arial", 10),
                anchor=tk.W
            )
            y_pos += 20
            
        # Port information
        if profile['ports_used']:
            # Show top ports
            top_ports = list(sorted(profile['ports_used']))[:5]
            ports_str = ", ".join([str(p) for p in top_ports])
            self.details_canvas.create_text(
                20, y_pos,
                text=f"Ports: {ports_str}" + ("..." if len(profile['ports_used']) > 5 else ""),
                font=("Arial", 10),
                anchor=tk.W
            )
            
        # Update traffic chart
        self._update_traffic_chart(profile)
        
    def _update_traffic_chart(self, profile):
        """Update traffic chart for the selected device."""
        try:
            # Clear the plot
            self.traffic_ax.clear()
            
            # Prepare data for the chart
            protocols_sent = profile['protocols_used']
            protocols_received = profile['protocols_seen']
            
            # Get set of all protocols
            all_protocols = set(protocols_sent.keys()) | set(protocols_received.keys())
            
            if not all_protocols:
                self.traffic_ax.set_title(f"No Protocol Data for {profile['ip']}")
                self.traffic_ax.text(
                    0.5, 0.5, 
                    "No protocol data available", 
                    horizontalalignment='center',
                    verticalalignment='center',
                    transform=self.traffic_ax.transAxes
                )
                self.traffic_canvas.draw_idle()
                return
                
            # Prepare data for plotting
            protocol_labels = list(all_protocols)
            sent_counts = [protocols_sent[p] for p in protocol_labels]
            received_counts = [protocols_received[p] for p in protocol_labels]
            
            # Set position indices for the bars
            x = range(len(protocol_labels))
            width = 0.35
            
            # Create the bar chart
            self.traffic_ax.bar([i - width/2 for i in x], sent_counts, width, label='Sent')
            self.traffic_ax.bar([i + width/2 for i in x], received_counts, width, label='Received')
            
            # Set labels and title
            self.traffic_ax.set_title(f"Protocol Traffic for {profile['ip']}")
            self.traffic_ax.set_xlabel('Protocol')
            self.traffic_ax.set_ylabel('Packet Count')
            self.traffic_ax.set_xticks(x)
            self.traffic_ax.set_xticklabels(protocol_labels)
            self.traffic_ax.legend()
            
            # Make sure layout is good
            self.traffic_fig.tight_layout()
            
            # Update canvas
            self.traffic_canvas.draw_idle()
            
        except Exception as e:
            logger.error(f"Error updating traffic chart: {e}")
            
    def _filter_devices(self, *args):
        """Filter devices based on search text."""
        if not self.is_updating:
            self._update_device_tree()
            
    def refresh_devices(self):
        """Manually refresh the device list."""
        if not self.is_updating and self.packet_data:
            threading.Thread(target=self._update_device_profiles, daemon=True).start()
            
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
