"""
Device Dashboard - Network device discovery and profiling
"""

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import random
import time
import threading
from PIL import Image, ImageTk, ImageDraw
import io
import math
import colorsys

class DeviceDashboard:
    """Dashboard for device discovery and profiling."""
    
    def __init__(self, parent, packet_capture):
        """Initialize the device dashboard."""
        self.parent = parent
        self.packet_capture = packet_capture
        self.running = True
        self.last_update = time.time()
        self.update_interval = 3.0  # Update every 3 seconds
        
        # Device tracking
        self.devices = {}  # IP -> device info
        self.connections = []  # (src, dst, protocol, count)
        
        # Create GUI
        self.create_dashboard()
        
        # Start update thread
        self.update_thread = threading.Thread(target=self.update_thread, daemon=True)
        self.update_thread.start()
        
    def create_dashboard(self):
        """Create the dashboard GUI."""
        # Main frame
        self.frame = ttk.Frame(self.parent, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Split into left panel (network map) and right panel (device details)
        self.paned_window = ttk.PanedWindow(self.frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Create network map visualization
        self.create_network_map()
        
        # Create device details panel
        self.create_device_details()
        
    def create_network_map(self):
        """Create network map visualization."""
        map_frame = ttk.LabelFrame(self.paned_window, text="Network Map", padding=10)
        self.paned_window.add(map_frame, weight=3)
        
        # Controls above the map
        controls_frame = ttk.Frame(map_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # View selector
        ttk.Label(controls_frame, text="View:").pack(side=tk.LEFT, padx=(0, 5))
        self.view_var = tk.StringVar(value="All Devices")
        view_combo = ttk.Combobox(
            controls_frame, 
            textvariable=self.view_var,
            values=["All Devices", "Active Only", "By Category"],
            state="readonly",
            width=15
        )
        view_combo.pack(side=tk.LEFT, padx=(0, 10))
        view_combo.bind("<<ComboboxSelected>>", lambda e: self.update_network_map())
        
        # Layout selector
        ttk.Label(controls_frame, text="Layout:").pack(side=tk.LEFT, padx=(0, 5))
        self.layout_var = tk.StringVar(value="Network")
        layout_combo = ttk.Combobox(
            controls_frame, 
            textvariable=self.layout_var,
            values=["Network", "Radial", "Grid"],
            state="readonly",
            width=10
        )
        layout_combo.pack(side=tk.LEFT, padx=(0, 10))
        layout_combo.bind("<<ComboboxSelected>>", lambda e: self.update_network_map())
        
        # Refresh button
        refresh_button = ttk.Button(
            controls_frame,
            text="Refresh Map",
            command=self.update_network_map
        )
        refresh_button.pack(side=tk.RIGHT)
        
        # Create canvas for network map
        self.map_canvas = tk.Canvas(map_frame, bg="white", highlightthickness=0)
        self.map_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Bind events for canvas interaction
        self.map_canvas.bind("<Motion>", self.on_map_motion)
        self.map_canvas.bind("<Button-1>", self.on_map_click)
        
        # Status bar below the map
        self.status_var = tk.StringVar(value="Discovering devices...")
        status_label = ttk.Label(map_frame, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(fill=tk.X, pady=(10, 0))
        
    def create_device_details(self):
        """Create device details panel."""
        details_frame = ttk.LabelFrame(self.paned_window, text="Device Details", padding=10)
        self.paned_window.add(details_frame, weight=2)
        
        # Device selector
        selector_frame = ttk.Frame(details_frame)
        selector_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(selector_frame, text="Select Device:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(
            selector_frame, 
            textvariable=self.device_var,
            state="readonly",
            width=25
        )
        self.device_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.device_combo.bind("<<ComboboxSelected>>", self.on_device_selected)
        
        # Details panel with tabs
        self.details_notebook = ttk.Notebook(details_frame)
        self.details_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Overview tab
        self.overview_frame = ttk.Frame(self.details_notebook, padding=10)
        self.details_notebook.add(self.overview_frame, text="Overview")
        
        # Traffic tab
        self.traffic_frame = ttk.Frame(self.details_notebook, padding=10)
        self.details_notebook.add(self.traffic_frame, text="Traffic")
        
        # Connections tab
        self.connections_frame = ttk.Frame(self.details_notebook, padding=10)
        self.details_notebook.add(self.connections_frame, text="Connections")
        
        # Create initial empty content
        self.create_empty_device_details()
        
    def create_empty_device_details(self):
        """Create empty device details panels."""
        # Clear overview frame
        for widget in self.overview_frame.winfo_children():
            widget.destroy()
            
        # Add placeholder text
        ttk.Label(
            self.overview_frame,
            text="Select a device from the network map or dropdown to view details",
            wraplength=300,
            justify="center"
        ).pack(expand=True)
        
        # Clear traffic frame
        for widget in self.traffic_frame.winfo_children():
            widget.destroy()
            
        # Add placeholder for traffic
        ttk.Label(
            self.traffic_frame,
            text="Traffic information will appear here when a device is selected",
            wraplength=300,
            justify="center"
        ).pack(expand=True)
        
        # Clear connections frame
        for widget in self.connections_frame.winfo_children():
            widget.destroy()
            
        # Add placeholder for connections
        ttk.Label(
            self.connections_frame,
            text="Connection details will appear here when a device is selected",
            wraplength=300,
            justify="center"
        ).pack(expand=True)
        
    def update_thread(self):
        """Background thread to update device data periodically."""
        while self.running:
            time.sleep(0.1)  # Short sleep to prevent high CPU usage
            
            current_time = time.time()
            if current_time - self.last_update >= self.update_interval:
                self.last_update = current_time
                
                # Process packet data and update device information
                self.update_device_data()
                
                # Update the UI
                self.parent.after(0, self.update_ui)
                
    def update_device_data(self):
        """Update device data from captured packets."""
        packets = self.packet_capture.packets
        
        if not packets:
            return
        
        # Process packets to extract device information
        for packet in packets:
            if hasattr(packet, 'haslayer') and packet.haslayer('IP'):
                # Extract source device info
                src_ip = packet['IP'].src
                if src_ip not in self.devices:
                    self.devices[src_ip] = self._create_device_record(src_ip)
                    
                # Update source device info
                device = self.devices[src_ip]
                device['packet_count'] += 1
                device['last_seen'] = time.time()
                device['bytes_sent'] += len(packet)
                
                # Extract protocol info
                if packet.haslayer('TCP'):
                    device['protocols']['TCP'] = device['protocols'].get('TCP', 0) + 1
                    device['ports_used'].add(packet['TCP'].sport)
                elif packet.haslayer('UDP'):
                    device['protocols']['UDP'] = device['protocols'].get('UDP', 0) + 1
                    device['ports_used'].add(packet['UDP'].sport)
                elif packet.haslayer('ICMP'):
                    device['protocols']['ICMP'] = device['protocols'].get('ICMP', 0) + 1
                
                # Extract destination device info
                dst_ip = packet['IP'].dst
                if dst_ip not in self.devices:
                    self.devices[dst_ip] = self._create_device_record(dst_ip)
                    
                # Update destination device info
                dst_device = self.devices[dst_ip]
                dst_device['packet_count'] += 1
                dst_device['last_seen'] = time.time()
                dst_device['bytes_received'] += len(packet)
                
                # Determine protocol for connection
                protocol = "Other"
                if packet.haslayer('TCP'):
                    protocol = "TCP"
                elif packet.haslayer('UDP'):
                    protocol = "UDP"
                elif packet.haslayer('ICMP'):
                    protocol = "ICMP"
                
                # Update connections
                conn_key = (src_ip, dst_ip, protocol)
                existing_conn = None
                for conn in self.connections:
                    if conn[0] == src_ip and conn[1] == dst_ip and conn[2] == protocol:
                        existing_conn = conn
                        break
                        
                if existing_conn:
                    existing_conn[3] += 1  # Increment count
                else:
                    self.connections.append([src_ip, dst_ip, protocol, 1])
        
        # Update device categories based on behavior
        for ip, device in self.devices.items():
            self._update_device_category(device)
            
    def update_ui(self):
        """Update the UI with new device data."""
        if not self.running:
            return
            
        # Update device dropdown
        devices = sorted(self.devices.keys())
        self.device_combo['values'] = devices
        
        # Update network map
        self.update_network_map()
        
        # Update device details if a device is selected
        if self.device_var.get():
            self.display_device_details(self.device_var.get())
            
        # Update status
        active_count = sum(1 for d in self.devices.values() if time.time() - d['last_seen'] < 60)
        self.status_var.set(f"Discovered {len(self.devices)} devices ({active_count} active in last minute)")
        
    def update_network_map(self):
        """Update the network map visualization."""
        # Clear canvas
        self.map_canvas.delete("all")
        
        if not self.devices:
            # No devices yet, show placeholder
            self.map_canvas.create_text(
                self.map_canvas.winfo_width() / 2,
                self.map_canvas.winfo_height() / 2,
                text="Waiting for device discovery...",
                font=("Segoe UI", 12),
                fill="#999999"
            )
            return
            
        # Determine which devices to show based on view setting
        view_mode = self.view_var.get()
        devices_to_show = {}
        
        if view_mode == "Active Only":
            # Show only devices active in the last minute
            for ip, device in self.devices.items():
                if time.time() - device['last_seen'] < 60:
                    devices_to_show[ip] = device
        elif view_mode == "By Category":
            # Group by category
            devices_to_show = self.devices
        else:
            # Show all devices
            devices_to_show = self.devices
            
        # Get canvas dimensions
        canvas_width = self.map_canvas.winfo_width() or 400  # Default if not yet drawn
        canvas_height = self.map_canvas.winfo_height() or 300
        
        # Determine layout
        layout_mode = self.layout_var.get()
        
        if layout_mode == "Network":
            # Network-style layout with router in center
            self._draw_network_layout(devices_to_show, canvas_width, canvas_height)
        elif layout_mode == "Radial":
            # Radial layout
            self._draw_radial_layout(devices_to_show, canvas_width, canvas_height)
        else:
            # Grid layout
            self._draw_grid_layout(devices_to_show, canvas_width, canvas_height)
            
    def _draw_network_layout(self, devices, width, height):
        """Draw devices in a network-style layout with router in center."""
        # Find router or gateway
        router_ip = None
        for ip, device in devices.items():
            if device['category'] == 'Router' or device['category'] == 'Gateway' or ip.endswith('.1'):
                router_ip = ip
                break
                
        if not router_ip and devices:
            # If no router found, use first device
            router_ip = list(devices.keys())[0]
            
        # If we still don't have a device, return
        if not router_ip:
            return
            
        # Position devices
        device_positions = {}
        
        # Position router in center
        center_x = width / 2
        center_y = height / 2
        device_positions[router_ip] = (center_x, center_y)
        
        # Categorize remaining devices
        categorized_devices = {}
        for ip, device in devices.items():
            if ip == router_ip:
                continue
                
            category = device['category']
            if category not in categorized_devices:
                categorized_devices[category] = []
                
            categorized_devices[category].append((ip, device))
            
        # Position devices by category in segments around the center
        num_categories = len(categorized_devices)
        if num_categories == 0:
            # Only router
            self._draw_device_node(router_ip, devices[router_ip], center_x, center_y)
            return
            
        # Calculate the segment angle
        segment_angle = 2 * math.pi / num_categories
        
        # Draw connection lines first so they're behind the nodes
        self._draw_connection_lines(device_positions, router_ip, center_x, center_y)
        
        # Draw router node
        self._draw_device_node(router_ip, devices[router_ip], center_x, center_y)
        
        # Position and draw devices in each category
        for i, (category, category_devices) in enumerate(categorized_devices.items()):
            # Calculate base angle for this category
            base_angle = i * segment_angle
            
            # Position each device in the category
            num_devices = len(category_devices)
            for j, (ip, device) in enumerate(category_devices):
                # Calculate radius based on device's packet count (more active = closer to center)
                packet_count = device['packet_count']
                base_radius = min(width, height) * 0.4  # Base distance from center
                radius = base_radius - (min(packet_count, 1000) / 1000) * (base_radius * 0.2)
                
                # Calculate position on the circle
                device_angle = base_angle + (j / max(1, num_devices - 1)) * segment_angle * 0.8
                x = center_x + radius * math.cos(device_angle)
                y = center_y + radius * math.sin(device_angle)
                
                # Store position
                device_positions[ip] = (x, y)
                
                # Draw device node
                self._draw_device_node(ip, device, x, y)
                
        # Draw connections between devices
        self._draw_device_connections(device_positions)
        
    def _draw_radial_layout(self, devices, width, height):
        """Draw devices in a radial layout."""
        # Sort devices by packet count
        sorted_devices = sorted(devices.items(), key=lambda x: x[1]['packet_count'], reverse=True)
        
        # Position devices
        device_positions = {}
        
        # Position most active device in center
        center_x = width / 2
        center_y = height / 2
        
        if not sorted_devices:
            return
            
        # Position devices in a spiral pattern
        center_ip, center_device = sorted_devices[0]
        device_positions[center_ip] = (center_x, center_y)
        
        # Draw the center node
        self._draw_device_node(center_ip, center_device, center_x, center_y)
        
        # Position remaining devices in a spiral
        if len(sorted_devices) > 1:
            max_radius = min(width, height) * 0.4
            spiral_spacing = max_radius / len(sorted_devices)
            
            for i, (ip, device) in enumerate(sorted_devices[1:], 1):
                # Calculate spiral position
                theta = i * math.pi / 4  # Angle increment
                radius = spiral_spacing * math.sqrt(i)
                
                # Calculate position
                x = center_x + radius * math.cos(theta)
                y = center_y + radius * math.sin(theta)
                
                # Store position
                device_positions[ip] = (x, y)
                
                # Draw device node
                self._draw_device_node(ip, device, x, y)
        
        # Draw connections between devices
        self._draw_device_connections(device_positions)
        
    def _draw_grid_layout(self, devices, width, height):
        """Draw devices in a grid layout."""
        # Group devices by category
        categorized_devices = {}
        for ip, device in devices.items():
            category = device['category']
            if category not in categorized_devices:
                categorized_devices[category] = []
                
            categorized_devices[category].append((ip, device))
            
        # Position devices
        device_positions = {}
        
        # Calculate grid parameters
        num_categories = len(categorized_devices)
        if num_categories == 0:
            return
            
        # Determine grid layout
        grid_rows = math.ceil(math.sqrt(num_categories))
        grid_cols = math.ceil(num_categories / grid_rows)
        
        # Calculate cell size
        cell_width = width / grid_cols
        cell_height = height / grid_rows
        
        # Position and draw devices by category
        for i, (category, category_devices) in enumerate(categorized_devices.items()):
            # Calculate grid position for this category
            row = i // grid_cols
            col = i % grid_cols
            
            # Calculate center of the cell
            cell_center_x = col * cell_width + cell_width / 2
            cell_center_y = row * cell_height + cell_height / 2
            
            # Draw category label
            self.map_canvas.create_text(
                cell_center_x,
                cell_center_y - cell_height * 0.4,
                text=category,
                font=("Segoe UI", 10, "bold"),
                fill="#555555"
            )
            
            # Position devices in a grid within the cell
            num_devices = len(category_devices)
            devices_per_row = math.ceil(math.sqrt(num_devices))
            device_grid_width = cell_width * 0.8
            device_grid_height = cell_height * 0.6
            
            # Calculate device spacing
            device_spacing_x = device_grid_width / max(1, devices_per_row)
            device_spacing_y = device_grid_height / max(1, math.ceil(num_devices / devices_per_row))
            
            # Draw each device in the category
            for j, (ip, device) in enumerate(category_devices):
                # Calculate grid position
                device_row = j // devices_per_row
                device_col = j % devices_per_row
                
                # Calculate position
                x = cell_center_x - device_grid_width / 2 + device_col * device_spacing_x + device_spacing_x / 2
                y = cell_center_y - device_grid_height / 4 + device_row * device_spacing_y + device_spacing_y / 2
                
                # Store position
                device_positions[ip] = (x, y)
                
                # Draw device node
                self._draw_device_node(ip, device, x, y)
        
        # Draw connections between devices if there's room
        if cell_width > 100 and cell_height > 100:
            self._draw_device_connections(device_positions, alpha=0.5)
            
    def _draw_device_node(self, ip, device, x, y):
        """Draw a single device node on the map."""
        # Choose icon based on device category
        category = device['category']
        
        # Determine node size based on packet count (more packets = larger node)
        base_size = 24
        packet_count = device['packet_count']
        size_factor = min(1.0 + (math.log(packet_count + 1) / 10), 2.0)
        node_size = int(base_size * size_factor)
        
        # Choose color based on category
        colors = {
            'Client': "#3498db",
            'Server': "#2ecc71",
            'Router': "#e74c3c",
            'Gateway': "#f39c12",
            'Mobile': "#9b59b6",
            'IoT': "#1abc9c",
            'Unknown': "#95a5a6"
        }
        
        color = colors.get(category, "#95a5a6")
        
        # Draw node
        node_id = self.map_canvas.create_oval(
            x - node_size/2, y - node_size/2,
            x + node_size/2, y + node_size/2,
            fill=color,
            outline="#ffffff",
            width=2,
            tags=("node", f"ip:{ip}")
        )
        
        # Draw IP label below the node
        label_id = self.map_canvas.create_text(
            x, y + node_size/2 + 12,
            text=ip,
            font=("Segoe UI", 8),
            fill="#333333",
            tags=("label", f"ip:{ip}")
        )
        
        # Draw icon in the center based on category
        icon_text = "💻"  # Default icon
        
        if category == "Server":
            icon_text = "🖥️"
        elif category == "Router" or category == "Gateway":
            icon_text = "🌐"
        elif category == "Mobile":
            icon_text = "📱"
        elif category == "IoT":
            icon_text = "🔌"
            
        icon_id = self.map_canvas.create_text(
            x, y,
            text=icon_text,
            font=("Segoe UI", 12),
            fill="#ffffff",
            tags=("icon", f"ip:{ip}")
        )
        
        # Draw activity indicator (pulsing effect for recently active devices)
        if time.time() - device['last_seen'] < 10:  # Active in the last 10 seconds
            pulse_size = node_size * 1.5
            pulse_id = self.map_canvas.create_oval(
                x - pulse_size/2, y - pulse_size/2,
                x + pulse_size/2, y + pulse_size/2,
                outline=color,
                width=2,
                tags=("pulse", f"ip:{ip}")
            )
            
            # Animate pulse
            self._animate_pulse(pulse_id, x, y, node_size)
            
    def _animate_pulse(self, pulse_id, x, y, base_size):
        """Animate a pulse effect around an active node."""
        if not self.running:
            return
            
        # Get current size
        coords = self.map_canvas.coords(pulse_id)
        if not coords or len(coords) != 4:
            return
            
        current_width = coords[2] - coords[0]
        max_size = base_size * 2
        
        if current_width < max_size:
            # Expand pulse
            new_size = current_width + 1
            self.map_canvas.coords(
                pulse_id,
                x - new_size/2, y - new_size/2,
                x + new_size/2, y + new_size/2
            )
            
            # Reduce opacity as it expands
            opacity = int(255 * (1 - (new_size - base_size) / (max_size - base_size)))
            new_color = f"#{opacity:02x}{opacity:02x}{opacity:02x}"
            self.map_canvas.itemconfig(pulse_id, outline=new_color)
            
            # Continue animation
            self.parent.after(50, lambda: self._animate_pulse(pulse_id, x, y, base_size))
        else:
            # Remove pulse when done
            self.map_canvas.delete(pulse_id)
            
    def _draw_connection_lines(self, device_positions, center_ip, center_x, center_y):
        """Draw lines from center device to all others."""
        for ip, (x, y) in device_positions.items():
            if ip != center_ip:
                # Draw a line from center to this device
                line_id = self.map_canvas.create_line(
                    center_x, center_y, x, y,
                    fill="#dddddd",
                    width=1,
                    dash=(4, 4),
                    tags=("connection", f"from:{center_ip}", f"to:{ip}")
                )
    
    def _draw_device_connections(self, device_positions, alpha=1.0):
        """Draw connections between devices based on captured traffic."""
        # Sort connections by count to draw the most active ones
        sorted_connections = sorted(self.connections, key=lambda x: x[3], reverse=True)
        max_connections = 25  # Limit to avoid cluttering
        
        # Calculate color alpha based on connection count
        max_count = sorted_connections[0][3] if sorted_connections else 1
        
        for src_ip, dst_ip, protocol, count in sorted_connections[:max_connections]:
            if src_ip in device_positions and dst_ip in device_positions:
                src_x, src_y = device_positions[src_ip]
                dst_x, dst_y = device_positions[dst_ip]
                
                # Calculate line width based on count (more traffic = thicker line)
                width = 1 + min(count / max_count * 3, 3)
                
                # Choose color based on protocol
                if protocol == "TCP":
                    color = "#3498db"
                elif protocol == "UDP":
                    color = "#2ecc71"
                elif protocol == "ICMP":
                    color = "#e74c3c"
                else:
                    color = "#95a5a6"
                    
                # Apply alpha
                if alpha < 1.0:
                    # Convert to RGB and apply alpha
                    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
                    a = int(255 * alpha)
                    color = f"#{r:02x}{g:02x}{b:02x}{a:02x}"
                
                # Draw the connection line
                line_id = self.map_canvas.create_line(
                    src_x, src_y, dst_x, dst_y,
                    fill=color,
                    width=width,
                    arrow=tk.LAST,
                    arrowshape=(8, 10, 3),
                    tags=("traffic", f"from:{src_ip}", f"to:{dst_ip}", f"protocol:{protocol}")
                )
                
                # Add traffic animation for busy connections
                if count > 10:
                    self._animate_traffic(line_id, src_x, src_y, dst_x, dst_y, color)
    
    def _animate_traffic(self, line_id, src_x, src_y, dst_x, dst_y, color):
        """Animate traffic flowing along a connection line."""
        if not self.running:
            return
            
        # Create a small circle to represent a packet
        packet_size = 4
        packet_id = self.map_canvas.create_oval(
            src_x - packet_size/2, src_y - packet_size/2,
            src_x + packet_size/2, src_y + packet_size/2,
            fill=color,
            outline="",
            tags=("packet")
        )
        
        # Animate the packet traveling along the line
        self._animate_packet(packet_id, src_x, src_y, dst_x, dst_y, 0, 20)
    
    def _animate_packet(self, packet_id, src_x, src_y, dst_x, dst_y, step, total_steps):
        """Animate a packet moving along a line."""
        if not self.running:
            return
            
        # Calculate position along the line
        t = step / total_steps
        x = src_x + (dst_x - src_x) * t
        y = src_y + (dst_y - src_y) * t
        
        # Update packet position
        packet_size = 4
        self.map_canvas.coords(
            packet_id,
            x - packet_size/2, y - packet_size/2,
            x + packet_size/2, y + packet_size/2
        )
        
        if step < total_steps:
            # Continue animation
            self.parent.after(50, lambda: self._animate_packet(packet_id, src_x, src_y, dst_x, dst_y, step + 1, total_steps))
        else:
            # Remove packet when done
            self.map_canvas.delete(packet_id)
    
    def on_map_motion(self, event):
        """Handle mouse motion over the map."""
        # Find item under mouse
        item = self.map_canvas.find_withtag("current")
        if item:
            tags = self.map_canvas.gettags(item)
            
            # Check if the item is a node or part of a node
            ip = None
            for tag in tags:
                if tag.startswith("ip:"):
                    ip = tag[3:]
                    
            if ip and ip in self.devices:
                # Show device info as a tooltip
                device = self.devices[ip]
                info = f"{ip}\n{device['category']}\nPackets: {device['packet_count']}"
                
                # Show tooltip near cursor
                self._show_map_tooltip(event.x, event.y, info)
            else:
                # Hide tooltip if not over a device
                self._hide_map_tooltip()
        else:
            # Hide tooltip if not over any item
            self._hide_map_tooltip()
    
    def _show_map_tooltip(self, x, y, text):
        """Show a tooltip on the map."""
        # Hide any existing tooltip
        self._hide_map_tooltip()
        
        # Create tooltip
        padding = 5
        tooltip_bg = "#ffffcc"
        tooltip_border = "#999999"
        
        # Background
        tooltip_id = self.map_canvas.create_rectangle(
            x + 10, y + 10,
            x + 160, y + 70,
            fill=tooltip_bg,
            outline=tooltip_border,
            tags=("tooltip")
        )
        
        # Text
        text_id = self.map_canvas.create_text(
            x + 15, y + 15,
            text=text,
            font=("Segoe UI", 9),
            fill="#333333",
            anchor=tk.NW,
            tags=("tooltip")
        )
    
    def _hide_map_tooltip(self):
        """Hide the map tooltip."""
        self.map_canvas.delete("tooltip")
    
    def on_map_click(self, event):
        """Handle mouse click on the map."""
        # Find item under mouse
        item = self.map_canvas.find_withtag("current")
        if item:
            tags = self.map_canvas.gettags(item)
            
            # Check if the item is a node or part of a node
            ip = None
            for tag in tags:
                if tag.startswith("ip:"):
                    ip = tag[3:]
                    
            if ip and ip in self.devices:
                # Select the device
                self.device_var.set(ip)
                self.display_device_details(ip)
    
    def on_device_selected(self, event):
        """Handle device selection from dropdown."""
        ip = self.device_var.get()
        if ip in self.devices:
            self.display_device_details(ip)
    
    def display_device_details(self, ip):
        """Display details for the selected device."""
        if ip not in self.devices:
            return
            
        device = self.devices[ip]
        
        # Update overview tab
        self._update_overview_tab(ip, device)
        
        # Update traffic tab
        self._update_traffic_tab(ip, device)
        
        # Update connections tab
        self._update_connections_tab(ip, device)
    
    def _update_overview_tab(self, ip, device):
        """Update the overview tab with device information."""
        # Clear overview frame
        for widget in self.overview_frame.winfo_children():
            widget.destroy()
            
        # Create scrollable frame for overview
        canvas = tk.Canvas(self.overview_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.overview_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Device header
        header_frame = ttk.Frame(scrollable_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Icon based on category
        category = device['category']
        icon_text = "💻"  # Default icon
        
        if category == "Server":
            icon_text = "🖥️"
        elif category == "Router" or category == "Gateway":
            icon_text = "🌐"
        elif category == "Mobile":
            icon_text = "📱"
        elif category == "IoT":
            icon_text = "🔌"
            
        ttk.Label(
            header_frame,
            text=icon_text,
            font=("Segoe UI", 24)
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        # IP and category
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.LEFT)
        
        ttk.Label(
            info_frame,
            text=ip,
            font=("Segoe UI", 14, "bold")
        ).pack(anchor=tk.W)
        
        ttk.Label(
            info_frame,
            text=category,
            font=("Segoe UI", 12)
        ).pack(anchor=tk.W)
        
        # Details section
        details_frame = ttk.LabelFrame(scrollable_frame, text="Device Details", padding=10)
        details_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create grid of details
        details = [
            ("First Seen", time.strftime("%H:%M:%S", time.localtime(device['first_seen']))),
            ("Last Seen", time.strftime("%H:%M:%S", time.localtime(device['last_seen']))),
            ("Packet Count", str(device['packet_count'])),
            ("Bytes Sent", self._format_bytes(device['bytes_sent'])),
            ("Bytes Received", self._format_bytes(device['bytes_received'])),
            ("Protocols Used", ", ".join(device['protocols'].keys())),
            ("Ports Used", ", ".join(str(p) for p in sorted(list(device['ports_used']))[:5]) + 
                           ("..." if len(device['ports_used']) > 5 else ""))
        ]
        
        # Add details to grid
        for i, (label, value) in enumerate(details):
            ttk.Label(
                details_frame,
                text=label + ":",
                font=("Segoe UI", 10, "bold"),
                width=15,
                anchor=tk.W
            ).grid(row=i, column=0, sticky=tk.W, pady=2)
            
            ttk.Label(
                details_frame,
                text=value,
                font=("Segoe UI", 10)
            ).grid(row=i, column=1, sticky=tk.W, pady=2)
            
        # Activity status
        if time.time() - device['last_seen'] < 30:
            status_color = "#2ecc71"  # Green
            status_text = "Active"
        elif time.time() - device['last_seen'] < 300:
            status_color = "#f39c12"  # Orange
            status_text = "Recently Active"
        else:
            status_color = "#95a5a6"  # Gray
            status_text = "Inactive"
            
        status_frame = ttk.Frame(scrollable_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            status_frame,
            text="Status:",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT)
        
        status_label = ttk.Label(
            status_frame,
            text=status_text,
            font=("Segoe UI", 10)
        )
        status_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Can't set label color in ttk, so use a colored indicator
        indicator = ttk.Label(
            status_frame,
            text="●",
            font=("Segoe UI", 10),
            foreground=status_color
        )
        indicator.pack(side=tk.LEFT, padx=(5, 0))
    
    def _update_traffic_tab(self, ip, device):
        """Update the traffic tab with traffic charts."""
        # Clear traffic frame
        for widget in self.traffic_frame.winfo_children():
            widget.destroy()
            
        # Bytes sent/received chart
        bytes_frame = ttk.LabelFrame(self.traffic_frame, text="Data Transfer", padding=10)
        bytes_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create bytes chart
        bytes_fig = Figure(figsize=(5, 2), dpi=100)
        bytes_ax = bytes_fig.add_subplot(111)
        
        labels = ['Sent', 'Received']
        sizes = [device['bytes_sent'], device['bytes_received']]
        
        if sum(sizes) > 0:
            # Create bar chart
            bars = bytes_ax.bar(labels, sizes, color=['#3498db', '#2ecc71'])
            
            # Add data labels
            for bar in bars:
                height = bar.get_height()
                bytes_ax.annotate(
                    self._format_bytes(height),
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=8
                )
                
            # Format graph
            bytes_ax.set_title("Data Transfer")
            bytes_ax.set_ylabel("Bytes")
            bytes_fig.tight_layout()
        else:
            # No data
            bytes_ax.text(0.5, 0.5, "No traffic data available", 
                ha='center', va='center', fontsize=12, color='gray')
            bytes_ax.axis('off')
            
        # Create canvas for bytes chart
        bytes_canvas = FigureCanvasTkAgg(bytes_fig, master=bytes_frame)
        bytes_canvas.draw()
        bytes_canvas.get_tk_widget().pack(fill=tk.X)
        
        # Protocol distribution chart
        if device['protocols']:
            proto_frame = ttk.LabelFrame(self.traffic_frame, text="Protocol Distribution", padding=10)
            proto_frame.pack(fill=tk.X, pady=(0, 10))
            
            # Create protocol chart
            proto_fig = Figure(figsize=(5, 3), dpi=100)
            proto_ax = proto_fig.add_subplot(111)
            
            # Get protocol data
            proto_labels = list(device['protocols'].keys())
            proto_sizes = list(device['protocols'].values())
            
            # Define colors
            proto_colors = {
                'TCP': '#3498db',
                'UDP': '#2ecc71',
                'ICMP': '#e74c3c',
                'HTTP': '#9b59b6',
                'HTTPS': '#1abc9c',
                'DNS': '#f39c12'
            }
            
            # Get colors for the protocols in the data
            colors = [proto_colors.get(label, '#95a5a6') for label in proto_labels]
            
            # Create pie chart
            wedges, texts, autotexts = proto_ax.pie(
                proto_sizes, 
                labels=proto_labels, 
                autopct='%1.1f%%',
                startangle=90,
                colors=colors,
                explode=[0.05] * len(proto_labels)  # Explode all slices
            )
            
            # Style the text and autotext
            for text in texts:
                text.set_fontsize(10)
            for autotext in autotexts:
                autotext.set_fontsize(9)
                autotext.set_fontweight('bold')
                autotext.set_color('white')
                
            # Equal aspect ratio ensures that pie is drawn as a circle
            proto_ax.axis('equal')
            proto_fig.tight_layout()
            
            # Create canvas for protocol chart
            proto_canvas = FigureCanvasTkAgg(proto_fig, master=proto_frame)
            proto_canvas.draw()
            proto_canvas.get_tk_widget().pack(fill=tk.X)
    
    def _update_connections_tab(self, ip, device):
        """Update the connections tab with connection information."""
        # Clear connections frame
        for widget in self.connections_frame.winfo_children():
            widget.destroy()
            
        # Get connections involving this IP
        incoming = []
        outgoing = []
        
        for src, dst, protocol, count in self.connections:
            if dst == ip:
                incoming.append((src, protocol, count))
            elif src == ip:
                outgoing.append((dst, protocol, count))
                
        # Sort connections by count
        incoming.sort(key=lambda x: x[2], reverse=True)
        outgoing.sort(key=lambda x: x[2], reverse=True)
        
        # Create tabs for incoming/outgoing
        conn_notebook = ttk.Notebook(self.connections_frame)
        conn_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Incoming connections tab
        incoming_frame = ttk.Frame(conn_notebook, padding=10)
        conn_notebook.add(incoming_frame, text="Incoming Connections")
        
        # Create treeview for incoming connections
        if incoming:
            in_tree = ttk.Treeview(
                incoming_frame,
                columns=("Source", "Protocol", "Packets"),
                show="headings",
                height=8
            )
            
            # Configure columns
            in_tree.heading("Source", text="Source IP")
            in_tree.heading("Protocol", text="Protocol")
            in_tree.heading("Packets", text="Packet Count")
            
            in_tree.column("Source", width=150)
            in_tree.column("Protocol", width=80)
            in_tree.column("Packets", width=80)
            
            # Add scrollbar
            in_scrollbar = ttk.Scrollbar(incoming_frame, orient="vertical", command=in_tree.yview)
            in_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            in_tree.configure(yscrollcommand=in_scrollbar.set)
            
            in_tree.pack(fill=tk.BOTH, expand=True)
            
            # Add data to tree
            for src, protocol, count in incoming:
                in_tree.insert("", "end", values=(src, protocol, count))
        else:
            # No incoming connections
            ttk.Label(
                incoming_frame,
                text="No incoming connections",
                font=("Segoe UI", 10),
                foreground="#999999"
            ).pack(pady=20)
        
        # Outgoing connections tab
        outgoing_frame = ttk.Frame(conn_notebook, padding=10)
        conn_notebook.add(outgoing_frame, text="Outgoing Connections")
        
        # Create treeview for outgoing connections
        if outgoing:
            out_tree = ttk.Treeview(
                outgoing_frame,
                columns=("Destination", "Protocol", "Packets"),
                show="headings",
                height=8
            )
            
            # Configure columns
            out_tree.heading("Destination", text="Destination IP")
            out_tree.heading("Protocol", text="Protocol")
            out_tree.heading("Packets", text="Packet Count")
            
            out_tree.column("Destination", width=150)
            out_tree.column("Protocol", width=80)
            out_tree.column("Packets", width=80)
            
            # Add scrollbar
            out_scrollbar = ttk.Scrollbar(outgoing_frame, orient="vertical", command=out_tree.yview)
            out_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            out_tree.configure(yscrollcommand=out_scrollbar.set)
            
            out_tree.pack(fill=tk.BOTH, expand=True)
            
            # Add data to tree
            for dst, protocol, count in outgoing:
                out_tree.insert("", "end", values=(dst, protocol, count))
        else:
            # No outgoing connections
            ttk.Label(
                outgoing_frame,
                text="No outgoing connections",
                font=("Segoe UI", 10),
                foreground="#999999"
            ).pack(pady=20)
        
        # Add button to show connection in network map
        ttk.Button(
            self.connections_frame,
            text="Show Connections in Network Map",
            command=lambda: self.update_network_map()
        ).pack(pady=10)
    
    def _create_device_record(self, ip):
        """Create a new device record structure."""
        return {
            'ip': ip,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocols': {},
            'ports_used': set(),
            'category': self._guess_device_category(ip)
        }
    
    def _update_device_category(self, device):
        """Update device category based on behavior."""
        ip = device['ip']
        
        # If category is already assigned, don't change it
        if device['category'] != 'Unknown':
            return
            
        # Analyze behavior to determine category
        
        # Check for server behavior (listens on well-known ports)
        server_ports = {80, 443, 22, 21, 25, 53, 3306, 5432, 27017, 8080, 8443}
        if any(port in server_ports for port in device['ports_used']):
            device['category'] = 'Server'
            return
            
        # Check for DNS server
        if 53 in device['ports_used'] and 'UDP' in device['protocols']:
            device['category'] = 'Server'
            return
        
        # Check for local IP patterns indicating routers/gateways
        if ip.endswith('.1') or ip.endswith('.254'):
            device['category'] = 'Router'
            return
        
        # Check for common router IPs
        if ip in ['192.168.0.1', '192.168.1.1', '10.0.0.1', '10.1.1.1']:
            device['category'] = 'Router'
            return
        
        # If no specific category, assume client
        device['category'] = 'Client'
    
    def _guess_device_category(self, ip):
        """Guess the device category based on IP address patterns."""
        # Check for common router IPs
        if ip.endswith('.1') or ip.endswith('.254'):
            return 'Router'
            
        if ip in ['192.168.0.1', '192.168.1.1', '10.0.0.1', '10.1.1.1']:
            return 'Router'
            
        # Default category
        return 'Unknown'
    
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
        if hasattr(self, 'update_thread') and self.update_thread.is_alive():
            self.update_thread.join(1.0)  # Wait for thread to terminate