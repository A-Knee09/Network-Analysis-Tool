import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Toplevel, StringVar
from ttkbootstrap import Style
from functionality import PacketCapture
from utils import export_to_pdf, send_email
import styles
from styles import apply_dark_theme, apply_light_theme, configure_treeview_style, get_theme_colors
from components import create_tooltip, StatusBar, InterfaceSelector, AboutDialog
import threading
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import platform
import time
import random
from kamene.all import IP, TCP, UDP, ARP  # Updated to use kamene instead of scapy
import traceback
import logging

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Enable high-DPI awareness
if platform.system() == "Windows":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

class NetworkAnalysisTool:
    def __init__(self, root, available_interfaces):
        self.root = root
        self.root.title("Network Analysis Tool")
        self.style = Style(theme="sandstone")
        
        # Set the window size and make it resizable
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Configure style constants
        self.PADDING = 10
        configure_treeview_style(self.style)
        
        # Performance optimization variables
        self.packet_queue = []  # For batch processing
        self.queue_lock = threading.Lock()
        self.last_ui_update = time.time()
        self.ui_update_interval = 0.5  # Update UI every 0.5 seconds
        self.packet_display_data = {}  # Store packet display info
        self.packet_count = 0
        
        # Track simulated packets for filtering
        self.simulated_packets = []
        
        # Show interface selection dialog first
        self.interface_selector = InterfaceSelector(self.root, available_interfaces, self.on_interface_selected)
        
    def on_interface_selected(self, interface):
        # Interface has been selected, initialize the main UI
        self.selected_interface = interface
        self.initialize_main_ui()
        
    def initialize_main_ui(self):
        # Initialize packet capture with selected interface
        self.packet_capture = PacketCapture()
        self.packet_capture.selected_interface = self.selected_interface
        
        # Create main UI frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=self.PADDING, pady=self.PADDING)
        
        # Application state variables
        self.is_capturing = False
        self.dark_mode = tk.BooleanVar(value=False)
        self.theme_colors = get_theme_colors("sandstone")
        
        # Create a top frame for toolbar and main controls
        self.create_toolbar()
        
        # Create a status bar
        self.status_bar = StatusBar(self.root)
        self.status_bar.set_status("Ready. Interface: " + self.selected_interface)
        
        # Create content area with paned window for flexibility
        self.content_pane = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.content_pane.pack(fill=tk.BOTH, expand=True, pady=(self.PADDING, 0))
        
        # Create sidebar for filters and controls
        self.create_sidebar()
        
        # Create main content area for packet display
        self.create_main_content()
        
        # Set initial status
        self.update_stats()
        
        # Update status periodically during capture
        self.root.after(1000, self.update_status_periodically)
        
    def create_toolbar(self):
        """Create the main toolbar with action buttons."""
        self.toolbar = ttk.Frame(self.main_frame)
        self.toolbar.pack(fill=tk.X, pady=(0, self.PADDING))
        
        # Capture controls
        self.start_button = ttk.Button(self.toolbar, text="▶ Start Capture", style="success.TButton", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        create_tooltip(self.start_button, "Start capturing packets on the selected interface")
        
        self.stop_button = ttk.Button(self.toolbar, text="⏹ Stop", style="danger.TButton", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.stop_button, "Stop the current packet capture")
        
        # File operations
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.save_button = ttk.Button(self.toolbar, text="💾 Save", command=self.save_packets)
        self.save_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.save_button, "Save captured packets to PCAP or CSV file")
        
        self.load_button = ttk.Button(self.toolbar, text="📂 Load", command=self.load_packets)
        self.load_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.load_button, "Load packets from a PCAP file")
        
        # Analysis
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.stats_button = ttk.Button(self.toolbar, text="📊 Statistics", command=self.show_statistics)
        self.stats_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.stats_button, "Show packet statistics and visualizations")
        
        self.export_button = ttk.Button(self.toolbar, text="📑 Export PDF", command=self.export_to_pdf)
        self.export_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.export_button, "Export statistics to a PDF report")
        
        # Settings
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.interfaces_button = ttk.Button(self.toolbar, text="🔄 Change Interface", command=self.change_interface)
        self.interfaces_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.interfaces_button, "Change the network interface for capture")
        
        # Help
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.about_button = ttk.Button(self.toolbar, text="ℹ️ About", command=self.show_about)
        self.about_button.pack(side=tk.LEFT, padx=5)
        create_tooltip(self.about_button, "About this application")
        
        # Theme toggle (right aligned)
        self.theme_toggle = ttk.Checkbutton(
            self.toolbar, 
            text="🌙 Dark Mode",
            variable=self.dark_mode,
            command=self.toggle_theme,
            style="Switch.TCheckbutton"
        )
        self.theme_toggle.pack(side=tk.RIGHT, padx=5)
        create_tooltip(self.theme_toggle, "Toggle between light and dark theme")
        
    def create_sidebar(self):
        """Create the sidebar with filter controls."""
        self.sidebar_frame = ttk.Frame(self.content_pane, width=250)
        self.content_pane.add(self.sidebar_frame, weight=1)
        
        # Stats frame
        self.stats_frame = ttk.LabelFrame(self.sidebar_frame, text="Capture Statistics")
        self.stats_frame.pack(fill=tk.X, pady=(0, self.PADDING), padx=self.PADDING)
        
        # Create statistics labels with consistent width
        self.stats_rows = {}
        
        stats_info = [
            ("packets", "Packets:"),
            ("rate", "Packets/sec:"),
            ("duration", "Duration:"),
            ("tcp", "TCP:"),
            ("udp", "UDP:"),
            ("icmp", "ICMP:"),
            ("other", "Other:"),
        ]
        
        for key, label_text in stats_info:
            frame = ttk.Frame(self.stats_frame)
            frame.pack(fill=tk.X, pady=2)
            
            label = ttk.Label(frame, text=label_text, width=12, anchor=tk.W)
            label.pack(side=tk.LEFT)
            
            value = ttk.Label(frame, text="0")
            value.pack(side=tk.RIGHT)
            
            self.stats_rows[key] = value
        
        # Protocol filter
        self.filter_frame = ttk.LabelFrame(self.sidebar_frame, text="Filters")
        self.filter_frame.pack(fill=tk.X, pady=(0, self.PADDING), padx=self.PADDING)
        
        # Protocol selection
        ttk.Label(self.filter_frame, text="Protocol:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        self.protocol_filter = ttk.Combobox(self.filter_frame, values=["All", "TCP", "UDP", "ICMP", "ARP", "Other"])
        self.protocol_filter.set("All")
        self.protocol_filter.pack(fill=tk.X, padx=5, pady=5)
        create_tooltip(self.protocol_filter, "Filter by protocol type")
        
        # IP search
        ttk.Label(self.filter_frame, text="IP Address:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        self.ip_filter = ttk.Entry(self.filter_frame)
        self.ip_filter.pack(fill=tk.X, padx=5, pady=5)
        create_tooltip(self.ip_filter, "Filter by source or destination IP address")
        
        # Apply filter button
        self.filter_button = ttk.Button(self.filter_frame, text="Apply Filters", command=self.apply_filters)
        self.filter_button.pack(fill=tk.X, padx=5, pady=5)
        create_tooltip(self.filter_button, "Apply the selected filters to the packet list")
        
        # Clear filter button
        self.clear_button = ttk.Button(self.filter_frame, text="Clear Filters", command=self.clear_filters)
        self.clear_button.pack(fill=tk.X, padx=5, pady=(0, 5))
        create_tooltip(self.clear_button, "Clear all filters and show all packets")
        
    def create_main_content(self):
        """Create the main content area with the enhanced packet table."""
        self.main_content = ttk.Frame(self.content_pane)
        self.content_pane.add(self.main_content, weight=4)
        
        # Create packet table with tabs for different views
        self.table_frame = ttk.Notebook(self.main_content)
        self.table_frame.pack(fill=tk.BOTH, expand=True, padx=self.PADDING)
        
        # === Basic view tab ===
        self.basic_frame = ttk.Frame(self.table_frame)
        self.table_frame.add(self.basic_frame, text="Basic View")
        
        # Table with scrollbars - Basic view
        self.tree_columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length")
        
        # Create a frame for the treeview and scrollbars
        self.tree_frame = ttk.Frame(self.basic_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create the treeview
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=self.tree_columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure column widths and headings
        column_widths = {
            "No.": 60,
            "Time": 120,
            "Source": 150,
            "Destination": 150,
            "Protocol": 120,
            "Length": 80
        }
        
        for col in self.tree_columns:
            self.tree.heading(col, text=col, anchor=tk.W)
            self.tree.column(col, width=column_widths.get(col, 100), stretch=True, anchor=tk.W)
            
        # Add scrollbars
        self.vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.vsb.set)
        
        self.hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.configure(xscrollcommand=self.hsb.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # === Advanced view tab ===
        self.advanced_frame = ttk.Frame(self.table_frame)
        self.table_frame.add(self.advanced_frame, text="Advanced View")
        
        # Table with scrollbars - Advanced view
        self.adv_tree_columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Port Info", "Payload")
        
        # Create a frame for the advanced treeview and scrollbars
        self.adv_tree_frame = ttk.Frame(self.advanced_frame)
        self.adv_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create the advanced treeview
        self.adv_tree = ttk.Treeview(
            self.adv_tree_frame,
            columns=self.adv_tree_columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure column widths and headings for advanced view
        adv_column_widths = {
            "No.": 60,
            "Time": 120,
            "Source": 150,
            "Destination": 150,
            "Protocol": 120,
            "Length": 80,
            "Port Info": 120,
            "Payload": 80
        }
        
        for col in self.adv_tree_columns:
            self.adv_tree.heading(col, text=col, anchor=tk.W)
            self.adv_tree.column(col, width=adv_column_widths.get(col, 100), stretch=True, anchor=tk.W)
            
        # Add scrollbars for advanced view
        self.adv_vsb = ttk.Scrollbar(self.adv_tree_frame, orient="vertical", command=self.adv_tree.yview)
        self.adv_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.adv_tree.configure(yscrollcommand=self.adv_vsb.set)
        
        self.adv_hsb = ttk.Scrollbar(self.adv_tree_frame, orient="horizontal", command=self.adv_tree.xview)
        self.adv_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.adv_tree.configure(xscrollcommand=self.adv_hsb.set)
        
        self.adv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add functionality to show packet details when a row is clicked
        self.tree.bind("<ButtonRelease-1>", self.show_packet_details)
        self.adv_tree.bind("<ButtonRelease-1>", self.show_packet_details_advanced)
        
        # Create a frame for packet details
        self.packet_details_frame = ttk.LabelFrame(self.main_content, text="Packet Details")
        self.packet_details_frame.pack(fill=tk.X, expand=False, padx=self.PADDING, pady=self.PADDING)
        
        # Packet details text view
        self.packet_details = tk.Text(self.packet_details_frame, height=8, wrap=tk.WORD)
        self.packet_details.pack(fill=tk.BOTH, expand=True)
        
        # Packet count and current row indicators
        self.packet_count = 0
        self.current_row = 0
        
    def start_capture(self):
        """Start capturing packets in a separate thread."""
        print(f"Starting capture on interface: {self.selected_interface}")
        
        # Start or restart capture
        if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
            print("Stopping existing capture thread")
            self.stop_capture()
            # Allow time for the thread to clean up
            import time
            time.sleep(0.5)
        
        # Clear previous packets and reset counters
        self.clear_packet_display()
        self.packet_count = 0
        
        # Reset packet capture
        self.packet_capture = PacketCapture()
        
        # Update UI state
        self.status_bar.set_status(f"Starting packet capture on {self.selected_interface}...")
        self.status_bar.set_progress_mode("indeterminate")
        self.status_bar.start_progress()
        
        # Set capturing flag
        self.is_capturing = True
        self.running = True
        
        # Start capturing
        try:
            # Begin capture thread
            print("Creating new capture thread")
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            print("Capture thread started")
            
            # Start GUI updates
            self.update_gui()
            
            # Update UI
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.interfaces_button.config(state=tk.DISABLED)
            
        except Exception as e:
            print(f"Failed to start capture: {e}")
            self.status_bar.set_status(f"Error starting capture: {e}")
            self.is_capturing = False
            self.running = False
    
    def capture_packets(self):
        """Capture packets in real-time and update the GUI."""
        print("In capture_packets method")
        
        try:
            # Configure packet capture first (try to capture real packets)
            result = self.packet_capture.start_capture(
                packet_handler=self.handle_packet, 
                interface=self.selected_interface
            )
            print("Packet capture attempted")
            
            if result:  # If there was an error (likely permissions)
                # Show a more friendly error message
                if "Permission denied" in result:
                    info_msg = "Running in simulation mode: showing test data for demonstration purposes."
                    print(info_msg)
                    self.root.after(0, lambda: self.status_bar.set_status(info_msg))
                    # Generate sample data for demonstration
                    self.simulate_packets(10)
                    
                    # Show a message box with instructions for capturing real packets
                    self.root.after(1000, lambda: messagebox.showinfo(
                        "Real Packet Capture", 
                        "To capture real network packets, you need elevated privileges:\n\n" +
                        "For Linux:\n" +
                        "  Run with 'sudo python3 main.py' or\n" +
                        "  Grant capability with:\n" +
                        "  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)\n\n" +
                        "For Windows:\n" +
                        "  Install Npcap (or WinPcap)\n" +
                        "  Run as Administrator"
                    ))
                else:
                    # For other errors, show the error message
                    error_msg = f"Capture error: {result}"
                    print(error_msg)
                    self.root.after(0, lambda: self.status_bar.set_status(error_msg))
            else:
                # Real packet capture worked! Setup periodic updates
                print("Real packet capture successful!")
                self.update_status_periodically()
            
        except Exception as e:
            # For unexpected errors, still show simulated data
            error_msg = f"Using simulated data (error: {str(e)})"
            print(f"Capture error: {str(e)}")
            # Update UI on the main thread
            self.root.after(0, lambda: self.status_bar.set_status(error_msg))
            # Generate sample data for demonstration
            self.simulate_packets(10)
    
    def simulate_packets(self, count):
        """Simulate some packets for testing the interface."""
        try:
            # Create a timestamp
            timestamp = time.time()
            
            # Define some realistic packet types for simulation
            protocol_types = [
                {"protocol": "TCP (HTTP)", "src_port": "80", "dst_port": "49152", "stat_key": "tcp"},
                {"protocol": "TCP (HTTPS)", "src_port": "443", "dst_port": "49153", "stat_key": "tcp"},
                {"protocol": "UDP (DNS)", "src_port": "53", "dst_port": "49154", "stat_key": "udp"},
                {"protocol": "ICMP (Echo Request)", "src_port": "", "dst_port": "", "stat_key": "icmp"},
                {"protocol": "TCP (SSH)", "src_port": "22", "dst_port": "49155", "stat_key": "tcp"},
                {"protocol": "ARP", "src_port": "", "dst_port": "", "stat_key": "other"},
                {"protocol": "UDP (NTP)", "src_port": "123", "dst_port": "49156", "stat_key": "udp"}
            ]
            
            # Source and destination IP addresses
            ip_addresses = [
                "192.168.1.1", "192.168.1.100", "8.8.8.8", "1.1.1.1", "10.0.0.1", 
                "172.217.170.14", "157.240.20.35", "192.168.0.1", "192.168.0.105", "34.102.136.180" # Varied IPs
            ]
            
            # Generate the new simulated packets
            new_packets = []
            
            # Simulate varied packets to make it more realistic
            import random
            for i in range(count):
                # Choose random protocol and IPs for variety
                pkt_type = random.choice(protocol_types)
                src_ip = random.choice(ip_addresses)
                dst_ip = random.choice([ip for ip in ip_addresses if ip != src_ip])
                
                # Construct port info if applicable
                port_info = ""
                if pkt_type["src_port"] and pkt_type["dst_port"]:
                    port_info = f"{pkt_type['src_port']} → {pkt_type['dst_port']}"
                
                # Create packet info
                packet_info = {
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": pkt_type["protocol"],
                    "length": random.randint(64, 1500),  # Realistic packet sizes
                    "time": timestamp + i,
                    "port_info": port_info,
                    "payload_size": random.randint(10, 1400),  # Random payload size
                    "ttl": random.choice([64, 128, 255]),  # Common TTL values
                    "encrypted": "HTTPS" in pkt_type["protocol"] or "SSH" in pkt_type["protocol"],
                    "flags": random.choice(["ACK", "SYN", "FIN", "PSH ACK", "SYN ACK"]) if "TCP" in pkt_type["protocol"] else ""
                }
                
                # Add to our collection of simulated packets
                new_packets.append(packet_info)
                
                # Format the timestamp
                formatted_time = time.strftime("%H:%M:%S", time.localtime(packet_info["time"]))
                
                # Increase packet count
                self.packet_count += 1
                
                # Add directly to UI views
                self.add_packet_to_basic_view(packet_info, formatted_time)
                self.add_packet_to_advanced_view(packet_info, formatted_time)
                
                # Update stats
                with self.packet_capture.lock:
                    self.packet_capture.packet_count += 1
                    self.packet_capture.stats[pkt_type["stat_key"]] += 1
                
                # Add a short delay to make it look realistic
                if i % 3 == 0:
                    self.root.update_idletasks()
            
            # Store the new packets
            self.simulated_packets.extend(new_packets)
                
            # Set start time if not set
            if not self.packet_capture.start_time:
                self.packet_capture.start_time = timestamp
                
            # Update UI
            self.update_stats()
            self.status_bar.set_status(f"Simulating network traffic - {count} packets generated")
            self.status_bar.set_progress(50)  # Show progress
            
            # Continue generating more packets in the background
            if self.is_capturing:
                self.root.after(3000, lambda: self.simulate_more_packets(5))
            
            print(f"Simulated {count} packets")
            
        except Exception as e:
            print(f"Error simulating packets: {e}")
            logger.error(traceback.format_exc())
    
    def simulate_more_packets(self, count):
        """Add more simulated packets periodically to create ongoing traffic."""
        if self.is_capturing:
            self.simulate_packets(count)
            # Continue simulating more packets until stopped
            self.root.after(4000, lambda: self.simulate_more_packets(random.randint(3, 8)))

    def handle_packet(self, packet):
        """Handle each captured packet."""
        try:
            # Process the packet and get the information dictionary
            packet_info = self.packet_capture.process_packet(packet)
            
            if packet_info:
                # Increase packet count
                self.packet_count += 1
                
                # Format the timestamp
                formatted_time = time.strftime("%H:%M:%S", time.localtime(packet_info["time"]))
                
                # Add to basic view
                self.root.after(0, lambda: self.add_packet_to_basic_view(packet_info, formatted_time))
                
                # Add to advanced view
                self.root.after(0, lambda: self.add_packet_to_advanced_view(packet_info, formatted_time))
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            logger.error(traceback.format_exc())
            
    def add_packet_to_basic_view(self, packet_info, formatted_time):
        """Add a packet to the basic view treeview."""
        try:
            # Determine row tag (alternating colors)
            row_tag = "even" if self.packet_count % 2 == 0 else "odd"
            
            # Insert into basic view
            self.tree.insert(
                "", "end",
                values=(
                    self.packet_count,
                    formatted_time,
                    packet_info["src"],
                    packet_info["dst"],
                    packet_info["protocol"],
                    packet_info["length"]
                ),
                tags=(row_tag,)
            )
            
            # Auto-scroll to the bottom
            self.tree.yview_moveto(1.0)
        except Exception as e:
            logger.error(f"Error adding packet to basic view: {e}")

    def add_packet_to_advanced_view(self, packet_info, formatted_time):
        """Add a packet to the advanced view treeview."""
        try:
            # Determine row tag (alternating colors)
            row_tag = "even" if self.packet_count % 2 == 0 else "odd"
            
            # Insert into advanced view
            self.adv_tree.insert(
                "", "end",
                values=(
                    self.packet_count,
                    formatted_time,
                    packet_info["src"],
                    packet_info["dst"],
                    packet_info["protocol"],
                    packet_info["length"],
                    packet_info["port_info"],
                    packet_info["payload_size"]
                ),
                tags=(row_tag,)
            )
            
            # Auto-scroll to the bottom
            self.adv_tree.yview_moveto(1.0)
        except Exception as e:
            logger.error(f"Error adding packet to advanced view: {e}")
                
    def stop_capture(self):
        """Stop the current packet capture."""
        if not self.is_capturing:
            return
            
        # Stop the capture
        self.packet_capture.stop_capture()
        self.is_capturing = False
        
        # Update the status bar
        self.status_bar.stop_progress()
        self.status_bar.set_progress_mode("determinate")
        self.status_bar.set_progress(100)
        self.status_bar.set_status(f"Capture stopped. {self.packet_count} packets captured.")
        
        # Update button states
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.interfaces_button.config(state=tk.NORMAL)
        
    def update_gui(self):
        """Update the GUI periodically during capture."""
        if self.is_capturing:
            # Update stats
            self.update_stats()
            # Schedule the next update
            self.root.after(500, self.update_gui)
            
    def update_status_periodically(self):
        """Update status bar periodically to show time elapsed."""
        if self.is_capturing:
            stats = self.packet_capture.get_capture_stats()
            if stats:
                self.status_bar.set_status(
                    f"Capturing: {stats['packets']} packets ({stats['rate']} p/s), duration: {stats['duration']}s"
                )
        
        # Schedule next update
        self.root.after(1000, self.update_status_periodically)
            
    def update_stats(self):
        """Update the statistics display with current stats."""
        try:
            stats = self.packet_capture.get_capture_stats()
            
            if stats:
                # Update each statistics row
                self.stats_rows["packets"].config(text=str(stats["packets"]))
                self.stats_rows["rate"].config(text=f"{stats['rate']} p/s")
                self.stats_rows["duration"].config(text=f"{stats['duration']}s")
                
                # Protocol breakdowns
                self.stats_rows["tcp"].config(text=str(stats["protocols"]["tcp"]))
                self.stats_rows["udp"].config(text=str(stats["protocols"]["udp"]))
                self.stats_rows["icmp"].config(text=str(stats["protocols"]["icmp"]))
                self.stats_rows["other"].config(text=str(stats["protocols"]["other"]))
        except Exception as e:
            logger.error(f"Error updating stats: {e}")
            
    def clear_packet_display(self):
        """Clear all packet displays."""
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for item in self.adv_tree.get_children():
            self.adv_tree.delete(item)
            
        self.packet_details.delete(1.0, tk.END)
        
    def show_packet_details(self, event):
        """Show details of the selected packet in the basic view."""
        try:
            selected_item = self.tree.selection()[0]
            if selected_item:
                # Get the values from the selected row
                values = self.tree.item(selected_item, 'values')
                if values:
                    # Try to show real packet details first
                    item_index = self.tree.index(selected_item)
                    if 0 <= item_index < len(self.packet_capture.packets):
                        try:
                            packet = self.packet_capture.packets[item_index]
                            self.packet_details.delete(1.0, tk.END)
                            self.packet_details.insert(tk.END, str(packet.show(dump=True)))
                            return
                        except Exception as e:
                            # If real packet details fail, show formatted information
                            pass
                            
                    # If we're showing simulated data, create a formatted display
                    self.packet_details.delete(1.0, tk.END)
                    
                    # Format the packet information nicely
                    packet_num, time_str, src, dst, protocol, length = values
                    
                    details = f"""Packet #{packet_num} ({protocol})
-----------------------------
Timestamp: {time_str}
Source IP: {src}
Destination IP: {dst}
Length: {length} bytes

"""
                    
                    # Add protocol specific details for simulation
                    if "TCP" in protocol:
                        details += "TCP Header:\n"
                        details += "  Sequence Number: 3423423423\n"
                        details += "  Acknowledgment Number: 1654534334\n"
                        details += "  Flags: ACK PSH\n"
                        details += "  Window Size: 64240\n"
                        
                        if "HTTP" in protocol:
                            details += "\nHTTP Data:\n"
                            details += "  GET /index.html HTTP/1.1\n"
                            details += "  Host: example.com\n"
                            details += "  User-Agent: Mozilla/5.0\n"
                            details += "  Accept: text/html,application/xhtml+xml\n"
                        elif "HTTPS" in protocol:
                            details += "\nTLS Encrypted Data\n"
                    elif "UDP" in protocol:
                        details += "UDP Header:\n"
                        details += "  Source Port: 53\n"
                        details += "  Destination Port: 49152\n"
                        details += "  Length: 48\n"
                        
                        if "DNS" in protocol:
                            details += "\nDNS Query:\n"
                            details += "  Transaction ID: 0x1234\n"
                            details += "  Flags: 0x0100 (Standard query)\n"
                            details += "  Questions: 1\n"
                            details += "  Query: example.com, type A, class IN\n"
                    elif "ICMP" in protocol:
                        details += "ICMP Header:\n"
                        details += "  Type: 8 (Echo request)\n"
                        details += "  Code: 0\n"
                        details += "  Checksum: 0x1a2b\n"
                        details += "  Identifier: 0x0001\n"
                        details += "  Sequence number: 0x0001\n"
                    
                    # Add the formatted details
                    self.packet_details.insert(tk.END, details)
        except IndexError:
            pass  # No selection
        except Exception as e:
            logger.error(f"Error showing packet details: {e}")
            
    def show_packet_details_advanced(self, event):
        """Show details of the selected packet in the advanced view."""
        try:
            selected_item = self.adv_tree.selection()[0]
            if selected_item:
                # Get the values from the selected row
                values = self.adv_tree.item(selected_item, 'values')
                if values:
                    # Try to show real packet details first
                    item_index = self.adv_tree.index(selected_item)
                    if 0 <= item_index < len(self.packet_capture.packets):
                        try:
                            packet = self.packet_capture.packets[item_index]
                            self.packet_details.delete(1.0, tk.END)
                            self.packet_details.insert(tk.END, str(packet.show(dump=True)))
                            return
                        except Exception as e:
                            # If real packet details fail, show formatted information
                            pass
                            
                    # If we're showing simulated data, create a formatted display
                    self.packet_details.delete(1.0, tk.END)
                    
                    # Format the packet information nicely with advanced details
                    packet_num, time_str, src, dst, protocol, length, port_info, payload = values
                    
                    details = f"""Packet #{packet_num} ({protocol})
-----------------------------
Timestamp: {time_str}
Source IP: {src}
Destination IP: {dst}
Ports: {port_info}
Length: {length} bytes
Payload Size: {payload} bytes

"""
                    
                    # Add protocol specific details for simulation (same as basic view)
                    if "TCP" in protocol:
                        details += "TCP Header:\n"
                        details += "  Sequence Number: 3423423423\n"
                        details += "  Acknowledgment Number: 1654534334\n"
                        details += "  Flags: ACK PSH\n"
                        details += "  Window Size: 64240\n"
                        
                        if "HTTP" in protocol:
                            details += "\nHTTP Data:\n"
                            details += "  GET /index.html HTTP/1.1\n"
                            details += "  Host: example.com\n"
                            details += "  User-Agent: Mozilla/5.0\n"
                            details += "  Accept: text/html,application/xhtml+xml\n"
                        elif "HTTPS" in protocol:
                            details += "\nTLS Encrypted Data\n"
                    elif "UDP" in protocol:
                        details += "UDP Header:\n"
                        details += "  Source Port: 53\n"
                        details += "  Destination Port: 49152\n"
                        details += "  Length: 48\n"
                        
                        if "DNS" in protocol:
                            details += "\nDNS Query:\n"
                            details += "  Transaction ID: 0x1234\n"
                            details += "  Flags: 0x0100 (Standard query)\n"
                            details += "  Questions: 1\n"
                            details += "  Query: example.com, type A, class IN\n"
                    elif "ICMP" in protocol:
                        details += "ICMP Header:\n"
                        details += "  Type: 8 (Echo request)\n"
                        details += "  Code: 0\n"
                        details += "  Checksum: 0x1a2b\n"
                        details += "  Identifier: 0x0001\n"
                        details += "  Sequence number: 0x0001\n"
                    
                    # Add the formatted details
                    self.packet_details.insert(tk.END, details)
        except IndexError:
            pass  # No selection
        except Exception as e:
            logger.error(f"Error showing packet details (advanced): {e}")
            
    def apply_filters(self):
        """Apply filters to the packet display."""
        protocol_filter = self.protocol_filter.get()
        ip_filter = self.ip_filter.get().strip()
        
        # Clear the current display
        self.clear_packet_display()
        
        # Since we may be using simulated data, we need to handle filtering differently
        # depending on whether we have real packets or simulated ones
        
        if hasattr(self, 'simulated_packets') and self.simulated_packets:
            # Filter our simulated packet data
            all_packets = self.simulated_packets
            filtered_packets = []
            
            for packet in all_packets:
                # Check protocol filter - make case insensitive for better usability
                protocol_match = True  # Default to match if "All" is selected
                if protocol_filter != "All":
                    protocol_match = protocol_filter.upper() in packet["protocol"].upper()
                
                # Check IP filter - partial match for better usability
                ip_match = True  # Default to match if no IP filter
                if ip_filter:
                    ip_match = (ip_filter in packet["src"] or ip_filter in packet["dst"])
                
                # Add to filtered packets if it matches all criteria
                if protocol_match and ip_match:
                    filtered_packets.append(packet)
                
            # Display the filtered simulated packets
            for i, packet_info in enumerate(filtered_packets):
                # Format the timestamp
                formatted_time = time.strftime("%H:%M:%S", time.localtime(packet_info["time"]))
                
                # Determine row tag
                row_tag = "even" if i % 2 == 0 else "odd"
                
                # Insert into basic view
                self.tree.insert(
                    "", "end",
                    values=(
                        i + 1,
                        formatted_time,
                        packet_info["src"],
                        packet_info["dst"],
                        packet_info["protocol"],
                        packet_info["length"]
                    ),
                    tags=(row_tag,)
                )
                
                # Insert into advanced view
                self.adv_tree.insert(
                    "", "end",
                    values=(
                        i + 1,
                        formatted_time,
                        packet_info["src"],
                        packet_info["dst"],
                        packet_info["protocol"],
                        packet_info["length"],
                        packet_info["port_info"],
                        packet_info["payload_size"]
                    ),
                    tags=(row_tag,)
                )
                
        else:
            # Use real packet capture data if available
            filtered_packets = self.packet_capture.packets  # Start with all packets
            
            if protocol_filter != "All":
                filtered_packets = [p for p in filtered_packets if self.packet_capture._get_packet_protocol(p) == protocol_filter]
                
            if ip_filter:
                filtered_packets = [p for p in filtered_packets if (IP in p and (p[IP].src == ip_filter or p[IP].dst == ip_filter))]
                
            # Display the filtered packets
            for i, packet in enumerate(filtered_packets):
                self.display_filtered_packet(i, packet)
            
        # Update status
        self.status_bar.set_status(f"Showing {len(filtered_packets)} packets matching filters")
        
        # Flash the filter button briefly to indicate successful filter application
        original_style = self.filter_button.cget('style')
        self.filter_button.config(style='success.TButton')
        self.root.after(400, lambda: self.filter_button.config(style=original_style))
            
    def display_filtered_packet(self, index, packet):
        """Display a filtered packet in the treeviews."""
        try:
            # Process the packet to get display information
            packet_info = self.packet_capture.process_packet(packet)
            
            if packet_info:
                # Format the timestamp
                formatted_time = time.strftime("%H:%M:%S", time.localtime(packet_info["time"]))
                
                # Determine row tag
                row_tag = "even" if index % 2 == 0 else "odd"
                
                # Insert into basic view
                self.tree.insert(
                    "", "end",
                    values=(
                        index + 1,  # Use 1-based indexing for display
                        formatted_time,
                        packet_info["src"],
                        packet_info["dst"],
                        packet_info["protocol"],
                        packet_info["length"]
                    ),
                    tags=(row_tag,)
                )
                
                # Insert into advanced view
                self.adv_tree.insert(
                    "", "end",
                    values=(
                        index + 1,
                        formatted_time,
                        packet_info["src"],
                        packet_info["dst"],
                        packet_info["protocol"],
                        packet_info["length"],
                        packet_info["port_info"],
                        packet_info["payload_size"]
                    ),
                    tags=(row_tag,)
                )
        except Exception as e:
            logger.error(f"Error displaying filtered packet: {e}")
            
    def clear_filters(self):
        """Clear all filters and show all packets."""
        self.protocol_filter.set("All")
        self.ip_filter.delete(0, tk.END)
        self.apply_filters()
            
    def save_packets(self):
        """Save captured packets to a file."""
        if not self.packet_capture.packets:
            messagebox.showwarning("No Data", "No packets to save. Capture some traffic first.")
            return
            
        # Ask for the file type
        file_type = messagebox.askyesno(
            "Save Format", 
            "Do you want to save in PCAP format?\n\nYes: Save as PCAP (for use in other tools)\nNo: Save as CSV (for spreadsheets)"
        )
        
        if file_type:  # PCAP
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
            )
            if file_path:
                result = self.packet_capture.save_to_pcap(file_path)
                if result is True:
                    messagebox.showinfo("Success", f"Saved {len(self.packet_capture.packets)} packets to {file_path}")
                else:
                    messagebox.showerror("Error", f"Failed to save: {result}")
        else:  # CSV
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if file_path:
                result = self.packet_capture.save_to_csv(file_path)
                if result is True:
                    messagebox.showinfo("Success", f"Saved {len(self.packet_capture.packets)} packets to {file_path}")
                else:
                    messagebox.showerror("Error", f"Failed to save: {result}")
                    
    def load_packets(self):
        """Load packets from a PCAP file."""
        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if file_path:
            # Stop any current capture
            if self.is_capturing:
                self.stop_capture()
                
            # Load the packets
            result = self.packet_capture.load_from_pcap(file_path)
            
            if result is True:
                # Clear the display
                self.clear_packet_display()
                
                # Process and display each loaded packet
                for i, packet in enumerate(self.packet_capture.packets):
                    self.display_filtered_packet(i, packet)
                    
                # Update stats and status
                self.packet_count = len(self.packet_capture.packets)
                self.update_stats()
                self.status_bar.set_status(f"Loaded {self.packet_count} packets from {file_path}")
            else:
                messagebox.showerror("Error", f"Failed to load packets: {result}")
                
    def show_statistics(self):
        """Show packet statistics and visualizations."""
        if not self.packet_capture.packets:
            messagebox.showwarning("No Data", "No packets to analyze. Capture some traffic first.")
            return
            
        # Create a new window for statistics
        stats_window = Toplevel(self.root)
        stats_window.title("Packet Statistics")
        stats_window.geometry("800x600")
        stats_window.minsize(800, 600)
        stats_window.grab_set()  # Make modal
        
        # Create a notebook for different charts
        notebook = ttk.Notebook(stats_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Protocol distribution frame
        protocol_frame = ttk.Frame(notebook)
        notebook.add(protocol_frame, text="Protocol Distribution")
        
        # Get protocol statistics
        protocol_stats = self.packet_capture.get_statistics()
        protocols = list(protocol_stats.keys())
        counts = list(protocol_stats.values())
        
        # Create a pie chart
        fig = go.Figure(data=[go.Pie(
            labels=protocols,
            values=counts,
            hole=.3,
            marker_colors=['#3366CC', '#DC3912', '#FF9900', '#109618', '#990099']
        )])
        
        fig.update_layout(
            title_text="Protocol Distribution",
            height=500,
        )
        
        # Convert to HTML
        chart_html = fig.to_html(include_plotlyjs='cdn')
        
        # Display in a webview or embedded browser if available
        try:
            import webview
            # Save to temporary file
            with open("temp_chart.html", "w") as f:
                f.write(chart_html)
            webview.create_window("Protocol Distribution", "temp_chart.html", width=700, height=500)
            webview.start()
        except ImportError:
            # Alternative: open in default browser
            import tempfile
            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
                f.write(chart_html)
                chart_path = f.name
            import webbrowser
            webbrowser.open('file://' + chart_path)
            
        # Traffic timeline frame (if we have enough data)
        if len(self.packet_capture.packets) > 10:
            time_frame = ttk.Frame(notebook)
            notebook.add(time_frame, text="Traffic Timeline")
            
            # Create time series data
            packet_times = [p.time for p in self.packet_capture.packets]
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
            
            # Create a time series chart
            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(x=x_values, y=y_values, mode='lines+markers'))
            
            fig2.update_layout(
                title="Packets per Second",
                xaxis_title="Seconds elapsed",
                yaxis_title="Packet count",
                height=500
            )
            
            # Save to HTML
            time_html = fig2.to_html(include_plotlyjs='cdn')
            
            # Display in browser
            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
                f.write(time_html)
                time_path = f.name
            
            # Add button to open
            ttk.Button(
                time_frame, 
                text="View Timeline Chart",
                command=lambda: webbrowser.open('file://' + time_path)
            ).pack(pady=20)
                
    def export_to_pdf(self):
        """Export statistics to a PDF report."""
        if not self.packet_capture.packets:
            messagebox.showwarning("No Data", "No packets to export. Capture some traffic first.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                protocol_stats = self.packet_capture.get_statistics()
                success = export_to_pdf(protocol_stats, self.selected_interface, file_path)
                
                if success:
                    # Ask if user wants to email the report
                    if messagebox.askyesno("Email Report", "Would you like to email this report?"):
                        self.email_report(file_path)
                    else:
                        messagebox.showinfo("Success", f"Report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")
                
    def email_report(self, report_file):
        """Email the generated PDF report."""
        # Create dialog for email
        email_dialog = Toplevel(self.root)
        email_dialog.title("Send Report by Email")
        email_dialog.geometry("400x200")
        email_dialog.grab_set()
        
        # Email entry
        ttk.Label(email_dialog, text="Recipient Email:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        email_var = StringVar()
        email_entry = ttk.Entry(email_dialog, textvariable=email_var, width=40)
        email_entry.pack(fill=tk.X, padx=10, pady=5)
        
        # Subject entry
        ttk.Label(email_dialog, text="Subject:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        subject_var = StringVar(value="Network Analysis Report")
        subject_entry = ttk.Entry(email_dialog, textvariable=subject_var, width=40)
        subject_entry.pack(fill=tk.X, padx=10, pady=5)
        
        # Send button
        def send():
            recipient = email_var.get().strip()
            subject = subject_var.get().strip()
            
            if not recipient:
                messagebox.showwarning("Missing Information", "Please enter a recipient email address.")
                return
                
            result = send_email(report_file, recipient, subject)
            
            if result is True:
                messagebox.showinfo("Success", f"Report sent to {recipient}")
                email_dialog.destroy()
            else:
                messagebox.showerror("Error", f"Failed to send email: {result}")
        
        ttk.Button(email_dialog, text="Send Report", command=send).pack(pady=10)
        ttk.Button(email_dialog, text="Cancel", command=email_dialog.destroy).pack(pady=0)
        
        # Center the dialog
        email_dialog.update_idletasks()
        width = email_dialog.winfo_width()
        height = email_dialog.winfo_height()
        x = (email_dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (email_dialog.winfo_screenheight() // 2) - (height // 2)
        email_dialog.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
    def change_interface(self):
        """Change the network interface for capture."""
        from functionality import get_available_interfaces
        
        # Stop any current capture
        if self.is_capturing:
            self.stop_capture()
            
        # Get available interfaces
        interfaces = get_available_interfaces()
        
        # Show interface selector
        self.interface_selector = InterfaceSelector(self.root, interfaces, self.on_interface_change)
        
    def on_interface_change(self, interface):
        """Handle interface change."""
        if interface != self.selected_interface:
            self.selected_interface = interface
            self.packet_capture.selected_interface = interface
            self.status_bar.set_status(f"Interface changed to: {interface}")
            
            # Clear the display
            self.clear_packet_display()
            
            # Reset stats
            self.packet_capture.packets = []
            self.packet_capture.packet_count = 0
            self.packet_capture.stats = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
            self.update_stats()
        
    def toggle_theme(self):
        """Toggle between light and dark theme."""
        try:
            # Get the current dark mode value from the variable
            is_dark = self.dark_mode.get()
            
            if is_dark:
                # Dark theme settings
                print("Switching to dark theme")
                bg_color = "#1a1a1a"
                alt_color = "#2a2a2a"
                text_color = "#ffffff"
                theme_name = "darkly"
                self.style = Style(theme="darkly")
            else:
                # Light theme settings
                print("Switching to light theme")
                bg_color = "#f8f9fa"
                alt_color = "#e9ecef"
                text_color = "#212529"
                theme_name = "sandstone"
                self.style = Style(theme="sandstone")
            
            # Update theme colors
            self.theme_colors = {
                "background": bg_color,
                "secondary": alt_color,
                "text": text_color
            }
            
            # Configure treeview styles
            configure_treeview_style(self.style)
            
            # Update tree colors for both views
            self.tree.tag_configure('odd', background=alt_color)
            self.tree.tag_configure('even', background=bg_color)
            self.adv_tree.tag_configure('odd', background=alt_color)
            self.adv_tree.tag_configure('even', background=bg_color)
            
            # Also update the packet details area background
            self.packet_details.config(bg=bg_color, fg=text_color)
            
            # Update status
            self.status_bar.set_status(f"Theme changed to: {theme_name}")
            
            print(f"Theme update successful")
            
        except Exception as e:
            # Just log the error instead of letting it propagate
            print(f"Theme toggle error: {str(e)}")
            logger.error(traceback.format_exc())

        
    def show_about(self):
        """Show about dialog."""
        about_dialog = AboutDialog(self.root)
        about_dialog.show()
        
    def on_closing(self):
        """Handle window closing."""
        if self.is_capturing:
            if messagebox.askyesno("Quit", "A capture is in progress. Are you sure you want to quit?"):
                self.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()
