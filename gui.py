import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Toplevel, StringVar
from ttkbootstrap import Style
from functionality import PacketCapture, get_available_interfaces
from utils import export_to_pdf, send_email
import styles
from styles import apply_dark_theme, apply_light_theme, configure_treeview_style, get_theme_colors
from components import create_tooltip, StatusBar, InterfaceSelector, AboutDialog
from dashboard.network_dashboard import NetworkDashboard
from dashboard.statistics_dashboard import StatisticsDashboard
from dashboard.device_dashboard import DeviceDashboard
import threading
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import platform
import time
import random
import tempfile
import webbrowser
import subprocess
from kamene.all import IP, TCP, UDP, ARP, ICMP  # Updated to use kamene instead of scapy
import os
import traceback
import logging
import matplotlib
# Removed PacketTranslator import as human-readable view is no longer needed

# Configure matplotlib to use Agg backend to avoid GUI dependencies
matplotlib.use('Agg')
# Explicitly set font path to resolve matplotlib font issues
try:
    import matplotlib.font_manager as fm
    # Add the default system font paths
    if platform.system() == "Windows":
        # Windows font directory
        font_dirs = [r'C:\Windows\Fonts']
    elif platform.system() == "Darwin":
        # macOS font directories
        font_dirs = ['/System/Library/Fonts', '/Library/Fonts', '~/Library/Fonts']
    else:
        # Linux font directories
        font_dirs = ['/usr/share/fonts', '/usr/local/share/fonts', '~/.fonts']
        
    for font_dir in font_dirs:
        fm.fontManager.addfont(os.path.expanduser(font_dir))
except Exception as e:
    logging.warning(f"Could not configure matplotlib fonts: {e}")

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Enable high-DPI awareness
if platform.system() == "Windows":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception as e:
        logger.debug(f"Could not enable high-DPI awareness: {e}")

class NetworkAnalysisTool:
    def __init__(self, root, available_interfaces):
        self.root = root
        self.root.title("Network Analysis Tool")
        self.style = Style(theme="flatly")  # Start with light theme
        
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
        
        # Track packets for filtering and dashboard
        self.filtered_packets = []
        self.all_packet_info = []  # Store all processed packet info
        
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
        self.dark_mode = False  # Initialize in light mode
        self.current_theme = "flatly"  # Start with flatly theme
        self.theme_colors = get_theme_colors(self.current_theme)
        
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
        
        # Create main content area with notebook for different views
        self.notebook = ttk.Notebook(self.content_pane)
        self.content_pane.add(self.notebook, weight=4)
        
        # Create packet view tab
        self.create_packet_view()
        
        # Create the network dashboard tab
        self.create_network_dashboard()
        
        # Create the statistics dashboard tab
        self.create_statistics_dashboard()
        
        # Create the device dashboard tab
        self.create_device_dashboard()
        
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
        
        # Theme toggle button (right aligned)
        self.theme_var = tk.StringVar(value="☀️ Light Mode")
        self.theme_button = ttk.Button(
            self.toolbar,
            textvariable=self.theme_var,
            command=self.toggle_theme
        )
        self.theme_button.pack(side=tk.RIGHT, padx=5)
        create_tooltip(self.theme_button, "Toggle between light and dark mode")
        
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
        
        # Port filter
        ttk.Label(self.filter_frame, text="Port:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        self.port_filter = ttk.Entry(self.filter_frame)
        self.port_filter.pack(fill=tk.X, padx=5, pady=5)
        create_tooltip(self.port_filter, "Filter by port number")
        
        # Apply filter button
        self.filter_button = ttk.Button(self.filter_frame, text="Apply Filters", command=self.apply_filters)
        self.filter_button.pack(fill=tk.X, padx=5, pady=5)
        create_tooltip(self.filter_button, "Apply the selected filters to the packet list")
        
        # Clear filter button
        self.clear_button = ttk.Button(self.filter_frame, text="Clear Filters", command=self.clear_filters)
        self.clear_button.pack(fill=tk.X, padx=5, pady=(0, 5))
        create_tooltip(self.clear_button, "Clear all filters and show all packets")
        
    def create_packet_view(self):
        """Create the main packet view tab."""
        self.packet_view_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.packet_view_frame, text="Packet Capture")
        
        # Create packet table with tabs for different views
        self.table_frame = ttk.Notebook(self.packet_view_frame)
        self.table_frame.pack(fill=tk.BOTH, expand=True, padx=self.PADDING)
        
        # === Packet View tab (formerly Advanced View) ===
        self.advanced_frame = ttk.Frame(self.table_frame)
        self.table_frame.add(self.advanced_frame, text="Packet View")
        
        # Table with scrollbars
        self.adv_tree_columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Port Info", "Payload")
        
        # Create a frame for the treeview and scrollbars
        self.adv_tree_frame = ttk.Frame(self.advanced_frame)
        self.adv_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create the treeview
        self.adv_tree = ttk.Treeview(
            self.adv_tree_frame,
            columns=self.adv_tree_columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure column widths and headings
        adv_column_widths = {
            "No.": 60,
            "Time": 100,
            "Source": 150,
            "Destination": 150,
            "Protocol": 100,
            "Length": 80,
            "Port Info": 120,
            "Payload": 120
        }
        
        for col in self.adv_tree_columns:
            self.adv_tree.heading(col, text=col, anchor=tk.W)
            self.adv_tree.column(col, width=adv_column_widths.get(col, 100), stretch=True, anchor=tk.W)
            
        # Add scrollbars
        self.adv_vsb = ttk.Scrollbar(self.adv_tree_frame, orient="vertical", command=self.adv_tree.yview)
        self.adv_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.adv_tree.configure(yscrollcommand=self.adv_vsb.set)
        
        self.adv_hsb = ttk.Scrollbar(self.adv_tree_frame, orient="horizontal", command=self.adv_tree.xview)
        self.adv_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.adv_tree.configure(xscrollcommand=self.adv_hsb.set)
        
        self.adv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add select event handler
        self.adv_tree.bind("<<TreeviewSelect>>", self.on_adv_packet_selected)
        
        # === Packet Details tab ===
        self.details_frame = ttk.Frame(self.table_frame)
        self.table_frame.add(self.details_frame, text="Packet Details")
        
        # Create a text widget for detailed packet information
        self.details_text = tk.Text(self.details_frame, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for details text
        details_vsb = ttk.Scrollbar(self.details_text, orient="vertical", command=self.details_text.yview)
        details_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.details_text.configure(yscrollcommand=details_vsb.set)
        
        # Set default text
        self.details_text.insert(tk.END, "Select a packet to view its details.")
        self.details_text.config(state=tk.DISABLED)
        
    def create_network_dashboard(self):
        """Create the network dashboard tab."""
        self.network_dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_dashboard_frame, text="Network Dashboard")
        
        # Initialize the network dashboard
        self.network_dashboard = NetworkDashboard(self.network_dashboard_frame)
        
    def create_statistics_dashboard(self):
        """Create the statistics dashboard tab."""
        self.statistics_dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.statistics_dashboard_frame, text="Statistics")
        
        # Initialize the statistics dashboard
        self.statistics_dashboard = StatisticsDashboard(self.statistics_dashboard_frame)
        
    def create_device_dashboard(self):
        """Create the device dashboard tab."""
        self.device_dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.device_dashboard_frame, text="Device Profiler")
        
        # Initialize the device dashboard
        self.device_dashboard = DeviceDashboard(self.device_dashboard_frame)
        
    def update_dashboard_data(self):
        """Update all dashboards with current packet data."""
        try:
            # Check if we have packet data to update dashboards
            if not self.all_packet_info:
                return
                
            # Update network dashboard
            if hasattr(self, 'network_dashboard'):
                logger.debug("Updating network dashboard")
                self.network_dashboard.update_dashboard(self.all_packet_info)
                
            # Update statistics dashboard
            if hasattr(self, 'statistics_dashboard'):
                logger.debug("Updating statistics dashboard")
                stats = self.packet_capture.get_capture_stats()
                self.statistics_dashboard.update_dashboard(self.all_packet_info, stats)
                
            # Update device dashboard
            if hasattr(self, 'device_dashboard'):
                logger.debug("Updating device dashboard")
                self.device_dashboard.update_dashboard(self.all_packet_info)
                
        except Exception as e:
            logger.error(f"Error updating dashboards: {e}")
            logger.error(traceback.format_exc())
        
    def start_capture(self):
        """Start packet capture."""
        if self.is_capturing:
            return
            
        # Reset UI and data
        self.clear_packet_display()
        self.all_packet_info = []
        self.packet_count = 0
        
        # Update UI state
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.is_capturing = True
        self.status_bar.set_status(f"Capturing packets on {self.selected_interface}...")
        self.status_bar.start_progress()
        
        # Start packet capture
        error = self.packet_capture.start_capture(self.handle_packet, self.selected_interface)
        if error:
            messagebox.showerror("Capture Error", f"Failed to start packet capture: {error}")
            self.stop_capture()
            return
            
        # Start periodic update
        self.update_ui()
        
    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_capturing:
            return
            
        # Stop packet capture
        self.packet_capture.stop_capture()
        self.is_capturing = False
        
        # Update UI
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_bar.set_status(f"Capture stopped. Packets: {self.packet_count}")
        self.status_bar.stop_progress()
        
        # Update dashboards with final data
        self.update_dashboard_data()
        
    def handle_packet(self, packet, packet_info):
        """Process each captured packet."""
        try:
            # Add timestamp if not present
            if "time" not in packet_info:
                packet_info["time"] = time.time()
                
            # Add to queue for batch processing
            with self.queue_lock:
                self.packet_queue.append(packet_info)
                self.all_packet_info.append(packet_info)
                
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
            
    def update_ui(self):
        """Update the UI with new packets from the queue."""
        current_time = time.time()
        
        if current_time - self.last_ui_update >= self.ui_update_interval:
            # Process packets in batch for better performance
            with self.queue_lock:
                packets_to_process = self.packet_queue.copy()
                self.packet_queue = []
                
            # Add new packets to display
            if packets_to_process:
                self.add_packets_to_display(packets_to_process)
                
                # Update dashboards periodically during capture
                if len(self.all_packet_info) % 25 == 0:  # Update every 25 packets
                    self.update_dashboard_data()
                    
            # Update statistics
            self.update_stats()
                
            # Record last update time
            self.last_ui_update = current_time
            
        # Schedule next update if still capturing
        if self.is_capturing:
            self.root.after(100, self.update_ui)
            
    def add_packets_to_display(self, packets):
        """Add packets to the display in batch."""
        if not packets:
            return
            
        # Add packets to the packet view
        for packet_info in packets:
            time_str = time.strftime('%H:%M:%S', time.localtime(packet_info.get('time', 0)))
            self.packet_count += 1
            
            # Add to packet view
            self.adv_tree.insert("", "end", values=(
                self.packet_count,
                time_str,
                packet_info.get('src', 'Unknown'),
                packet_info.get('dst', 'Unknown'),
                packet_info.get('protocol', 'Unknown'),
                packet_info.get('length', 0),
                packet_info.get('port_info', ''),
                packet_info.get('payload_size', 0)
            ))
                
        # Limit the number of displayed packets for performance
        max_display = 1000
        
        # Remove excess items if needed
        adv_items = self.adv_tree.get_children()
        if len(adv_items) > max_display:
            for i in range(len(adv_items) - max_display):
                self.adv_tree.delete(adv_items[i])
                
        # Ensure the latest packet is visible
        if adv_items:
            self.adv_tree.see(adv_items[-1])
                
    def update_stats(self):
        """Update the statistics display."""
        try:
            stats = self.packet_capture.get_capture_stats()
            if stats:
                self.stats_rows["packets"].config(text=str(stats["packets"]))
                self.stats_rows["rate"].config(text=str(stats["rate"]))
                self.stats_rows["duration"].config(text=f"{stats['duration']}s")
                self.stats_rows["tcp"].config(text=str(stats["protocols"]["tcp"]))
                self.stats_rows["udp"].config(text=str(stats["protocols"]["udp"]))
                self.stats_rows["icmp"].config(text=str(stats["protocols"]["icmp"]))
                self.stats_rows["other"].config(text=str(stats["protocols"]["other"]))
                
                # Check for capture errors
                if stats.get("error"):
                    self.status_bar.set_status(f"Capture error: {stats['error']}")
        except Exception as e:
            logger.error(f"Error updating stats: {e}")
            
    def update_status_periodically(self):
        """Update the status bar periodically."""
        if self.is_capturing:
            stats = self.packet_capture.get_capture_stats()
            if stats:
                self.status_bar.set_status(f"Capturing on {self.selected_interface}. {stats['packets']} packets, {stats['rate']} pps")
        self.root.after(1000, self.update_status_periodically)
        
    def clear_packet_display(self):
        """Clear all packet displays."""
        # Clear packet tree
        for item in self.adv_tree.get_children():
            self.adv_tree.delete(item)
            
        # Clear details text
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Select a packet to view its details.")
        self.details_text.config(state=tk.DISABLED)
        
    # Basic view handler removed as we now only have the Advanced View
        
    def on_adv_packet_selected(self, event):
        """Handle packet selection in advanced view."""
        try:
            # Set a flag to prevent recursive selection events
            if hasattr(self, '_in_selection_handler') and self._in_selection_handler:
                return
                
            self._in_selection_handler = True
            
            selection = self.adv_tree.selection()
            if not selection:
                self._in_selection_handler = False
                return
                
            item = selection[0]
            values = self.adv_tree.item(item, "values")
            if not values:
                self._in_selection_handler = False
                return
                
            # Get packet index
            packet_index = int(values[0]) - 1
            
            # Show details in a separate thread to avoid UI freezing
            threading.Thread(target=self._show_packet_details_thread, 
                            args=(packet_index,), 
                            daemon=True).start()
            
            # Reset selection handler flag
            self._in_selection_handler = False
                
        except Exception as e:
            # Make sure to always reset the flag
            self._in_selection_handler = False
            logger.error(f"Error in packet selection: {e}")
            self.status_bar.set_status(f"Error selecting packet: {str(e)}")
            
    def _show_packet_details_thread(self, packet_index):
        """Show packet details in a separate thread to avoid UI freezing."""
        try:
            # First, update status in main thread
            self.root.after(0, lambda: self.status_bar.set_status("Loading packet details..."))
            
            try:
                # Get packet details in background thread
                details = self.packet_capture.get_packet_details(packet_index)
                
                # Update UI in main thread using a simpler function that won't call sync_selection
                # This helps break any recursive loops that could cause maximum recursion depth errors
                self.root.after(0, lambda: self._display_packet_details(details))
            except Exception as e:
                logger.error(f"Error getting packet details in thread: {e}")
                # Make sure to handle errors in the main thread
                self.root.after(0, lambda: self.status_bar.set_status(f"Error: {str(e)}"))
        except RuntimeError:
            # If we get a runtime error related to the main thread, try a different approach
            logger.error("RuntimeError in packet details thread, trying fallback")
            self.root.after(0, lambda: self.status_bar.set_status("Error: Could not get packet details. Try again."))
            
    def _display_packet_details(self, details):
        """Display packet details in the text widget without triggering selection events."""
        if not details:
            self.status_bar.set_status("No packet details available")
            return
            
        # Format details for display
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        # Add each layer of details
        for layer, layer_details in details.items():
            if layer == "Raw Data":
                self.details_text.insert(tk.END, f"\n=== {layer} ===\n", "heading")
                self.details_text.insert(tk.END, f"{layer_details}\n\n")
            else:
                self.details_text.insert(tk.END, f"\n=== {layer} Layer ===\n", "heading")
                
                if isinstance(layer_details, dict):
                    for field, value in layer_details.items():
                        self.details_text.insert(tk.END, f"{field}: ", "field")
                        self.details_text.insert(tk.END, f"{value}\n")
                else:
                    self.details_text.insert(tk.END, f"{layer_details}\n")
                    
        self.details_text.config(state=tk.DISABLED)
        self.status_bar.set_status("Packet details loaded")
            
    def _update_packet_details_ui(self, packet_index, details):
        """Update the UI with packet details (called in main thread)."""
        try:
            # Synchronize selection in other views if possible
            self.sync_selection(packet_index)
            
            # Show details in UI
            if not details:
                return
                
            # Format details for display
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            
            # Add each layer of details
            for layer, layer_details in details.items():
                if layer == "Raw Data":
                    self.details_text.insert(tk.END, f"\n=== {layer} ===\n", "heading")
                    self.details_text.insert(tk.END, f"{layer_details}\n\n")
                elif layer == "Error":
                    self.details_text.insert(tk.END, f"\n=== Error ===\n", "heading")
                    self.details_text.insert(tk.END, f"{layer_details}\n\n")
                else:
                    self.details_text.insert(tk.END, f"\n=== {layer} Layer ===\n", "heading")
                    
                    if isinstance(layer_details, dict):
                        for field, value in layer_details.items():
                            self.details_text.insert(tk.END, f"{field}: ", "field")
                            self.details_text.insert(tk.END, f"{value}\n")
                    else:
                        self.details_text.insert(tk.END, f"{layer_details}\n")
                        
            self.details_text.config(state=tk.DISABLED)
            
        except Exception as e:
            logger.error(f"Error updating packet details UI: {e}")
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, f"Error displaying packet details: {str(e)}")
            self.details_text.config(state=tk.DISABLED)
        
    # Removed human-readable view handler
        
    def sync_selection(self, packet_index):
        """Synchronize packet selection in the view without triggering selection events."""
        try:
            # Temporarily remove the selection event binding to prevent recursive calls
            self.adv_tree.unbind("<<TreeviewSelect>>")
            
            # Get items from the packet view
            adv_tree_items = self.adv_tree.get_children()
            
            # Find item with matching packet number
            adv_item = None
            
            # Search for matching item
            for item in adv_tree_items:
                values = self.adv_tree.item(item, "values")
                if values and int(values[0]) == packet_index + 1:
                    adv_item = item
                    break
                    
            # Select the item in the view
            if adv_item:
                self.adv_tree.selection_set(adv_item)
                self.adv_tree.see(adv_item)
            
            # Re-add the selection binding
            self.adv_tree.bind("<<TreeviewSelect>>", self.on_adv_packet_selected)
                
        except Exception as e:
            # Make sure to re-add binding even if an error occurs
            try:
                self.adv_tree.bind("<<TreeviewSelect>>", self.on_adv_packet_selected)
            except:
                pass
            logger.error(f"Error syncing selection: {e}")
            
    def show_packet_details(self, packet_index):
        """Show detailed information about a packet."""
        try:
            if packet_index < 0 or packet_index >= len(self.packet_capture.packets):
                return
                
            details = self.packet_capture.get_packet_details(packet_index)
            if not details:
                return
                
            # Format details for display
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            
            # Add each layer of details
            for layer, layer_details in details.items():
                if layer == "Raw Data":
                    self.details_text.insert(tk.END, f"\n=== {layer} ===\n", "heading")
                    self.details_text.insert(tk.END, f"{layer_details}\n\n")
                else:
                    self.details_text.insert(tk.END, f"\n=== {layer} Layer ===\n", "heading")
                    
                    if isinstance(layer_details, dict):
                        for field, value in layer_details.items():
                            self.details_text.insert(tk.END, f"{field}: ", "field")
                            self.details_text.insert(tk.END, f"{value}\n")
                    else:
                        self.details_text.insert(tk.END, f"{layer_details}\n")
                        
            self.details_text.config(state=tk.DISABLED)
            
        except Exception as e:
            logger.error(f"Error showing packet details: {e}")
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, f"Error displaying packet details: {str(e)}")
            self.details_text.config(state=tk.DISABLED)
            
    # Removed human-readable packet explanation
            
    def apply_filters(self):
        """Apply filters to the packet display."""
        protocol_filter = self.protocol_filter.get()
        ip_filter = self.ip_filter.get().strip()
        port_filter = self.port_filter.get().strip()
        
        # Clear current display
        self.clear_packet_display()
        
        # Apply filters to all packet info
        filtered_info = []
        
        for packet_info in self.all_packet_info:
            # Protocol filter
            if protocol_filter != "All":
                protocol = packet_info.get('protocol', '')
                if protocol_filter.lower() not in protocol.lower():
                    continue
                    
            # IP filter
            if ip_filter:
                src = packet_info.get('src', '')
                dst = packet_info.get('dst', '')
                if ip_filter not in src and ip_filter not in dst:
                    continue
                    
            # Port filter
            if port_filter:
                port_info = packet_info.get('port_info', '')
                if port_filter not in port_info:
                    continue
                    
            # Packet passes all filters
            filtered_info.append(packet_info)
            
        # Update filtered packets
        self.filtered_packets = filtered_info
        
        # Display filtered packets
        self.add_packets_to_display(filtered_info)
        
        # Update status
        self.status_bar.set_status(f"Filtered: {len(filtered_info)} packets match the filter criteria")
        
    def clear_filters(self):
        """Clear all filters and show all packets."""
        # Reset filter fields
        self.protocol_filter.set("All")
        self.ip_filter.delete(0, tk.END)
        self.port_filter.delete(0, tk.END)
        
        # Clear current display
        self.clear_packet_display()
        
        # Show all packets
        self.filtered_packets = self.all_packet_info.copy()
        self.add_packets_to_display(self.all_packet_info)
        
        # Update status
        self.status_bar.set_status(f"Filters cleared. Showing all {len(self.all_packet_info)} packets")
        
    def save_packets(self):
        """Save packets to a file."""
        if not self.packet_capture.packets:
            messagebox.showinfo("No Data", "No packets to save.")
            return
            
        # Ask for save type
        save_type = messagebox.askquestion("Save Type", "Do you want to save as PCAP? Select 'No' for CSV format.")
        
        if save_type == 'yes':
            # Save as PCAP
            filename = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
            )
            
            if not filename:
                return
                
            error = self.packet_capture.save_packets_to_pcap(filename)
            if error:
                messagebox.showerror("Save Error", f"Failed to save PCAP file: {error}")
            else:
                messagebox.showinfo("Save Complete", f"Saved {len(self.packet_capture.packets)} packets to {filename}")
                
        else:
            # Save as CSV
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            
            if not filename:
                return
                
            # Determine what to save - filtered or all packets
            packets_to_save = self.filtered_packets if self.filtered_packets else self.all_packet_info
            
            error = self.packet_capture.save_packets_to_csv(filename, packets_to_save)
            if error:
                messagebox.showerror("Save Error", f"Failed to save CSV file: {error}")
            else:
                messagebox.showinfo("Save Complete", f"Saved {len(packets_to_save)} packets to {filename}")
                
    def load_packets(self):
        """Load packets from a PCAP file."""
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if not filename:
            return
            
        # Stop any ongoing capture
        if self.is_capturing:
            self.stop_capture()
            
        # Clear current display
        self.clear_packet_display()
        self.all_packet_info = []
        self.packet_count = 0
        
        # Show loading indicator
        self.status_bar.set_status(f"Loading packets from {filename}...")
        self.status_bar.set_progress_mode("indeterminate")
        self.status_bar.start_progress()
        
        def load_thread():
            try:
                # Load packets in a separate thread to avoid blocking the UI
                processed_packets = self.packet_capture.load_packets_from_pcap(filename)
                
                if processed_packets:
                    # Update UI on the main thread
                    self.root.after(0, lambda: self.handle_loaded_packets(processed_packets, filename))
                else:
                    # Show error on the main thread
                    self.root.after(0, lambda: messagebox.showerror("Load Error", f"Failed to load packets from {filename}"))
                    self.root.after(0, lambda: self.status_bar.set_status("Failed to load packets"))
                    self.root.after(0, lambda: self.status_bar.stop_progress())
                    self.root.after(0, lambda: self.status_bar.set_progress_mode("determinate"))
                    
            except Exception as e:
                # Show error on the main thread
                self.root.after(0, lambda: messagebox.showerror("Load Error", f"Error loading packets: {str(e)}"))
                self.root.after(0, lambda: self.status_bar.set_status("Error loading packets"))
                self.root.after(0, lambda: self.status_bar.stop_progress())
                self.root.after(0, lambda: self.status_bar.set_progress_mode("determinate"))
                
        # Start loading thread
        threading.Thread(target=load_thread, daemon=True).start()
        
    def handle_loaded_packets(self, processed_packets, filename):
        """Handle loaded packets from a PCAP file."""
        # Update packet info
        self.all_packet_info = processed_packets
        
        # Display packets
        self.add_packets_to_display(processed_packets)
        
        # Update status
        self.status_bar.set_status(f"Loaded {len(processed_packets)} packets from {filename}")
        self.status_bar.stop_progress()
        self.status_bar.set_progress_mode("determinate")
        
        # Update stats
        self.update_stats()
        
        # Update dashboards
        self.update_dashboard_data()
        
    def export_to_pdf(self):
        """Export statistics and visualizations to a PDF report."""
        if not self.packet_capture.packets:
            messagebox.showinfo("No Data", "No packets to export.")
            return
            
        # Ask for filename
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if not filename:
            return
            
        # Show loading indicator
        self.status_bar.set_status("Generating PDF report...")
        self.status_bar.set_progress_mode("indeterminate")
        self.status_bar.start_progress()
        
        def export_thread():
            try:
                # Get protocol count for the report
                protocol_count = {}
                for proto, count in self.packet_capture.stats.items():
                    if count > 0:
                        protocol_count[proto.upper()] = count
                        
                # Generate PDF
                result = export_to_pdf(protocol_count, self.selected_interface, filename)
                
                if result:
                    # Show success on the main thread
                    self.root.after(0, lambda: messagebox.showinfo("Export Complete", f"Report saved to {filename}"))
                    self.root.after(0, lambda: self.status_bar.set_status(f"Report exported to {filename}"))
                    
                    # Ask if the user wants to open the PDF
                    self.root.after(0, lambda: self.ask_to_open_pdf(filename))
                else:
                    # Show error on the main thread
                    self.root.after(0, lambda: messagebox.showerror("Export Error", "Failed to generate PDF report"))
                    self.root.after(0, lambda: self.status_bar.set_status("Failed to export report"))
                    
            except Exception as e:
                # Show error on the main thread
                self.root.after(0, lambda: messagebox.showerror("Export Error", f"Error exporting report: {str(e)}"))
                self.root.after(0, lambda: self.status_bar.set_status("Error exporting report"))
                
            finally:
                # Reset status bar
                self.root.after(0, lambda: self.status_bar.stop_progress())
                self.root.after(0, lambda: self.status_bar.set_progress_mode("determinate"))
                
        # Start export thread
        threading.Thread(target=export_thread, daemon=True).start()
        
    def ask_to_open_pdf(self, filename):
        """Ask the user if they want to open the PDF."""
        open_now = messagebox.askyesno("Export Complete", "Do you want to open the report now?")
        if open_now:
            try:
                if platform.system() == 'Windows':
                    os.startfile(filename)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.run(['open', filename], check=True)
                else:  # Linux
                    subprocess.run(['xdg-open', filename], check=True)
            except Exception as e:
                messagebox.showerror("Open Error", f"Failed to open PDF: {str(e)}")
                
    def change_interface(self):
        """Change the network interface for capture."""
        if self.is_capturing:
            messagebox.showinfo("Cannot Change Interface", "Please stop capture before changing interfaces.")
            return
            
        # Get available interfaces
        interfaces = get_available_interfaces()
        
        # Show interface selector
        self.interface_selector = InterfaceSelector(self.root, interfaces, self.on_interface_changed)
        
    def on_interface_changed(self, interface):
        """Handle interface change."""
        self.selected_interface = interface
        self.packet_capture.selected_interface = interface
        self.status_bar.set_status(f"Interface changed to {interface}")
        
    def show_about(self):
        """Show the about dialog."""
        # Create and show about dialog with static network diagram
        dialog = AboutDialog(
            self.root, 
            "Network Analysis Tool", 
            "1.0", 
            "A network traffic analysis and monitoring toolkit for capturing and analyzing packets."
        )
        # Dialog is modal, so it will block until closed
        
    def toggle_theme(self):
        """Toggle between dark and light mode."""
        try:
            if self.dark_mode:
                # Switch to light mode
                self.dark_mode = False
                self.theme_var.set("☀️ Light Mode")
                self.current_theme = "flatly"  # Light theme
                self.style.theme_use(self.current_theme)
            else:
                # Switch to dark mode
                self.dark_mode = True
                self.theme_var.set("🌙 Dark Mode")
                self.current_theme = "darkly"  # Dark theme
                self.style.theme_use(self.current_theme)
                
            # Update theme colors
            self.theme_colors = get_theme_colors(self.current_theme)
            
            # Update UI elements that depend on theme
            configure_treeview_style(self.style)
            
            # Force redraw of elements
            self.root.update_idletasks()
            
        except Exception as e:
            logger.error(f"Error toggling theme: {e}")
            messagebox.showerror("Theme Error", f"Could not change theme: {str(e)}")
        
    def on_closing(self):
        """Handle window closing."""
        if self.is_capturing:
            if messagebox.askyesno("Confirm Exit", "A capture is in progress. Are you sure you want to exit?"):
                self.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()
