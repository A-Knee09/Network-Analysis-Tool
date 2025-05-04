"""
Component module - reusable UI components for the network analyzer
"""

import tkinter as tk
from tkinter import ttk, StringVar, Toplevel, BooleanVar
import threading
from ttkbootstrap import Style
import time
import random
import math
import logging
import platform
import os

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def create_tooltip(widget, text):
    """Create a tooltip for a given widget with improved behavior."""
    tooltip = None
    delay_id = None
    
    def delayed_show(event=None):
        nonlocal tooltip
        
        # Get position relative to widget
        x = widget.winfo_rootx() + 20
        y = widget.winfo_rooty() + widget.winfo_height() + 5
        
        # Create tooltip window with nice style
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)  # No decorations
        tooltip.wm_geometry(f"+{x}+{y}")
        
        # Create frame with border and padding
        frame = tk.Frame(tooltip, bg="#ffffcc", bd=1, relief="solid")
        frame.pack(fill="both", expand=True)
        
        # Create label with text
        label = tk.Label(
            frame, 
            text=text, 
            justify=tk.LEFT,
            bg="#ffffcc", 
            padx=10, 
            pady=6,
            wraplength=300
        )
        label.pack()
        
    def hide(event=None):
        nonlocal tooltip, delay_id
        if delay_id:
            widget.after_cancel(delay_id)
            delay_id = None
        if tooltip:
            tooltip.destroy()
            tooltip = None
            
    def on_enter(event):
        nonlocal delay_id
        hide()  # Hide any existing tooltips
        delay_id = widget.after(500, delayed_show)  # Show after delay
            
    # Bind events to widget
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", hide)
    widget.bind("<ButtonPress>", hide)
    
    return tooltip
            

class StatusBar(ttk.Frame):
    """Status bar component with progress indicator and status message."""
    def __init__(self, parent):
        super().__init__(parent)
        
        # Create a frame for the status bar
        self.config(relief="sunken", padding=(10, 5))
        self.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status message
        self.status_var = StringVar()
        self.status_label = ttk.Label(self, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            self, 
            mode="determinate", 
            length=200, 
            maximum=100
        )
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Set initial status
        self.set_status("Ready")
        
    def set_status(self, message):
        """Set the status message."""
        self.status_var.set(message)
        self.update()
        
    def set_progress(self, value):
        """Set the progress bar value (0-100)."""
        self.progress["value"] = value
        self.update()
        
    def set_progress_mode(self, mode):
        """Set the progress bar mode (determinate or indeterminate)."""
        self.progress["mode"] = mode
        self.update()
        
    def start_progress(self):
        """Start the progress bar animation."""
        self.progress.start()
        
    def stop_progress(self):
        """Stop the progress bar animation."""
        self.progress.stop()


class InterfaceSelector:
    """A dialog for selecting network interfaces with enhanced features."""
    def __init__(self, parent, interfaces, callback):
        self.parent = parent
        self.interfaces = interfaces
        self.callback = callback
        self.interface_types = self._classify_interfaces(interfaces)
        
        # Create a new window with improved dimensions
        self.window = Toplevel(parent)
        self.window.title("Select Network Interface")
        self.window.geometry("850x550")  # Increased for better visibility
        self.window.minsize(750, 500)    # Larger minimum size
        self.window.resizable(True, True)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Make it modal
        self.window.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        # Main frame with padding
        self.frame = ttk.Frame(self.window, padding=20)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Title with icon
        title_frame = ttk.Frame(self.frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            title_frame, 
            text="🌐",
            font=("Segoe UI", 24)
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(
            title_frame,
            text="Select a Network Interface",
            font=("Segoe UI", 16, "bold")
        ).pack(side=tk.LEFT)
        
        # Search and filter
        filter_frame = ttk.Frame(self.frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search box
        search_frame = ttk.Frame(filter_frame)
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_var = StringVar()
        self.search_var.trace("w", self._filter_interfaces)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Interface type filter
        type_frame = ttk.Frame(filter_frame)
        type_frame.pack(side=tk.LEFT, padx=(20, 0))
        
        ttk.Label(type_frame, text="Interface Type:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.type_var = StringVar(value="All")
        self.type_combo = ttk.Combobox(
            type_frame,
            textvariable=self.type_var,
            values=["All"] + list(self.interface_types.keys()),
            state="readonly",
            width=15
        )
        self.type_combo.pack(side=tk.LEFT)
        self.type_combo.bind("<<ComboboxSelected>>", self._filter_interfaces)
        
        # Content - split into left and right panels
        content_frame = ttk.Frame(self.frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left side - Interface list
        list_frame = ttk.LabelFrame(content_frame, text="Available Interfaces")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Scrollable list
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview for interfaces
        self.interface_tree = ttk.Treeview(
            list_frame,
            columns=("Interface", "IP"),
            show="headings",
            selectmode="browse",
            height=10
        )
        self.interface_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure scrollbar
        scrollbar.config(command=self.interface_tree.yview)
        self.interface_tree.config(yscrollcommand=scrollbar.set)
        
        # Configure columns
        self.interface_tree.heading("Interface", text="Interface")
        self.interface_tree.heading("IP", text="IP Address")
        self.interface_tree.column("Interface", width=250)
        self.interface_tree.column("IP", width=150)
        
        # Color alternating rows
        self.interface_tree.tag_configure('odd', background='#f5f5f5')
        self.interface_tree.tag_configure('even', background='#ffffff')
        
        # Right side - Interface details panel
        self.details_frame = ttk.LabelFrame(content_frame, text="Interface Details")
        self.details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Details content
        self.details_content = ttk.Frame(self.details_frame, padding=10)
        self.details_content.pack(fill=tk.BOTH, expand=True)
        
        # Details fields
        self.detail_fields = {
            "Name": StringVar(value="Select an interface"),
            "IP Address": StringVar(value="-"),
            "MAC Address": StringVar(value="-"),
            "Type": StringVar(value="-"),
            "Status": StringVar(value="-"),
            "Description": StringVar(value="-")
        }
        
        # Create labels for each field
        row = 0
        for field, var in self.detail_fields.items():
            ttk.Label(
                self.details_content, 
                text=f"{field}:", 
                font=("Segoe UI", 10, "bold"),
                width=15,
                anchor=tk.W
            ).grid(row=row, column=0, sticky=tk.W, pady=5)
            
            ttk.Label(
                self.details_content,
                textvariable=var,
                wraplength=250
            ).grid(row=row, column=1, sticky=tk.W, pady=5)
            
            row += 1
            
        # Network status visualization
        self.status_frame = ttk.LabelFrame(self.details_content, text="Network Status")
        self.status_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(15, 0))
        
        self.status_indicator = ttk.Label(self.status_frame, text="○", foreground="gray", font=("Segoe UI", 14))
        self.status_indicator.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.status_text = ttk.Label(self.status_frame, text="Select an interface", wraplength=250)
        self.status_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Bind selection event
        self.interface_tree.bind("<<TreeviewSelect>>", self._on_selection_changed)
        self.interface_tree.bind("<Double-1>", lambda e: self.on_select())
        
        # Populate the tree
        self._populate_interface_list()
        
        # Button frame
        button_frame = ttk.Frame(self.frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        # Remember interface
        self.remember_var = tk.BooleanVar(value=False)
        remember_cb = ttk.Checkbutton(
            button_frame,
            text="Remember my selection",
            variable=self.remember_var
        )
        remember_cb.pack(side=tk.LEFT)
        
        # Cancel button
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.on_cancel
        ).pack(side=tk.RIGHT, padx=5)
        
        # Select button
        ttk.Button(
            button_frame,
            text="Select Interface",
            style="primary.TButton",
            command=self.on_select
        ).pack(side=tk.RIGHT, padx=5)
        
        # Test connection button
        self.test_button = ttk.Button(
            button_frame,
            text="Test Connection",
            command=self._test_connection
        )
        self.test_button.pack(side=tk.RIGHT, padx=5)
        
        # Center the window on the screen
        self.center_window()
        
        # Set focus to search entry
        self.search_entry.focus_set()
        
    def _classify_interfaces(self, interfaces):
        """Classify interfaces into types based on name patterns."""
        types = {
            "Ethernet": [],
            "WiFi": [],
            "Virtual": [],
            "Loopback": [],
            "Other": []
        }
        
        for iface_info in interfaces:
            # Handle both string and tuple formats
            if isinstance(iface_info, tuple) and len(iface_info) >= 2:
                iface, ip = iface_info
            else:
                iface = iface_info
                ip = "Unknown IP"
                
            name = str(iface).lower()
            
            if name == "lo" or "loop" in name:
                types["Loopback"].append((iface, ip))
            elif name.startswith(("eth", "en")) or "ethernet" in name:
                types["Ethernet"].append((iface, ip))
            elif name.startswith(("wlan", "wi", "wlp")) or "wireless" in name:
                types["WiFi"].append((iface, ip)) 
            elif any(x in name for x in ["vir", "vbox", "vmnet", "docker", "br-", "veth"]):
                types["Virtual"].append((iface, ip))
            else:
                types["Other"].append((iface, ip))
                
        return types
    
    def _populate_interface_list(self):
        """Populate the interface list with available interfaces."""
        # Clear existing items
        for item in self.interface_tree.get_children():
            self.interface_tree.delete(item)
            
        # Add interfaces
        for i, iface_info in enumerate(self.interfaces):
            tag = 'odd' if i % 2 else 'even'
            
            # Handle both string and tuple formats
            if isinstance(iface_info, tuple) and len(iface_info) >= 2:
                iface, ip = iface_info
            else:
                iface = iface_info
                ip = "Unknown IP"
                
            self.interface_tree.insert("", "end", values=(iface, ip), tags=(tag,))
            
    def _filter_interfaces(self, *args):
        """Filter interfaces based on search text and type."""
        search_text = self.search_var.get().lower()
        iface_type = self.type_var.get()
        
        # Clear existing items
        for item in self.interface_tree.get_children():
            self.interface_tree.delete(item)
            
        # Get filtered interfaces
        filtered_interfaces = []
        
        if iface_type == "All":
            # Use all interfaces
            for type_interfaces in self.interface_types.values():
                filtered_interfaces.extend(type_interfaces)
        else:
            # Use only interfaces of the selected type
            filtered_interfaces = self.interface_types.get(iface_type, [])
            
        # Apply search filter
        if search_text:
            filtered_interfaces = [
                (iface, ip) for iface, ip in filtered_interfaces
                if search_text in str(iface).lower() or search_text in str(ip).lower()
            ]
            
        # Add filtered interfaces to tree
        for i, (iface, ip) in enumerate(filtered_interfaces):
            tag = 'odd' if i % 2 else 'even'
            self.interface_tree.insert("", "end", values=(iface, ip), tags=(tag,))
            
    def _on_selection_changed(self, event):
        """Handle interface selection change."""
        selection = self.interface_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.interface_tree.item(item, "values")
        if not values:
            return
            
        # Get interface name and IP
        iface = values[0]
        ip = values[1]
        
        # Update detail fields
        self.detail_fields["Name"].set(iface)
        self.detail_fields["IP Address"].set(ip)
        
        # Determine interface type
        if str(iface).lower() == "lo" or "loop" in str(iface).lower():
            iface_type = "Loopback"
        elif str(iface).lower().startswith(("eth", "en")) or "ethernet" in str(iface).lower():
            iface_type = "Ethernet"
        elif str(iface).lower().startswith(("wlan", "wi", "wlp")) or "wireless" in str(iface).lower():
            iface_type = "WiFi"
        elif any(x in str(iface).lower() for x in ["vir", "vbox", "vmnet", "docker", "br-", "veth"]):
            iface_type = "Virtual"
        else:
            iface_type = "Other"
            
        self.detail_fields["Type"].set(iface_type)
        
        # Set MAC address (simulated for now)
        mac_address = self._get_mac_address(iface)
        self.detail_fields["MAC Address"].set(mac_address)
        
        # Set status based on IP
        if ip and ip != "Unknown IP":
            self.detail_fields["Status"].set("Active")
            self.status_indicator.config(text="●", foreground="green")
            self.status_text.config(text="Interface is active and has an IP address")
        else:
            self.detail_fields["Status"].set("Unknown")
            self.status_indicator.config(text="●", foreground="orange")
            self.status_text.config(text="Interface status is unknown")
            
        # Set description based on type
        descriptions = {
            "Ethernet": "Wired network interface for connecting to networks via Ethernet cable",
            "WiFi": "Wireless network interface for connecting to WiFi networks",
            "Loopback": "Loopback interface for local communications within the device",
            "Virtual": "Virtual network interface for containerization or virtualization",
            "Other": "Network interface of unspecified type"
        }
        
        self.detail_fields["Description"].set(descriptions.get(iface_type, "Network interface"))
        
    def _get_mac_address(self, iface):
        """Get MAC address for an interface (simulated)."""
        # In a real implementation, this would use platform-specific commands to get the actual MAC
        # For now, generate a consistent pseudo-MAC based on the interface name
        try:
            # Use a hash of the interface name to generate a consistent pseudo-MAC
            import hashlib
            hash_obj = hashlib.md5(str(iface).encode())
            hash_digest = hash_obj.hexdigest()
            
            # Format as a MAC address (first 12 characters of the hash)
            mac = ':'.join([hash_digest[i:i+2] for i in range(0, 12, 2)])
            return mac
        except Exception as e:
            logger.error(f"Error generating MAC address: {e}")
            return "Unknown MAC"
        
    def _test_connection(self):
        """Test the selected interface."""
        selection = self.interface_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.interface_tree.item(item, "values")
        if not values:
            return
            
        # Get interface name
        iface = values[0]
        
        # Update status
        self.status_indicator.config(text="◉", foreground="orange")
        self.status_text.config(text="Testing connection...")
        self.status_frame.update()
        
        # Simulate connection test (brief delay)
        def test_thread():
            time.sleep(1)  # Simulate network test
            
            # Update UI in main thread
            self.window.after(0, self._update_test_result, iface)
            
        threading.Thread(target=test_thread, daemon=True).start()
        
    def _update_test_result(self, iface):
        """Update test result in UI thread."""
        # In a real implementation, this would check if the interface can be used for packet capture
        # For now, assume success except for virtual interfaces
        is_virtual = any(x in str(iface).lower() for x in ["vir", "vbox", "vmnet", "docker", "br-", "veth"])
        
        if is_virtual:
            self.status_indicator.config(text="●", foreground="orange")
            self.status_text.config(text="This is a virtual interface and may have limited functionality")
        else:
            self.status_indicator.config(text="●", foreground="green")
            self.status_text.config(text="Interface is ready for packet capture")
        
    def center_window(self):
        """Center the window on the screen."""
        self.window.update_idletasks()
        
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        
        # Get screen dimensions
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        # Calculate position
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        # Set position
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
    def on_select(self):
        """Handle interface selection."""
        selection = self.interface_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.interface_tree.item(item, "values")
        if not values:
            return
            
        # Get selected interface
        interface = values[0]
        
        # Store preference if requested
        if self.remember_var.get():
            try:
                # Save to preferences file
                with open("interface_preference.txt", "w") as f:
                    f.write(interface)
            except Exception as e:
                logger.error(f"Error saving interface preference: {e}")
        
        # Call callback with selected interface
        self.window.destroy()
        self.callback(interface)
        
    def on_cancel(self):
        """Handle cancel."""
        self.window.destroy()
        
        # If no interface will be selected, use a default
        if self.callback:
            # Try to find a non-loopback interface
            default_interface = None
            for interfaces in self.interface_types.values():
                if interfaces and "loopback" not in str(interfaces[0][0]).lower():
                    default_interface = interfaces[0][0]
                    break
                    
            # If no non-loopback found, use the first one
            if not default_interface and self.interfaces:
                if isinstance(self.interfaces[0], tuple):
                    default_interface = self.interfaces[0][0]
                else:
                    default_interface = self.interfaces[0]
                    
            if default_interface:
                self.callback(default_interface)


class AboutDialog:
    """About dialog with application information and animated GIF."""
    def __init__(self, parent, app_name, version, description):
        # Create the about dialog window
        self.window = tk.Toplevel(parent)
        self.window.title("About")
        self.window.geometry("700x550")
        self.window.minsize(700, 550)
        self.window.resizable(True, True)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Make it modal
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        
        # Main frame with padding
        self.frame = ttk.Frame(self.window, padding=20)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a horizontal layout frame
        content_frame = ttk.Frame(self.frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Left side - Network animation with frame border (sized to match animation)
        # We'll adjust the frame size after we know the animation dimensions
        icon_frame = ttk.Frame(content_frame, borderwidth=2, relief="groove", padding=10)
        icon_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        # Create a label for the GIF animation
        self.animation_label = ttk.Label(icon_frame)
        self.animation_label.pack(padx=5, pady=5)
        
        # Load and display the GIF animation
        try:
            # Load the GIF file
            self.gif_path = "assets/about_animation4.gif"
            self.gif_frames = []
            self.current_frame = 0
            
            # Open the GIF
            try:
                from PIL import Image, ImageTk
                
                # Check if file exists
                if os.path.exists(self.gif_path):
                    gif = Image.open(self.gif_path)
                    
                    # Define desired size (smaller than original)
                    max_width = 300  # Set maximum width
                    max_height = 300  # Set maximum height
                    
                    # Get original size
                    original_width, original_height = gif.size
                    
                    # Calculate scaling factor to maintain aspect ratio
                    width_ratio = max_width / original_width
                    height_ratio = max_height / original_height
                    scaling_factor = min(width_ratio, height_ratio)
                    
                    # Calculate new dimensions
                    new_width = int(original_width * scaling_factor)
                    new_height = int(original_height * scaling_factor)
                    
                    # Get all frames and resize them
                    for i in range(0, gif.n_frames):
                        gif.seek(i)
                        # Resize the frame while maintaining aspect ratio
                        resized_frame = gif.copy().resize((new_width, new_height), Image.LANCZOS)
                        frame = ImageTk.PhotoImage(resized_frame)
                        self.gif_frames.append(frame)
                    
                    # Start animation
                    self.animate_gif()
                else:
                    # If the file doesn't exist, show a placeholder message
                    self.animation_label.configure(text=f"Animation file not found:\n{self.gif_path}")
                    
            except ImportError:
                # Fallback if PIL is not available
                self.animation_label.configure(text="GIF Animation\n(requires PIL)")
                
        except Exception as e:
            # Fallback to a static label if the GIF can't be loaded
            self.animation_label.configure(text=f"Network Analyzer\n(Animation error: {str(e)})")
            
        # Right side - Text content
        self.text_frame = ttk.Frame(content_frame)
        self.text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Store parameters
        self.app_name = app_name
        self.version = version
        self.description = description
        
        # Application name
        ttk.Label(
            self.text_frame,
            text=self.app_name,
            font=("Segoe UI", 16, "bold"),
            justify=tk.CENTER
        ).pack(pady=(0, 5), fill=tk.X)
        
        # Version
        ttk.Label(
            self.text_frame,
            text=f"Version {self.version}",
            font=("Segoe UI", 10),
            justify=tk.CENTER
        ).pack(pady=(0, 10), fill=tk.X)
        
        # Description - either use provided description or default
        description_text = "Network Analysis Tool developed for final year project. Originally created in December 2024 as a tkinter and networking learning project and later enhanced for academic submission.\n\nThis tool analyzes network traffic, captures packets, and provides visualizations for network monitoring and security analysis.\n\n Made with pain tears and frustration by A-knee09 (Anirudh Saksena) :D"
        
        description_label = ttk.Label(
            self.text_frame,
            text=description_text,
            wraplength=320,
            justify=tk.LEFT
        )
        description_label.pack(pady=(0, 20), anchor=tk.W, fill=tk.X)
        
        # Tech stack section
        ttk.Label(
            self.text_frame,
            text="Tech Stack:",
            font=("Segoe UI", 10, "bold")
        ).pack(pady=(5, 5), anchor=tk.W)
        
        tech_stack = ttk.Frame(self.text_frame, relief=tk.GROOVE, borderwidth=2, padding=10)
        tech_stack.pack(fill=tk.X, pady=(0, 10), anchor=tk.W, padx=5)
        
        ttk.Label(tech_stack, text="• Python").pack(anchor=tk.W)
        ttk.Label(tech_stack, text="• Tkinter/ttk").pack(anchor=tk.W)
        ttk.Label(tech_stack, text="• Matplotlib").pack(anchor=tk.W)
        ttk.Label(tech_stack, text="• Kamene (Scapy fork)").pack(anchor=tk.W)
        ttk.Label(tech_stack, text="• FPDF").pack(anchor=tk.W)
        
        # System info
        ttk.Label(
            self.text_frame,
            text="System Information:",
            font=("Segoe UI", 10, "bold")
        ).pack(pady=(5, 5), anchor=tk.W)
        
        ttk.Label(
            self.text_frame,
            text=f"OS: {platform.system()} {platform.release()}",
        ).pack(anchor=tk.W)
        
        ttk.Label(
            self.text_frame,
            text=f"Python: {platform.python_version()}",
        ).pack(anchor=tk.W)
        
        # Close button
        ttk.Button(
            self.frame,
            text="Close",
            command=self.close,
            width=15
        ).pack(side=tk.BOTTOM, pady=(20, 0))
        
        # Center the window
        self.center_window()
    
    def animate_gif(self):
        """Animate the GIF by cycling through frames."""
        if self.gif_frames:
            # Update the label with the next frame
            self.animation_label.configure(image=self.gif_frames[self.current_frame])
            
            # On first frame, adjust the frame size to match the animation size with padding
            if self.current_frame == 0 and hasattr(self, 'animation_adjusted') == False:
                # Get the size of the first frame (all frames have the same size)
                img_width = self.gif_frames[0].width()
                img_height = self.gif_frames[0].height()
                
                # Set a fixed width and height for the frame with some padding
                padding = 20  # Padding around the animation (10px on each side)
                frame_width = img_width + padding
                frame_height = img_height + padding
                
                # Force the animation label and its parent frame to a fixed size
                # For ttk frames, we need to use width and height options directly
                self.animation_label.master['width'] = frame_width
                self.animation_label.master['height'] = frame_height
                self.animation_label.master.pack_propagate(False)  # Prevent parent from shrinking
                
                # Mark as adjusted so we don't do this again
                self.animation_adjusted = True
            
            # Move to the next frame (loop if at the end)
            self.current_frame = (self.current_frame + 1) % len(self.gif_frames)
            
            # Schedule the next frame update
            self.window.after(100, self.animate_gif)  # Update every 100ms
    
    def center_window(self):
        """Center the window on the parent."""
        self.window.update_idletasks()
        
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        
        parent_x = self.window.master.winfo_rootx()
        parent_y = self.window.master.winfo_rooty()
        parent_width = self.window.master.winfo_width()
        parent_height = self.window.master.winfo_height()
        
        # Calculate position
        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2
        
        # Set position
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
    def close(self):
        """Close the dialog."""
        self.window.destroy()
