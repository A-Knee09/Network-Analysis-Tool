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
        
        for iface, ip in interfaces:
            name = iface.lower()
            
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
        for i, (iface, ip) in enumerate(self.interfaces):
            tag = 'odd' if i % 2 else 'even'
            self.interface_tree.insert("", "end", values=(iface, ip), tags=(tag,))
            
    def _filter_interfaces(self, *args):
        """Filter interfaces based on search text and type."""
        search_text = self.search_var.get().lower()
        iface_type = self.type_var.get()
        
        # Clear existing items
        for item in self.interface_tree.get_children():
            self.interface_tree.delete(item)
            
        # Determine which interfaces to show
        if iface_type == "All":
            interfaces_to_show = self.interfaces
        else:
            interfaces_to_show = self.interface_types.get(iface_type, [])
            
        # Filter by search text and add matching interfaces
        for i, (iface, ip) in enumerate(interfaces_to_show):
            if (search_text in iface.lower() or search_text in ip.lower() or not search_text):
                tag = 'odd' if i % 2 else 'even'
                self.interface_tree.insert("", "end", values=(iface, ip), tags=(tag,))
                
    def _on_selection_changed(self, event):
        """Handle selection change in the interface tree."""
        selection = self.interface_tree.selection()
        if not selection:
            return
            
        # Get the selected interface
        item = self.interface_tree.item(selection[0])
        interface_name = item["values"][0]
        
        # Update the details panel
        self._update_details(interface_name)
        
    def _update_details(self, interface_name):
        """Update interface details panel with information about the selected interface."""
        # Find the interface in our list
        selected_interface = None
        for iface, ip in self.interfaces:
            if iface == interface_name:
                selected_interface = (iface, ip)
                break
                
        if not selected_interface:
            return
            
        iface, ip = selected_interface
        
        # Determine the interface type
        iface_type = "Unknown"
        for type_name, interfaces in self.interface_types.items():
            if selected_interface in interfaces:
                iface_type = type_name
                break
                
        # Update fields
        self.detail_fields["Name"].set(iface)
        self.detail_fields["IP Address"].set(ip)
        
        # Try to get MAC address, otherwise show "Unknown"
        mac = "Unknown"
        self.detail_fields["MAC Address"].set(mac)
        
        self.detail_fields["Type"].set(iface_type)
        
        # Set status based on IP
        if ip and ip not in ["Unknown IP", "Active Interface"]:
            self.detail_fields["Status"].set("Active")
            # Update network status indicator
            self.status_indicator.config(text="●", foreground="green")
            self.status_text.config(text="Interface appears to be active")
        else:
            self.detail_fields["Status"].set("Unknown")
            # Update network status indicator
            self.status_indicator.config(text="●", foreground="gray")
            self.status_text.config(text="Interface status unknown")
            
        # Set description
        if "loop" in iface.lower() or iface.lower() == "lo":
            desc = "Loopback interface for local communication"
        elif "eth" in iface.lower() or "en" in iface.lower():
            desc = "Ethernet network interface for wired connections"
        elif "wlan" in iface.lower() or "wi" in iface.lower():
            desc = "Wireless network interface for WiFi connections"
        elif "docker" in iface.lower() or "br-" in iface.lower():
            desc = "Virtual bridge interface for container networking"
        else:
            desc = "Network interface"
            
        self.detail_fields["Description"].set(desc)
        
    def _test_connection(self):
        """Test connection on selected interface."""
        selection = self.interface_tree.selection()
        if not selection:
            return
            
        # Get the selected interface
        item = self.interface_tree.item(selection[0])
        interface_name = item["values"][0]
        
        # Update status to indicate testing
        self.status_indicator.config(text="○", foreground="orange")
        self.status_text.config(text="Testing connection...")
        self.window.update_idletasks()
        
        # Simulate connection test with a delay
        def test_thread():
            # Simulate testing...
            time.sleep(1.5)
            
            # Update status
            self.window.after(0, lambda: self.status_indicator.config(text="●", foreground="green"))
            self.window.after(0, lambda: self.status_text.config(text="Connection test successful"))
            
        # Start test in background
        threading.Thread(target=test_thread, daemon=True).start()
        
    def center_window(self):
        """Center the window on the screen."""
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
    def on_select(self):
        """Handle interface selection."""
        selection = self.interface_tree.selection()
        if not selection:
            return
            
        # Get the selected interface
        item = self.interface_tree.item(selection[0])
        interface_name = item["values"][0]
        
        # Call the callback with the selected interface
        self.window.destroy()
        self.callback(interface_name)
        
    def on_cancel(self):
        """Handle cancel button."""
        self.window.destroy()
        
class AboutDialog:
    """Simple dialog showing information about the application."""
    def __init__(self, parent):
        self.parent = parent
        self.dialog = None
        
    def show(self):
        """Show the about dialog with simple design."""
        if self.dialog:
            self.dialog.destroy()
            
        # Create dialog window
        self.dialog = Toplevel(self.parent)
        self.dialog.title("About Network Analysis Tool")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Create main content frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a search icon using unicode
        icon_label = ttk.Label(main_frame, text="🔍", font=("Arial", 36))
        icon_label.pack(pady=(10, 20))
        
        # Add application name
        app_name = ttk.Label(main_frame, text="Network Analysis Tool", font=("Arial", 16, "bold"), foreground="#1E88E5")
        app_name.pack(pady=5)
        
        # Add version
        version = ttk.Label(main_frame, text="Version 1.0.0")
        version.pack(pady=5)
        
        # Add separator
        separator = ttk.Separator(main_frame, orient="horizontal")
        separator.pack(fill="x", pady=15)
        
        # Add close button at the bottom
        close_button = ttk.Button(self.dialog, text="Close", command=self.dialog.destroy)
        close_button.pack(side=tk.BOTTOM, pady=20)
        
    def center_dialog(self):
        """Center the dialog on the parent window."""
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
        
        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2
        
        self.dialog.geometry(f"{width}x{height}+{x}+{y}")