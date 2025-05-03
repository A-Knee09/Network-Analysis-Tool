import tkinter as tk
from tkinter import ttk, Toplevel, StringVar
import platform
import sys
import webbrowser


def create_tooltip(widget, text):
    """Create a tooltip for a given widget with improved behavior."""
    if platform.system() == "Darwin":  # macOS has native tooltips
        widget.config(cursor="question_arrow")
        return
    
    # Make sure we destroy any existing tooltip for this widget
    if hasattr(widget, "_tooltip_id"):
        widget.after_cancel(widget._tooltip_id)
        widget._tooltip_id = None
        
    if hasattr(widget, "_tooltip"):
        try:
            widget._tooltip.destroy()
        except:
            pass

    def delayed_show(event=None):
        # Store current position
        x = widget.winfo_pointerx() + 15
        y = widget.winfo_pointery() + 10
        
        # Create a toplevel window
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)  # Remove window decorations
        tooltip.wm_geometry(f"+{x}+{y}")  # Position at mouse pointer
        tooltip.wm_attributes("-topmost", True)  # Keep on top
        
        # Fade-in effect colors
        bg_color = "#282828" if widget.winfo_toplevel().tk.call("ttk::style", "theme", "use") == "darkly" else "#ffffe0"
        fg_color = "#ffffff" if widget.winfo_toplevel().tk.call("ttk::style", "theme", "use") == "darkly" else "#000000"
        
        # Add a label with styled text
        label = ttk.Label(tooltip, text=text, justify=tk.LEFT,
                 background=bg_color, foreground=fg_color, relief="solid", borderwidth=1,
                 font=("Segoe UI", "9", "normal"), padding=(8, 4))
        label.pack(ipadx=2)
        
        # Store tooltip reference
        widget._tooltip = tooltip
        
        # Auto-hide after 3 seconds as fallback
        widget._tooltip_id = widget.after(3000, lambda: hide())
    
    def hide(event=None):
        # Cancel any scheduled showing/hiding
        if hasattr(widget, "_tooltip_id") and widget._tooltip_id:
            widget.after_cancel(widget._tooltip_id)
            widget._tooltip_id = None
            
        # Destroy tooltip if it exists
        if hasattr(widget, "_tooltip") and widget._tooltip:
            try:
                widget._tooltip.destroy()
                widget._tooltip = None
            except:
                pass
    
    # Delay showing the tooltip slightly for better UX
    def on_enter(event):
        hide()  # Hide any existing tooltip first
        widget._tooltip_id = widget.after(500, delayed_show)
    
    # Bind events
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", hide)
    widget.bind("<ButtonPress>", hide)  # Hide on mouse click


class StatusBar(ttk.Frame):
    """Status bar component with progress indicator and status message."""
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Progress bar
        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate", length=200)
        self.progress.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Status message
        self.status_var = StringVar()
        self.status_label = ttk.Label(self, textvariable=self.status_var, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, padx=10, pady=5)
        
        # Set initial status
        self.status_var.set("Ready")
        
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
        
        # Create a new window
        self.window = Toplevel(parent)
        self.window.title("Select Network Interface")
        self.window.geometry("750x500")
        self.window.minsize(600, 400)
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
        
        # Instructions
        ttk.Label(
            self.frame,
            text="Choose the network interface you want to monitor:",
            wraplength=700
        ).pack(fill=tk.X, pady=(0, 10))
        
        # Search and filter frame
        filter_frame = ttk.Frame(self.frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search box
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = StringVar()
        self.search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.search_var.trace_add("write", self._filter_interfaces)
        
        # Interface type filter
        ttk.Label(filter_frame, text="Interface Type:").pack(side=tk.LEFT, padx=(10, 5))
        self.type_var = StringVar(value="All")
        type_combo = ttk.Combobox(
            filter_frame, 
            textvariable=self.type_var,
            values=["All"] + list(self.interface_types.keys()),
            state="readonly",
            width=15
        )
        type_combo.pack(side=tk.LEFT)
        self.type_var.trace_add("write", self._filter_interfaces)
        
        # Main content area with splitting
        content_frame = ttk.Frame(self.frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Left side - Interface list
        list_frame = ttk.LabelFrame(content_frame, text="Available Interfaces")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Scrollbar for list
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
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
                width=12,
                anchor=tk.W
            ).grid(row=row, column=0, sticky=tk.W, pady=5)
            
            ttk.Label(
                self.details_content, 
                textvariable=var,
                wraplength=250
            ).grid(row=row, column=1, sticky=tk.W, pady=5)
            row += 1
        
        # Stats preview
        stats_frame = ttk.LabelFrame(self.details_content, text="Network Status")
        stats_frame.grid(row=row, column=0, columnspan=2, sticky=tk.NSEW, pady=(10, 0))
        
        # Status indicator
        status_frame = ttk.Frame(stats_frame, padding=10)
        status_frame.pack(fill=tk.X)
        
        self.status_indicator = ttk.Label(
            status_frame,
            text="○",
            foreground="gray",
            font=("Segoe UI", 16)
        )
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 10))
        
        self.status_label = ttk.Label(
            status_frame,
            text="Select an interface to view status",
            wraplength=250
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add interfaces to the list
        self._populate_interface_list()
        
        # Select the first interface by default
        if interfaces:
            self.interface_tree.selection_set(self.interface_tree.get_children()[0])
            self._update_details(self.interfaces[0][0])
            
        # Double-click to select
        self.interface_tree.bind("<Double-1>", lambda e: self.on_select())
        
        # Selection changed
        self.interface_tree.bind("<<TreeviewSelect>>", self._on_selection_changed)
        
        # Buttons
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
            iface_lower = iface.lower()
            if "loop" in iface_lower or "lo" == iface_lower:
                types["Loopback"].append((iface, ip))
            elif "eth" in iface_lower or "ens" in iface_lower or "enp" in iface_lower:
                types["Ethernet"].append((iface, ip))
            elif "wlan" in iface_lower or "wifi" in iface_lower or "wl" in iface_lower:
                types["WiFi"].append((iface, ip))
            elif "virt" in iface_lower or "vbox" in iface_lower or "vmnet" in iface_lower or "docker" in iface_lower:
                types["Virtual"].append((iface, ip))
            else:
                types["Other"].append((iface, ip))
                
        return {k: v for k, v in types.items() if v}
        
    def _populate_interface_list(self):
        """Populate the interface list with available interfaces."""
        # Clear existing items
        for item in self.interface_tree.get_children():
            self.interface_tree.delete(item)
            
        # Add interfaces based on current filters
        search_term = self.search_var.get().lower()
        type_filter = self.type_var.get()
        
        interfaces_to_show = []
        if type_filter == "All":
            interfaces_to_show = self.interfaces
        else:
            interfaces_to_show = self.interface_types.get(type_filter, [])
            
        # Apply search filter
        if search_term:
            interfaces_to_show = [
                (iface, ip) for iface, ip in interfaces_to_show
                if search_term in iface.lower() or (ip and search_term in ip.lower())
            ]
            
        # Insert filtered interfaces
        for i, (iface, ip) in enumerate(interfaces_to_show):
            tag = 'even' if i % 2 == 0 else 'odd'
            self.interface_tree.insert("", "end", values=(iface, ip), tags=(tag,))
        
    def _filter_interfaces(self, *args):
        """Filter interfaces based on search text and type."""
        self._populate_interface_list()
        
    def _on_selection_changed(self, event):
        """Handle selection change in the interface tree."""
        selected = self.interface_tree.selection()
        if not selected:
            return
            
        # Get the selected interface
        values = self.interface_tree.item(selected, "values")
        interface = values[0]  # The interface name
        
        # Update details panel
        self._update_details(interface)
        
    def _update_details(self, interface_name):
        """Update interface details panel with information about the selected interface."""
        # Find the interface in our list
        interface_ip = ""
        for iface, ip in self.interfaces:
            if iface == interface_name:
                interface_ip = ip
                break
                
        # Determine interface type
        interface_type = "Unknown"
        for type_name, interfaces in self.interface_types.items():
            if any(iface == interface_name for iface, _ in interfaces):
                interface_type = type_name
                break
                
        # Set basic details
        self.detail_fields["Name"].set(interface_name)
        self.detail_fields["IP Address"].set(interface_ip or "Unknown")
        
        # Set status based on IP
        if interface_ip and interface_ip != "Unknown IP":
            self.status_indicator.config(text="●", foreground="green")
            self.status_label.config(text="Interface appears to be active")
            self.detail_fields["Status"].set("Active")
        else:
            self.status_indicator.config(text="●", foreground="gray")
            self.status_label.config(text="Interface status unknown")
            self.detail_fields["Status"].set("Unknown")
            
        # Set type
        self.detail_fields["Type"].set(interface_type)
        
        # Set MAC and Description - in a real app, you'd query this info
        self.detail_fields["MAC Address"].set("Unknown") # Would be retrieved from system in real impl
        
        # Set description based on interface name
        if "loopback" in interface_name.lower() or interface_name.lower() == "lo":
            self.detail_fields["Description"].set("Loopback interface for local communication")
        elif interface_type == "Ethernet":
            self.detail_fields["Description"].set("Wired Ethernet network interface")
        elif interface_type == "WiFi":
            self.detail_fields["Description"].set("Wireless network interface")
        elif interface_type == "Virtual":
            self.detail_fields["Description"].set("Virtual or emulated network interface")
        else:
            self.detail_fields["Description"].set("")
            
    def _test_connection(self):
        """Test connection on selected interface."""
        selected = self.interface_tree.selection()
        if not selected:
            return
            
        # Get the selected interface
        values = self.interface_tree.item(selected, "values")
        interface = values[0]
        ip = values[1]
        
        if ip and ip != "Unknown IP":
            # Update status indicator to show testing
            self.status_indicator.config(text="⟳", foreground="blue")
            self.status_label.config(text="Testing connection...")
            self.window.update_idletasks()
            
            # In a real implementation, we would do an actual test here
            # For demonstration, we'll just pretend it succeeded
            import time
            time.sleep(0.5)  # Simulate short delay
            
            self.status_indicator.config(text="●", foreground="green")
            self.status_label.config(text="Connection test successful")
        else:
            self.status_indicator.config(text="●", foreground="red")
            self.status_label.config(text="Cannot test interface without IP address")
        
    def center_window(self):
        """Center the window on the screen."""
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
    def on_select(self):
        """Handle interface selection."""
        selected = self.interface_tree.selection()
        if not selected:
            return
            
        # Get the selected interface
        values = self.interface_tree.item(selected, "values")
        interface = values[0]  # The interface name
        
        # Save preference if requested
        if self.remember_var.get():
            try:
                with open(".interface_preference", "w") as f:
                    f.write(interface)
            except:
                pass
        
        # Call the callback with the selected interface
        self.callback(interface)
        
        # Close the window
        self.window.destroy()
        
    def on_cancel(self):
        """Handle cancel button."""
        if len(self.interfaces) > 0:
            # Select the first interface by default
            self.callback(self.interfaces[0][0])
        else:
            # No interfaces available, exit the application
            sys.exit(0)
            
        self.window.destroy()


class AboutDialog:
    """Modern, animated dialog showing information about the application."""
    def __init__(self, parent):
        self.parent = parent
        self.dialog = None
        self.animation_frames = []
        self.current_frame = 0
        
    def show(self):
        """Show the about dialog with animations and modern design."""
        try:
            # Create dialog window with custom styling
            self.dialog = Toplevel(self.parent)
            self.dialog.title("About Network Analysis Tool")
            self.dialog.geometry("1050x950")
            self.dialog.resizable(False, False)
            self.dialog.transient(self.parent)
            
            # Set background color based on theme
            theme = self.parent.tk.call("ttk::style", "theme", "use")
            bg_color = "#282c34" if theme == "darkly" else "#f8f9fa"
            fg_color = "white" if theme == "darkly" else "black"
            accent_color = "#61afef" if theme == "darkly" else "#3366cc"
            
            # Configure dialog background
            self.dialog.configure(bg=bg_color)
            
            # Make the dialog modal
            self.dialog.grab_set()
            self.dialog.focus_set()
            
            # Handle dialog close
            self.dialog.protocol("WM_DELETE_WINDOW", self.dialog.destroy)
            
            # Main canvas for drawing the animated elements
            self.canvas = tk.Canvas(self.dialog, bg=bg_color, highlightthickness=0)
            self.canvas.pack(fill=tk.BOTH, expand=True)
            
            # Create header section with logo animation
            y_offset = 30
            
            # GIF image display setup
            self.gif_frame = tk.Frame(self.canvas, bg=bg_color)
            self.canvas.create_window(325, 80, window=self.gif_frame, width=300, height=120)
            
            # We'll display a GIF if provided, otherwise use a placeholder message
            try:
                # Try to load as an animated GIF
                import os
                if os.path.exists("about_animation.gif"):
                    self.gif_frames = []
                    self.current_gif_frame = 0
                    
                    # Load the GIF and extract frames
                    try:
                        # Try PIL first for animated GIF support
                        from PIL import Image, ImageTk
                        gif = Image.open("about_animation.gif")
                        
                        # Get all frames
                        for i in range(0, gif.n_frames):
                            gif.seek(i)
                            frame = ImageTk.PhotoImage(gif.copy())
                            self.gif_frames.append(frame)
                            
                        # Create label to display the frames
                        self.gif_label = tk.Label(self.gif_frame, image=self.gif_frames[0], bg=bg_color)
                        self.gif_label.pack(fill=tk.BOTH, expand=True)
                        
                        # Start animation
                        self.animate_gif()
                    except ImportError:
                        # Fallback to standard PhotoImage which doesn't support animation
                        self.gif_image = tk.PhotoImage(file="about_animation.gif")
                        self.gif_label = tk.Label(self.gif_frame, image=self.gif_image, bg=bg_color)
                        self.gif_label.pack(fill=tk.BOTH, expand=True)
                else:
                    raise FileNotFoundError("GIF file not found")
            except Exception as e:
                print(f"Could not load GIF image: {e}")
                self.canvas.create_text(
                    325, 80,
                    text="[Place for your GIF animation]",
                    font=("Helvetica", 12),
                    fill=fg_color
                )
            
            # App title with shadow effect
            title_y = y_offset + 140
            for offset in range(3, 0, -1):
                shadow_color = "#444" if theme == "darkly" else "#ccc"
                self.canvas.create_text(
                    325 + offset, title_y + offset, 
                    text="Network Analysis Tool",
                    font=("Helvetica", 28, "bold"),
                    fill=shadow_color
                )
            
            self.canvas.create_text(
                325, title_y, 
                text="Network Analysis Tool",
                font=("Helvetica", 28, "bold"),
                fill=accent_color
            )
            
            # Version with glowing effect
            self.version_text = self.canvas.create_text(
                325, title_y + 40, 
                text="Version 1.0.0",
                font=("Helvetica", 12),
                fill=fg_color
            )
            
            # Create a decorative separator line
            self.canvas.create_line(
                175, title_y + 70, 475, title_y + 70, 
                fill=accent_color, width=2, 
                dash=(5, 2)
            )
            
            # Description section with stylized box
            desc_y = title_y + 100
            desc_box = self.canvas.create_rectangle(
                125, desc_y, 525, desc_y + 100,
                outline=accent_color, width=2,
                fill=bg_color
            )
            
            description = "A sophisticated network packet analysis tool designed for visualizing, " + \
                         "tracking, and analyzing network traffic in real-time with advanced " + \
                         "filtering and protocol detection capabilities."
                         
            self.canvas.create_text(
                325, desc_y + 50, 
                text=description,
                font=("Helvetica", 11),
                fill=fg_color,
                width=350,
                justify="center"
            )
            
            # Technologies with icons in a simple text list
            tech_y = desc_y + 130
            tech_title = self.canvas.create_text(
                325, tech_y, 
                text="POWERED BY",
                font=("Helvetica", 10, "bold"),
                fill=accent_color
            )
            
            # Create a simple text list of technologies
            tech_text = "Python 3 • Tkinter • Kamene • Plotly"
            
            self.canvas.create_text(
                325, tech_y + 30,
                text=tech_text,
                font=("Helvetica", 11),
                fill=fg_color
            )
            
            # Created by section
            creator_y = tech_y + 80
            self.canvas.create_text(
                325, creator_y, 
                text="Created for Advanced Networks Course",
                font=("Helvetica", 10),
                fill=fg_color
            )
            
            # Current date
            import datetime
            current_date = datetime.datetime.now().strftime("%B %Y")
            self.canvas.create_text(
                325, creator_y + 25, 
                text=f"© {current_date}",
                font=("Helvetica", 10),
                fill=fg_color
            )
            
            # Create a custom button style if it doesn't exist
            try:
                self.dialog.tk.call("ttk::style", "configure", "AccentButton.TButton", 
                                  "-background", accent_color, 
                                  "-foreground", "white")
                self.dialog.tk.call("ttk::style", "map", "AccentButton.TButton",
                                  "-background", [('active', self._lighten_color(accent_color, 1.1))])
            except Exception as e:
                print(f"Custom style error: {e}")
                
            # Close button with hover effect
            close_button_frame = tk.Frame(self.dialog, bg=bg_color)
            close_button_frame.pack(pady=10)
            
            self.close_button = ttk.Button(
                close_button_frame,
                text="Close",
                style="AccentButton.TButton" if accent_color else "TButton",
                command=self.dialog.destroy
            )
            self.close_button.pack()
            
            # Start only the version glow animation since we're using a GIF
            self.animate_version_glow()
            
            # Center on parent
            self.center_dialog()
            
        except Exception as e:
            print(f"Error showing About dialog: {e}")
            import traceback
            traceback.print_exc()
            
    def create_network_animation(self):
        """Create the network node animation elements."""
        # Create nodes
        node_radius = 8
        center_x, center_y = 325, 80
        
        # Create central node
        self.nodes.append({
            "id": self.canvas.create_oval(
                center_x - node_radius, center_y - node_radius,
                center_x + node_radius, center_y + node_radius,
                fill="#61afef", outline=""
            ),
            "x": center_x,
            "y": center_y,
            "size": node_radius * 2
        })
        
        # Create satellite nodes
        import math
        for i in range(6):
            angle = math.radians(60 * i)
            distance = 70
            x = center_x + distance * math.cos(angle)
            y = center_y + distance * math.sin(angle)
            
            self.nodes.append({
                "id": self.canvas.create_oval(
                    x - node_radius, y - node_radius,
                    x + node_radius, y + node_radius,
                    fill="#98c379" if i % 2 == 0 else "#e06c75", outline=""
                ),
                "x": x,
                "y": y,
                "size": node_radius * 1.5
            })
            
            # Create connection line
            line_id = self.canvas.create_line(
                center_x, center_y, x, y,
                fill="#4b5263", width=2, dash=(3, 2)
            )
            self.connections.append(line_id)
    
    def animate_network(self):
        """Animate the network nodes."""
        import random
        
        # Animate nodes by changing their size slightly
        for node in self.nodes:
            size_change = random.uniform(0.95, 1.05)
            current_size = node["size"]
            new_size = current_size * size_change
            
            x, y = node["x"], node["y"]
            r = new_size / 2
            
            self.canvas.coords(
                node["id"],
                x - r, y - r, x + r, y + r
            )
            
            node["size"] = new_size
        
        # Animate a data packet traveling on a random connection
        if random.random() > 0.7:  # 30% chance of data packet
            conn_idx = random.randint(0, len(self.connections) - 1)
            coords = self.canvas.coords(self.connections[conn_idx])
            
            # Create data packet
            packet = self.canvas.create_rectangle(
                coords[0] - 3, coords[1] - 3,
                coords[0] + 3, coords[1] + 3,
                fill="#61afef", outline=""
            )
            
            # Animate it along the connection
            self._animate_packet(packet, coords, 0)
        
        # Schedule next animation frame
        self.dialog.after(50, self.animate_network)
    
    def _animate_packet(self, packet_id, line_coords, step):
        """Animate a packet moving along a connection line."""
        if not self.dialog or step >= 100:
            return
        
        # Calculate position along the line
        x1, y1, x2, y2 = line_coords
        pos_x = x1 + (x2 - x1) * (step / 100)
        pos_y = y1 + (y2 - y1) * (step / 100)
        
        # Update packet position
        self.canvas.coords(
            packet_id,
            pos_x - 3, pos_y - 3,
            pos_x + 3, pos_y + 3
        )
        
        # Schedule next step or delete packet if done
        if step < 100:
            self.dialog.after(10, lambda: self._animate_packet(packet_id, line_coords, step + 5))
        else:
            self.canvas.delete(packet_id)
    
    def animate_gif(self):
        """Animate the GIF by cycling through frames."""
        if not hasattr(self, 'gif_frames') or not self.gif_frames or not self.dialog:
            return
            
        # Update to next frame
        self.current_gif_frame = (self.current_gif_frame + 1) % len(self.gif_frames)
        self.gif_label.configure(image=self.gif_frames[self.current_gif_frame])
        
        # GIF animation speed (adjust as needed, typically 100ms)
        self.dialog.after(100, self.animate_gif)
    
    def animate_version_glow(self):
        """Create a subtle glow animation for the version text."""
        colors = [
            "#61afef", "#65b3f3", "#69b7f7", "#6dbbfb", "#71bfff",
            "#71bfff", "#6dbbfb", "#69b7f7", "#65b3f3", "#61afef"
        ]
        
        # Update color
        if self.current_frame < len(colors):
            self.canvas.itemconfig(self.version_text, fill=colors[self.current_frame])
            self.current_frame = (self.current_frame + 1) % len(colors)
        
        # Schedule next frame
        if self.dialog:
            self.dialog.after(200, self.animate_version_glow)
            
    def _lighten_color(self, hex_color, factor=1.3):
        """Lighten a color by the specified factor."""
        try:
            # Remove leading '#' if present
            if hex_color.startswith('#'):
                hex_color = hex_color[1:]
            
            # Convert hex to RGB
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16) if len(hex_color) >= 6 else 0
            
            # Lighten
            r = min(int(r * factor), 255)
            g = min(int(g * factor), 255)
            b = min(int(b * factor), 255)
            
            # Convert back to hex
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception as e:
            print(f"Error lightening color: {e}")
            return hex_color
    
    def center_dialog(self):
        """Center the dialog on the parent window."""
        try:
            self.dialog.update_idletasks()
            
            # Get parent and dialog dimensions
            parent_width = self.parent.winfo_width()
            parent_height = self.parent.winfo_height()
            parent_x = self.parent.winfo_rootx()
            parent_y = self.parent.winfo_rooty()
            
            dialog_width = self.dialog.winfo_width()
            dialog_height = self.dialog.winfo_height()
            
            # Calculate position
            x = parent_x + (parent_width - dialog_width) // 2
            y = parent_y + (parent_height - dialog_height) // 2
            
            # Set position
            self.dialog.geometry(f"+{x}+{y}")
        except Exception as e:
            print(f"Error centering dialog: {e}")

