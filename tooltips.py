import tkinter as tk
from tkinter import ttk
import platform

class EnhancedTooltip:
    """Enhanced tooltip class with improved styling and technical explanations."""
    
    # Database of technical term explanations
    TECH_TERMS = {
        # Network Protocols
        "TCP": "Transmission Control Protocol: A reliable, connection-oriented protocol that ensures data delivery.",
        "UDP": "User Datagram Protocol: A connectionless protocol that sends data without guaranteeing delivery.",
        "HTTP": "HyperText Transfer Protocol: Used for transmitting web pages and other content on the internet.",
        "HTTPS": "HyperText Transfer Protocol Secure: Encrypted version of HTTP for secure web browsing.",
        "DNS": "Domain Name System: Translates human-readable domain names to IP addresses.",
        "ICMP": "Internet Control Message Protocol: Used for error reporting and network diagnostics like ping.",
        "ARP": "Address Resolution Protocol: Maps IP addresses to physical MAC addresses on a network.",
        "SSH": "Secure Shell: Protocol for secure remote login and command execution.",
        "FTP": "File Transfer Protocol: Used for transferring files between computers on a network.",
        "SMTP": "Simple Mail Transfer Protocol: Used for sending email between servers.",
        "POP3": "Post Office Protocol 3: Used by email clients to retrieve emails from a server.",
        "IMAP": "Internet Message Access Protocol: Modern protocol for accessing email on a remote server.",
        
        # Network terms
        "Packet": "A unit of data routed between an origin and destination on the Internet or other networks.",
        "Protocol": "A standard set of rules that allow devices to communicate with each other.",
        "Port": "A virtual point where network connections start and end, identified by a number.",
        "IP Address": "Internet Protocol Address: A unique identifier assigned to each device on a network.",
        "MAC Address": "Media Access Control Address: A unique identifier assigned to a network interface.",
        "Payload": "The actual data being carried in a packet, excluding headers and metadata.",
        "TTL": "Time To Live: A limit on how long data can exist before being discarded.",
        "MTU": "Maximum Transmission Unit: The largest size packet that can be sent over a network.",
        "Latency": "The time delay between sending and receiving data across a network.",
        "Bandwidth": "The maximum rate of data transfer across a network connection.",
        "SYN": "Synchronize flag in TCP: Used to initiate a connection between hosts.",
        "ACK": "Acknowledgment flag in TCP: Confirms receipt of data packets.",
        "FIN": "Finish flag in TCP: Indicates the end of data transmission.",
        "RST": "Reset flag in TCP: Abruptly terminates a connection due to an error.",
        "PSH": "Push flag in TCP: Tells the receiver to deliver data to the application immediately.",
        
        # Application categories
        "Web Browsing": "Traffic related to viewing websites and web applications.",
        "Streaming": "Continuous transmission of audio or video data from a server to a client.",
        "Gaming": "Network traffic related to online video games.",
        "VoIP": "Voice over IP: Technology for delivering voice communications over Internet Protocol networks.",
        "File Transfer": "Traffic related to sending files between devices or systems.",
        "Database": "Traffic related to accessing or modifying database systems.",
        "Email": "Traffic related to sending and receiving electronic mail.",
        "Social Media": "Traffic to social networking and media sharing platforms.",
        "Remote Access": "Traffic related to accessing and controlling distant computers or systems.",
        
        # Analysis terms
        "Traffic Flow": "The path that network data takes from source to destination.",
        "Protocol Distribution": "The breakdown of network traffic by protocol type.",
        "Packet Size": "The amount of data contained in a single network packet, measured in bytes.",
        "Capture": "The process of collecting and recording network packets.",
        "Filter": "A way to select specific packets based on criteria like protocol or IP address.",
        "Analyzer": "A tool that examines network traffic to provide insights and statistics.",
        "Dashboard": "A visual display of key network metrics and information.",
        "Payload Analysis": "Examining the content of network packets for information or anomalies.",
        "Traffic Pattern": "Recurring characteristics in network communication that form identifiable trends.",
        "Network Map": "Visual representation of devices and connections in a network."
    }
    
    def __init__(self, widget, text=None, term=None, wrap_length=300, hover_delay=500, background=None, foreground=None):
        """Initialize enhanced tooltip with styling and content."""
        self.widget = widget
        self.hover_delay = hover_delay  # milliseconds
        self.tooltip_id = None
        self.tooltip = None
        
        # Check if we're explaining a technical term or using custom text
        if term and term in self.TECH_TERMS:
            self.text = self.TECH_TERMS[term]
            # Add the term itself as a title
            self.text = f"{term}:\n{self.text}"
        else:
            self.text = text or ""
            
        self.wrap_length = wrap_length
        
        # Define custom colors if provided, otherwise use defaults
        if background and foreground:
            self.background = background
            self.foreground = foreground
        else:
            # Default colors for light/dark detection will be determined on show
            self.background = None
            self.foreground = None
        
        # Bind events
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)
        self.widget.bind("<ButtonPress>", self.on_leave)  # Hide on mouse press
    
    def on_enter(self, event=None):
        """When mouse enters the widget, schedule tooltip display."""
        # Cancel any existing tooltip schedule
        self.on_leave()
        
        # Schedule new tooltip
        self.tooltip_id = self.widget.after(self.hover_delay, self.show_tooltip)
    
    def on_leave(self, event=None):
        """When mouse leaves the widget, cancel and hide tooltip."""
        # Cancel scheduled tooltip if any
        if self.tooltip_id:
            self.widget.after_cancel(self.tooltip_id)
            self.tooltip_id = None
            
        # Hide active tooltip if any
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
    
    def show_tooltip(self):
        """Display the tooltip near the widget."""
        # Get the widget's position relative to screen
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        # Determine background/foreground based on widget style if not explicitly set
        if not self.background or not self.foreground:
            try:
                # Try to detect if we're in dark mode via ttk style
                style_name = self.widget.winfo_toplevel().tk.call("ttk::style", "theme", "use")
                if style_name in ["darkly", "solar", "superhero"]:
                    # Dark mode
                    self.background = "#343a40"
                    self.foreground = "#f8f9fa"
                else:
                    # Light mode
                    self.background = "#f8f9fa"
                    self.foreground = "#343a40"
            except:
                # Fallback colors
                self.background = "#f8f9fa"
                self.foreground = "#343a40"
        
        # Create tooltip window
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)  # No window decorations
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        # Apply platform-specific styling
        if platform.system() == "Darwin":  # macOS
            self.tooltip.tk.call("::tk::unsupported::MacWindowStyle", "style", 
                                self.tooltip._w, "help", "noActivates")
        
        # Create the tooltip frame with border
        frame = tk.Frame(self.tooltip, background=self.background, borderwidth=1, relief="solid")
        frame.pack(expand=True, fill="both")
        
        # Add title and explanation if it's a tech term
        if ":" in self.text and self.text.split(":", 1)[0] in self.TECH_TERMS:
            title, explanation = self.text.split(":", 1)
            
            # Create a title label
            title_label = tk.Label(
                frame, 
                text=title, 
                justify=tk.LEFT,
                background=self.background, 
                foreground=self.foreground,
                font=("Segoe UI", 10, "bold"),
                padx=8,
                pady=(6, 2),
                wraplength=self.wrap_length
            )
            title_label.pack(anchor="w")
            
            # Create a separator
            separator = ttk.Separator(frame, orient="horizontal")
            separator.pack(fill="x", padx=5, pady=2)
            
            # Create the explanation label
            label = tk.Label(
                frame, 
                text=explanation, 
                justify=tk.LEFT,
                background=self.background, 
                foreground=self.foreground,
                wraplength=self.wrap_length,
                font=("Segoe UI", 9),
                padx=8,
                pady=(2, 6)
            )
            label.pack(anchor="w")
        else:
            # Just create a regular label
            label = tk.Label(
                frame, 
                text=self.text, 
                justify=tk.LEFT,
                background=self.background, 
                foreground=self.foreground,
                wraplength=self.wrap_length,
                font=("Segoe UI", 9),
                padx=8,
                pady=6
            )
            label.pack()
        
        # Make tooltip appear on top
        self.tooltip.wm_attributes("-topmost", True)
        
        # Auto-hide after 8 seconds
        self.tooltip.after(8000, self.on_leave)


def add_technical_term_tooltip(widget, term):
    """Add a tooltip explaining a technical term to a widget."""
    if term in EnhancedTooltip.TECH_TERMS:
        return EnhancedTooltip(widget, term=term)
    return None


def add_tooltips_to_ui(parent, tooltips_map):
    """
    Add tooltips to multiple UI elements based on a mapping.
    
    Args:
        parent: The parent widget/window containing the elements
        tooltips_map: Dictionary mapping widget names/paths to terms or custom text
                     Format: {'widget_path': {'type': 'term|text', 'content': 'term_name or custom text'}}
    """
    for widget_path, tooltip_info in tooltips_map.items():
        try:
            # Try to get the widget by path
            widget = parent.nametowidget(widget_path)
            
            # Add tooltip based on type
            if tooltip_info['type'] == 'term':
                EnhancedTooltip(widget, term=tooltip_info['content'])
            else:
                EnhancedTooltip(widget, text=tooltip_info['content'])
        except (KeyError, tk.TclError):
            # Widget not found or tooltip info invalid, skip it
            continue
