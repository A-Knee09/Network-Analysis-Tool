import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from ttkbootstrap import Style
from .functionality import PacketCapture
from .utils import export_to_pdf, send_email
from .styles import apply_dark_theme, apply_light_theme, configure_treeview_style
import threading
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import ctypes
from scapy.all import IP, TCP, UDP  # Ensure Scapy imports are correct

# Enable high-DPI awareness on Windows
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass


class NetworkAnalysisTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Network Analysis Tool")
        self.style = Style(theme="minty")

        # Set the window size and make it resizable
        self.root.geometry("1200x600")
        self.root.minsize(800, 400)

        # Initialize packet capture
        self.packet_capture = PacketCapture()

        # Apply custom styles
        configure_treeview_style(self.style)

        # Create a top bar for progress and status
        self.top_bar = ttk.Frame(root)
        self.top_bar.pack(fill=tk.X, pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(self.top_bar, orient="horizontal", mode="indeterminate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.top_bar, textvariable=self.status_var)
        self.status_bar.pack(side=tk.LEFT, padx=5)

        # Create a left sidebar for filter controls
        self.sidebar = ttk.Frame(root)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # Protocol filter dropdown
        self.protocol_filter_label = ttk.Label(self.sidebar, text="Filter by Protocol:")
        self.protocol_filter_label.pack(pady=5)

        self.protocol_filter = ttk.Combobox(self.sidebar, values=["All", "TCP", "UDP", "ICMP"])
        self.protocol_filter.set("All")
        self.protocol_filter.pack(pady=5)

        self.filter_button = ttk.Button(self.sidebar, text="Apply Filter", command=self.filter_packets)
        self.filter_button.pack(pady=5)

        # Search bar
        self.search_label = ttk.Label(self.sidebar, text="Search by IP:")
        self.search_label.pack(pady=5)

        self.search_entry = ttk.Entry(self.sidebar)
        self.search_entry.pack(pady=5)

        self.search_button = ttk.Button(self.sidebar, text="Search", command=self.search_packets)
        self.search_button.pack(pady=5)

        # Create a main area for the packet table and statistics
        self.main_area = ttk.Frame(root)
        self.main_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Packet table with serial number column
        self.tree = ttk.Treeview(self.main_area, columns=("Serial", "Source IP", "Destination IP", "Protocol"), show="headings")
        self.tree.heading("Serial", text="Serial")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Create a bottom bar for main controls
        self.bottom_bar = ttk.Frame(root)
        self.bottom_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        # Start and stop capture buttons
        self.start_button = ttk.Button(self.bottom_bar, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.bottom_bar, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Save and load buttons
        self.save_button = ttk.Button(self.bottom_bar, text="Save", command=self.save_packets)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.load_button = ttk.Button(self.bottom_bar, text="Load", command=self.load_packets)
        self.load_button.pack(side=tk.LEFT, padx=5)

        # Export and email buttons
        self.export_button = ttk.Button(self.bottom_bar, text="Export PDF", command=self.export_to_pdf)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.email_button = ttk.Button(self.bottom_bar, text="Email Report", command=self.email_report)
        self.email_button.pack(side=tk.LEFT, padx=5)

        # Dark mode toggle
        self.dark_mode = tk.BooleanVar()
        self.dark_mode_button = ttk.Checkbutton(self.bottom_bar, text="Dark Mode", variable=self.dark_mode, command=self.toggle_theme)
        self.dark_mode_button.pack(side=tk.LEFT, padx=5)

        # View Details button
        self.details_button = ttk.Button(self.bottom_bar, text="View Details", command=self.show_packet_details)
        self.details_button.pack(side=tk.LEFT, padx=5)

        # Serial number counter
        self.serial_number = 1

    def start_capture(self):
        """Start capturing packets in a separate thread."""
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Capturing packets...")
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop capturing packets."""
        self.packet_capture.stop_capture()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set("Capture stopped.")

    def capture_packets(self):
        """Capture packets in real-time and update the GUI."""
        self.packet_capture.start_capture(self.process_packet)

    def process_packet(self, packet):
        """Process each captured packet and update the Treeview."""
        src_ip, dst_ip, protocol = self.packet_capture.process_packet(packet)
        if src_ip and dst_ip and protocol:
            self.tree.insert("", "end", values=(self.serial_number, src_ip, dst_ip, protocol))
            self.serial_number += 1  # Increment serial number

    def filter_packets(self):
        """Filter packets based on the selected protocol."""
        selected_protocol = self.protocol_filter.get()
        filtered_packets = self.packet_capture.filter_packets(selected_protocol)

        self.tree.delete(*self.tree.get_children())
        self.serial_number = 1  # Reset serial number
        for packet in filtered_packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = self.packet_capture._get_packet_protocol(packet)
                self.tree.insert("", "end", values=(self.serial_number, src_ip, dst_ip, protocol))
                self.serial_number += 1  # Increment serial number

    def search_packets(self):
        """Search for packets by IP address."""
        query = self.search_entry.get()
        if query:
            filtered_packets = self.packet_capture.filter_by_ip(query)
            self.tree.delete(*self.tree.get_children())
            self.serial_number = 1  # Reset serial number
            for packet in filtered_packets:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = self.packet_capture._get_packet_protocol(packet)
                    self.tree.insert("", "end", values=(self.serial_number, src_ip, dst_ip, protocol))
                    self.serial_number += 1  # Increment serial number

    def show_packet_details(self):
        """Show detailed information about the selected packet."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a packet to view details.")
            return

        # Get the selected packet
        packet_index = int(self.tree.item(selected_item, "values")[0]) - 1
        packet = self.packet_capture.packets[packet_index]

        # Create a new window
        details_window = tk.Toplevel(self.root)
        details_window.title("Packet Details")

        # Display packet details
        details_text = tk.Text(details_window, wrap=tk.NONE)
        details_text.pack(fill=tk.BOTH, expand=True)

        # Add packet details to the text widget
        details_text.insert(tk.END, packet.show(dump=True))
        details_text.config(state=tk.DISABLED)  # Make it read-only

    def show_statistics(self):
        """Show advanced statistics using Plotly."""
        protocol_count = self.packet_capture.get_statistics()

        # Create a DataFrame for statistics
        df = pd.DataFrame(list(protocol_count.items()), columns=["Protocol", "Count"])

        # Create a Plotly figure
        fig = make_subplots(rows=1, cols=2, specs=[[{"type": "bar"}, {"type": "pie"}]])

        # Bar chart
        fig.add_trace(
            go.Bar(x=df["Protocol"], y=df["Count"], name="Protocol Distribution"),
            row=1, col=1
        )

        # Pie chart
        fig.add_trace(
            go.Pie(labels=df["Protocol"], values=df["Count"], name="Protocol Distribution"),
            row=1, col=2
        )

        # Update layout
        fig.update_layout(
            title="Packet Statistics",
            showlegend=True,
            template="plotly_white"
        )

        # Show the figure
        fig.show()

    def export_to_pdf(self):
        """Export statistics to a PDF report."""
        protocol_count = self.packet_capture.get_statistics()
        filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if filename:
            export_to_pdf(protocol_count, filename)
            messagebox.showinfo("Export", "PDF report exported successfully!")

    def email_report(self):
        """Email the PDF report."""
        protocol_count = self.packet_capture.get_statistics()
        filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if filename:
            export_to_pdf(protocol_count, filename)
            recipient = "recipient@example.com"  # Replace with actual recipient email
            send_email(filename, recipient)
            messagebox.showinfo("Email", "Report emailed successfully!")

    def toggle_theme(self):
        """Toggle between dark and light themes."""
        if self.dark_mode.get():
            apply_dark_theme(self.style)
        else:
            apply_light_theme(self.style)

    def save_packets(self):
        """Save captured packets to a file."""
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("CSV files", "*.csv")])
        if filename:
            if filename.endswith(".pcap"):
                self.packet_capture.save_to_pcap(filename)
            elif filename.endswith(".csv"):
                self.packet_capture.save_to_csv(filename)
            messagebox.showinfo("Save", "Packets saved successfully!")

    def load_packets(self):
        """Load packets from a file."""
        filename = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("CSV files", "*.csv")])
        if filename:
            if filename.endswith(".pcap"):
                self.packet_capture.load_from_pcap(filename)
            elif filename.endswith(".csv"):
                self.packet_capture.load_from_csv(filename)
            self.tree.delete(*self.tree.get_children())
            self.serial_number = 1  # Reset serial number
            for packet in self.packet_capture.packets:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = self.packet_capture._get_packet_protocol(packet)
                    self.tree.insert("", "end", values=(self.serial_number, src_ip, dst_ip, protocol))
                    self.serial_number += 1  # Increment serial number
            messagebox.showinfo("Load", "Packets loaded successfully!")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalysisTool(root)
    root.mainloop()


