"""
Network Dashboard - Real-time visualization of network health and status
"""

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
from matplotlib.figure import Figure
import numpy as np
import random
import time
import threading
from PIL import Image, ImageTk

class NetworkDashboard:
    """Network dashboard showing real-time health metrics and status visualization."""
    
    def __init__(self, parent, packet_capture):
        """Initialize the network dashboard."""
        self.parent = parent
        self.packet_capture = packet_capture
        self.last_update = time.time()
        self.update_interval = 1.0  # Update every second
        
        # Initial health metrics
        self.health_score = 85  # Initial score
        self.latency = 25  # ms
        self.packet_loss = 0.2  # %
        self.throughput = 1.2  # Mbps
        self.error_rate = 0.5  # %
        
        # Health history for graph
        self.health_history = [self.health_score] * 30
        self.timestamps = list(range(30))
        
        # Alert history
        self.alerts = []
        
        # Create GUI
        self.create_dashboard()
        
        # Start update thread
        self.running = True
        self.update_thread = threading.Thread(target=self.update_metrics_thread, daemon=True)
        self.update_thread.start()
        
    def create_dashboard(self):
        """Create the dashboard GUI."""
        # Main frame
        self.frame = ttk.Frame(self.parent, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Create top panel with health score
        self.create_health_panel()
        
        # Create metrics panel
        self.create_metrics_panel()
        
        # Create health history graph
        self.create_health_graph()
        
        # Create network alerts panel
        self.create_alerts_panel()
        
    def create_health_panel(self):
        """Create the health score indicator panel."""
        health_frame = ttk.LabelFrame(self.frame, text="Network Health Score", padding=10)
        health_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Health score display
        score_frame = ttk.Frame(health_frame)
        score_frame.pack(side=tk.LEFT, padx=10)
        
        self.health_var = tk.StringVar(value=str(self.health_score))
        self.health_label = ttk.Label(
            score_frame,
            textvariable=self.health_var,
            font=("Segoe UI", 36, "bold"),
            foreground=self._get_health_color(self.health_score)
        )
        self.health_label.pack()
        
        ttk.Label(
            score_frame,
            text="/100",
            font=("Segoe UI", 12)
        ).pack()
        
        # Status description
        status_frame = ttk.Frame(health_frame)
        status_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20)
        
        self.status_var = tk.StringVar(value=self._get_health_description(self.health_score))
        status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            font=("Segoe UI", 12, "bold"),
            wraplength=400
        )
        status_label.pack(anchor=tk.W)
        
        self.status_detail_var = tk.StringVar(value="Your network is performing well with low latency and minimal packet loss.")
        status_detail = ttk.Label(
            status_frame,
            textvariable=self.status_detail_var,
            wraplength=400
        )
        status_detail.pack(anchor=tk.W, pady=(5, 0))
        
        # Visual indicator
        indicator_frame = ttk.Frame(health_frame)
        indicator_frame.pack(side=tk.RIGHT, padx=10)
        
        self.indicator_canvas = tk.Canvas(indicator_frame, width=80, height=80, highlightthickness=0)
        self.indicator_canvas.pack()
        
        # Create initial indicator
        self.update_health_indicator(self.health_score)
        
    def create_metrics_panel(self):
        """Create the network metrics panel."""
        metrics_frame = ttk.LabelFrame(self.frame, text="Network Metrics", padding=10)
        metrics_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create 2x2 grid of metrics
        metrics_grid = ttk.Frame(metrics_frame)
        metrics_grid.pack(fill=tk.X)
        
        # Define metrics as a dictionary
        self.metrics = {
            'latency': {
                "name": "Latency", 
                "value": self.latency, 
                "unit": "ms", 
                "var": tk.StringVar(), 
                "ideal": "< 50",
                "good": 50,  # threshold for good performance
                "label": None
            },
            'packet_loss': {
                "name": "Packet Loss", 
                "value": self.packet_loss, 
                "unit": "%", 
                "var": tk.StringVar(), 
                "ideal": "< 1.0",
                "good": 1.0,
                "label": None
            },
            'throughput': {
                "name": "Throughput", 
                "value": self.throughput, 
                "unit": "Mbps", 
                "var": tk.StringVar(), 
                "ideal": "> 1.0",
                "good": 1.0,
                "label": None
            },
            'error_rate': {
                "name": "Error Rate", 
                "value": self.error_rate, 
                "unit": "%", 
                "var": tk.StringVar(), 
                "ideal": "< 1.0",
                "good": 1.0,
                "label": None
            }
        }
        
        # Create metric tiles
        metrics_list = list(self.metrics.items())
        for i, (key, metric) in enumerate(metrics_list):
            col = i % 2
            row = i // 2
            
            tile = ttk.Frame(metrics_grid, padding=10, relief="solid", borderwidth=1)
            tile.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
            
            # Set initial value
            metric["var"].set(f"{metric['value']:.1f}{metric['unit']}")
            
            # Metric name
            ttk.Label(
                tile,
                text=metric["name"],
                font=("Segoe UI", 11, "bold")
            ).pack(anchor=tk.W)
            
            # Metric value
            value_label = ttk.Label(
                tile,
                textvariable=metric["var"],
                font=("Segoe UI", 14)
            )
            value_label.pack(anchor=tk.W, pady=(5, 0))
            
            # Store reference to update later
            metric["label"] = value_label
            
            # Ideal range
            ttk.Label(
                tile,
                text=f"Ideal: {metric['ideal']}",
                font=("Segoe UI", 9),
                foreground="#707070"
            ).pack(anchor=tk.W, pady=(5, 0))
        
        # Configure grid
        metrics_grid.columnconfigure(0, weight=1)
        metrics_grid.columnconfigure(1, weight=1)
        
    def create_health_graph(self):
        """Create a graph showing health score history."""
        graph_frame = ttk.LabelFrame(self.frame, text="Health History", padding=10)
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(5, 2), dpi=100)
        self.ax = self.fig.add_subplot(111)
        
        # Create canvas first
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Then plot health history
        self.plot_health_history()
        
    def create_alerts_panel(self):
        """Create network alerts panel."""
        alerts_frame = ttk.LabelFrame(self.frame, text="Network Alerts", padding=10)
        alerts_frame.pack(fill=tk.X)
        
        # Create alerts list with scrollbar
        alerts_container = ttk.Frame(alerts_frame)
        alerts_container.pack(fill=tk.BOTH, expand=True)
        
        self.alerts_text = tk.Text(
            alerts_container,
            height=4,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(alerts_container, command=self.alerts_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_text.config(yscrollcommand=scrollbar.set)
        
        # Add sample alert
        self.add_alert("Network monitoring started")
        
    def update_metrics_thread(self):
        """Background thread to update metrics periodically."""
        while self.running:
            time.sleep(0.1)  # Short sleep to prevent high CPU usage
            
            current_time = time.time()
            if current_time - self.last_update >= self.update_interval:
                self.last_update = current_time
                
                # Generate new metrics from packet capture data
                self.calculate_new_metrics()
                
                # Schedule GUI update on the main thread
                self.parent.after(0, self.update_dashboard)
                
    def calculate_new_metrics(self):
        """Calculate new network metrics based on captured data."""
        # Get stats from packet capture
        stats = self.packet_capture.get_capture_stats()
        
        if stats:
            # Calculate metrics
            
            # Simulated latency calculation (would use real ICMP times in production)
            # In a real implementation, you would calculate actual response times from packets
            packet_count = stats.get('packets', 0)
            
            # This is a demo implementation - in reality, you'd calculate these from actual packet data
            # Base values on packet count for the demo
            if packet_count > 0:
                # Adjust latency based on packet rate (simulated)
                packet_rate = stats.get('rate', 0)
                if packet_rate > 0:
                    # Higher packet rate generally means more network activity
                    # which could affect latency in unpredictable ways
                    self.latency = 15 + (random.random() * 10) + (packet_rate * 0.5)
                    
                    # More packets might indicate higher throughput
                    self.throughput = 1.0 + (packet_rate * 0.2) + (random.random() * 0.5)
                    
                    # Packet loss calculation would usually be done by tracking sequence numbers
                    # Here we just simulate based on activity
                    self.packet_loss = 0.1 + (random.random() * 0.3)
                    if packet_rate > 10:  # Higher traffic can sometimes lead to more packet loss
                        self.packet_loss += random.random() * 0.5
                        
                    # Error rate - in reality this would come from packet checksums, retransmissions, etc.
                    self.error_rate = 0.2 + (random.random() * 0.6)
                    
                    # Calculate health score based on metrics
                    latency_score = max(0, 100 - (self.latency * 1.5))  # Lower latency is better
                    loss_score = max(0, 100 - (self.packet_loss * 20))  # Lower packet loss is better
                    throughput_score = min(100, self.throughput * 20)   # Higher throughput is better
                    error_score = max(0, 100 - (self.error_rate * 30))  # Lower error rate is better
                    
                    # Overall health score - weighted average
                    self.health_score = int(0.35 * latency_score + 
                                        0.25 * loss_score + 
                                        0.15 * throughput_score + 
                                        0.25 * error_score)
                    
                    # Add to history
                    self.health_history.append(self.health_score)
                    self.health_history = self.health_history[-30:]  # Keep only last 30 values
                    
                    # Generate alerts based on new metrics
                    self.check_for_alerts()
        
    def update_dashboard(self):
        """Update all dashboard elements with new metrics."""
        # Update health score
        self.health_var.set(str(self.health_score))
        self.health_label.config(foreground=self._get_health_color(self.health_score))
        
        # Update status description
        self.status_var.set(self._get_health_description(self.health_score))
        detail_text = self._get_status_detail()
        self.status_detail_var.set(detail_text)
        
        # Update health indicator
        self.update_health_indicator(self.health_score)
        
        # Update metrics - Using dictionary format for metrics
        for key, value in {
            'latency': self.latency,
            'packet_loss': self.packet_loss,
            'throughput': self.throughput,
            'error_rate': self.error_rate
        }.items():
            if key in self.metrics:
                metric = self.metrics[key]
                metric['var'].set(f"{value:.1f}{metric['unit']}")
                
                # Set color based on threshold
                if key == 'throughput':
                    good = value >= metric['good']
                else:
                    good = value <= metric['good']
                
                if good:
                    metric['label'].config(foreground="#2ecc71")  # Green
                else:
                    metric['label'].config(foreground="#e74c3c")  # Red
        
        # Update graph
        self.plot_health_history()
        
    def update_health_indicator(self, score):
        """Update the visual health indicator."""
        # Clear canvas
        self.indicator_canvas.delete("all")
        
        # Parameters
        width = 80
        height = 80
        center_x = width // 2
        center_y = height // 2
        radius = 30
        
        # Draw outer circle
        self.indicator_canvas.create_oval(
            center_x - radius - 2, center_y - radius - 2,
            center_x + radius + 2, center_y + radius + 2,
            width=2, outline="#d0d0d0"
        )
        
        # Draw background circle
        self.indicator_canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            fill="#f5f5f5", outline=""
        )
        
        # Get color based on health score
        color = self._get_health_color(score)
        
        # Calculate arc extent
        extent = score * 3.6  # Convert score (0-100) to degrees (0-360)
        
        # Draw score arc
        self.indicator_canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=90, extent=-extent,  # Start from top, go clockwise
            style=tk.PIESLICE,
            fill=color,
            outline=""
        )
        
        # Draw inner circle (for donut effect)
        inner_radius = radius * 0.7
        self.indicator_canvas.create_oval(
            center_x - inner_radius, center_y - inner_radius,
            center_x + inner_radius, center_y + inner_radius,
            fill="#ffffff", outline=""
        )
        
        # Draw score text
        self.indicator_canvas.create_text(
            center_x, center_y,
            text=str(score),
            font=("Segoe UI", 14, "bold"),
            fill=color
        )
        
    def plot_health_history(self):
        """Update the health history graph."""
        self.ax.clear()
        
        # Plot the health history
        x = list(range(len(self.health_history)))
        y = self.health_history
        
        # Create gradient fill under the curve
        cmap = plt.get_cmap('YlGn')
        colors = [cmap(0.2 + (0.8 * (val / 100))) for val in y]
        
        # Plot line
        self.ax.plot(x, y, color='#2ecc71', linewidth=2)
        
        # Fill under the curve with gradient
        for i in range(len(x) - 1):
            self.ax.fill_between([x[i], x[i+1]], [0, 0], [y[i], y[i+1]], color=colors[i], alpha=0.7)
        
        # Set y axis range
        self.ax.set_ylim(0, 100)
        
        # Remove axes spines
        for spine in self.ax.spines.values():
            spine.set_visible(False)
            
        # Add horizontal gridlines
        self.ax.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Set background color
        self.ax.set_facecolor('#f9f9f9')
        
        # Remove ticks
        self.ax.set_xticks([])
        
        # Add y-axis label on right side
        self.ax.yaxis.set_label_position("right")
        self.ax.set_ylabel("Health Score")
        
        # Draw horizontal threshold lines
        self.ax.axhline(y=70, color='#f39c12', linestyle='--', alpha=0.5)
        self.ax.axhline(y=50, color='#e74c3c', linestyle='--', alpha=0.5)
        
        # Update canvas
        self.fig.tight_layout()
        self.canvas.draw()
        
    def add_alert(self, message):
        """Add an alert message to the alerts panel."""
        timestamp = time.strftime("%H:%M:%S")
        alert = f"[{timestamp}] {message}\n"
        
        # Add to alerts list
        self.alerts.append(alert)
        self.alerts = self.alerts[-10:]  # Keep only last 10 alerts
        
        # Update text widget
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        for a in self.alerts:
            self.alerts_text.insert(tk.END, a)
        self.alerts_text.config(state=tk.DISABLED)
        self.alerts_text.see(tk.END)  # Scroll to bottom
        
    def check_for_alerts(self):
        """Check metrics for alert conditions."""
        # High latency alert
        if self.latency > 40 and random.random() < 0.3:
            self.add_alert(f"High latency detected: {self.latency:.1f}ms")
            
        # Packet loss alert
        if self.packet_loss > 1.0 and random.random() < 0.4:
            self.add_alert(f"Elevated packet loss: {self.packet_loss:.1f}%")
            
        # Low throughput alert
        if self.throughput < 1.0 and random.random() < 0.3:
            self.add_alert(f"Low network throughput: {self.throughput:.1f} Mbps")
            
        # Health score alerts
        if self.health_score < 50 and random.random() < 0.5:
            self.add_alert("Network health is critical - investigation recommended")
        elif self.health_score < 70 and random.random() < 0.3:
            self.add_alert("Network health is degraded - monitor closely")
            
    def _get_health_color(self, score):
        """Get a color based on health score."""
        if score >= 80:
            return "#2ecc71"  # Green
        elif score >= 60:
            return "#f39c12"  # Orange
        else:
            return "#e74c3c"  # Red
            
    def _get_health_description(self, score):
        """Get a description of the health score."""
        if score >= 80:
            return "Network Healthy"
        elif score >= 60:
            return "Network Performance Degraded"
        else:
            return "Network Performance Critical"
            
    def _get_status_detail(self):
        """Get detailed status description based on current metrics."""
        details = []
        
        if self.latency > 40:
            details.append("high latency")
        if self.packet_loss > 1.0:
            details.append("packet loss")
        if self.throughput < 1.0:
            details.append("low throughput")
        if self.error_rate > 1.0:
            details.append("transmission errors")
            
        if details:
            issues = ", ".join(details)
            return f"Network is experiencing issues with {issues}. This may affect application performance."
        else:
            return "Your network is performing well with low latency and minimal packet loss."
            
    # This duplicate method has been removed to avoid confusion
        
    def stop(self):
        """Stop the update thread."""
        self.running = False
        if self.update_thread.is_alive():
            self.update_thread.join(1.0)  # Wait for thread to terminate