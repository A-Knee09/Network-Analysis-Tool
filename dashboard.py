import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
import webbrowser
from datetime import datetime
import time

class Dashboard:
    """A dashboard view for displaying network analysis information."""
    
    def __init__(self, parent_notebook, visualizer, traffic_analyzer):
        """Initialize the dashboard tab within the existing UI."""
        self.parent = parent_notebook
        self.visualizer = visualizer
        self.traffic_analyzer = traffic_analyzer
        
        # Create the dashboard frame
        self.dashboard_frame = ttk.Frame(parent_notebook)
        parent_notebook.add(self.dashboard_frame, text="Dashboard")
        
        # Create the content with scrolling
        self.create_dashboard_content()
        
        # Update interval in milliseconds
        self.update_interval = 5000
        self.last_update = time.time()
        
    def create_dashboard_content(self):
        """Create the dashboard content with interactive elements."""
        # Create a canvas with scrollbar for the dashboard
        self.canvas = tk.Canvas(self.dashboard_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.dashboard_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        # Configure scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack the canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Add mousewheel scrolling
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Dashboard header
        header_frame = ttk.Frame(self.scrollable_frame)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        ttk.Label(
            header_frame, 
            text="Network Traffic Dashboard",
            font=("Segoe UI", 18, "bold")
        ).pack(side="left")
        
        self.timestamp_label = ttk.Label(
            header_frame,
            text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}",
            font=("Segoe UI", 10)
        )
        self.timestamp_label.pack(side="right", padx=10)
        
        refresh_button = ttk.Button(
            header_frame,
            text="↻ Refresh",
            command=self.update_dashboard
        )
        refresh_button.pack(side="right")
        
        # Insights section
        insights_frame = ttk.LabelFrame(self.scrollable_frame, text="Traffic Insights")
        insights_frame.pack(fill="x", padx=20, pady=10)
        
        self.insights_text = tk.Text(
            insights_frame,
            wrap="word",
            height=4,
            font=("Segoe UI", 11),
            padx=10,
            pady=10,
            state="disabled"
        )
        self.insights_text.pack(fill="x", padx=10, pady=10)
        
        # Protocol distribution section
        self.protocol_frame = ttk.LabelFrame(self.scrollable_frame, text="Protocol Distribution")
        self.protocol_frame.pack(fill="x", padx=20, pady=10)
        
        # Placeholder for the protocol chart (will be updated by plotly)
        self.protocol_display = ttk.Label(self.protocol_frame, text="Loading chart...", font=("Segoe UI", 12))
        self.protocol_display.pack(pady=20)
        
        # Traffic flow section
        self.traffic_frame = ttk.LabelFrame(self.scrollable_frame, text="Traffic Flow Visualization")
        self.traffic_frame.pack(fill="x", padx=20, pady=10)
        
        # Traffic options
        traffic_options = ttk.Frame(self.traffic_frame)
        traffic_options.pack(fill="x", padx=10, pady=(10, 0))
        
        ttk.Label(traffic_options, text="Time Window:").pack(side="left", padx=(0, 5))
        
        self.time_window_var = tk.StringVar(value="All")
        time_combo = ttk.Combobox(
            traffic_options,
            textvariable=self.time_window_var,
            values=["All", "Last 1 minute", "Last 5 minutes", "Last 15 minutes"],
            width=15,
            state="readonly"
        )
        time_combo.pack(side="left", padx=5)
        time_combo.bind("<<ComboboxSelected>>", self.update_traffic_chart)
        
        # Placeholder for traffic chart
        self.traffic_display = ttk.Label(self.traffic_frame, text="Loading chart...", font=("Segoe UI", 12))
        self.traffic_display.pack(pady=20)
        
        # Categories section
        self.categories_frame = ttk.LabelFrame(self.scrollable_frame, text="Application Categories")
        self.categories_frame.pack(fill="x", padx=20, pady=10)
        
        # Placeholder for categories chart
        self.categories_display = ttk.Label(self.categories_frame, text="Loading chart...", font=("Segoe UI", 12))
        self.categories_display.pack(pady=20)
        
        # Add web view for interactive charts
        self.html_display = tk.Label(self.scrollable_frame, text="Initializing charts...")
        self.html_display.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Button to open charts in browser for better interaction
        browser_button = ttk.Button(
            self.scrollable_frame,
            text="Open Interactive Dashboard in Browser",
            command=self.open_in_browser
        )
        browser_button.pack(pady=(0, 20))
    
    def update_dashboard(self):
        """Update all dashboard components with current data."""
        # Update timestamp
        self.timestamp_label.config(text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        
        # Get visualization data
        viz_data = self.traffic_analyzer.get_visualization_data()
        
        # Update insights
        insights = self.traffic_analyzer.get_insights()
        self.update_insights(insights)
        
        # Update charts if we have data
        if viz_data["protocol_count"]:
            # Create HTML for the charts
            dashboard_data = {
                "protocol_count": viz_data["protocol_count"],
                "port_data": viz_data["port_data"],
                "application_categories": viz_data["application_categories"],
                "packet_sizes": [100, 125, 200, 342, 1340] * 10,  # Placeholder data for testing
                "timestamps": [time.time() - i * 10 for i in range(50)]  # Placeholder timestamps
            }
            
            # Create dashboard figure
            dashboard_fig = self.visualizer.create_dashboard(dashboard_data)
            
            # Create HTML for embedding
            dashboard_html = self.visualizer.get_html(dashboard_fig)
            
            # Create temporary HTML file for viewing
            self.dashboard_html_path = "/tmp/network_dashboard.html"
            with open(self.dashboard_html_path, "w") as f:
                f.write(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Network Traffic Dashboard</title>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        h1 {{ color: #375a7f; }}
                        .timestamp {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
                        .insights {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #375a7f; }}
                        .insights p {{ margin: 5px 0; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Network Traffic Dashboard</h1>
                        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                        
                        <div class="insights">
                            <h3>Traffic Insights</h3>
                            {"<p>" + "</p><p>".join(insights) + "</p>" if insights else "<p>No insights available yet.</p>"}
                        </div>
                        
                        {dashboard_html}
                    </div>
                </body>
                </html>
                """)
            
            # Update display label to notify user
            self.html_display.config(text=f"Dashboard updated. Click 'Open Interactive Dashboard in Browser' to view.")
        else:
            self.html_display.config(text="No data available for visualization yet. Start a capture to see charts.")
        
        self.last_update = time.time()
    
    def update_insights(self, insights):
        """Update the insights text box with traffic insights."""
        # Enable editing, clear content, add new insights, then disable again
        self.insights_text.config(state="normal")
        self.insights_text.delete(1.0, tk.END)
        
        if insights:
            for i, insight in enumerate(insights):
                # Add bullet point before each insight
                self.insights_text.insert(tk.END, f"• {insight}")
                if i < len(insights) - 1:
                    self.insights_text.insert(tk.END, "\n")
        else:
            self.insights_text.insert(tk.END, "Start capturing packets to see insights about your network traffic.")
        
        self.insights_text.config(state="disabled")
    
    def update_traffic_chart(self, event=None):
        """Update the traffic chart based on the selected time window."""
        # Convert time window selection to seconds
        selection = self.time_window_var.get()
        if selection == "Last 1 minute":
            window = 60
        elif selection == "Last 5 minutes":
            window = 300
        elif selection == "Last 15 minutes":
            window = 900
        else:  # "All"
            window = None
            
        # Update dashboard with new time window
        self.update_dashboard()
    
    def open_in_browser(self):
        """Open the dashboard in the default web browser for better interaction."""
        if hasattr(self, 'dashboard_html_path'):
            webbrowser.open(f"file://{self.dashboard_html_path}")
        else:
            # If no dashboard has been generated yet, update first
            self.update_dashboard()
            if hasattr(self, 'dashboard_html_path'):
                webbrowser.open(f"file://{self.dashboard_html_path}")
    
    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling."""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def check_for_updates(self):
        """Check if dashboard needs updating based on timer."""
        current_time = time.time()
        if current_time - self.last_update > self.update_interval / 1000:
            self.update_dashboard()
        
        # Schedule the next check
        self.parent.after(1000, self.check_for_updates)
