import plotly.graph_objects as go
import plotly.io as pio
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from collections import defaultdict, Counter
import io
import base64
import os
from datetime import datetime, timedelta
import time

# Set default renderer for plotly to browser for debugging
# In production, we'll capture the output as HTML
pio.renderers.default = "browser"

class NetworkVisualizer:
    """Class to create interactive visualizations for network traffic analysis."""
    
    def __init__(self):
        """Initialize the visualizer with default styling."""
        # Define consistent color schemes for protocols
        self.protocol_colors = {
            "TCP": "#1f77b4",
            "UDP": "#ff7f0e",
            "ICMP": "#2ca02c",
            "ARP": "#d62728",
            "DNS": "#9467bd",
            "HTTP": "#8c564b",
            "HTTPS": "#e377c2",
            "Other": "#7f7f7f"
        }
        
        # Define color scheme for application categories
        self.category_colors = {
            "Web Browsing": "#1f77b4",
            "Email": "#ff7f0e",
            "File Transfer": "#2ca02c",
            "Streaming": "#d62728",
            "Gaming": "#9467bd",
            "Social Media": "#8c564b",
            "VoIP": "#e377c2",
            "Database": "#7f7f7f",
            "Remote Access": "#bcbd22",
            "Other": "#17becf"
        }
        
        # Set consistent layout properties
        self.layout_defaults = dict(
            font=dict(family="Segoe UI, Arial", size=10),
            margin=dict(l=40, r=40, t=40, b=40),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            ),
            plot_bgcolor='rgba(245, 245, 245, 0.5)',
            paper_bgcolor='rgba(255, 255, 255, 0.5)',
            height=450
        )

    def create_protocol_distribution_chart(self, protocol_count):
        """Create a pie chart showing distribution of protocols."""
        if not protocol_count:
            return self._empty_chart("No protocol data available")
            
        labels = list(protocol_count.keys())
        values = list(protocol_count.values())
        
        # Use protocol colors if available, otherwise use default
        colors = [self.protocol_colors.get(proto, self.protocol_colors["Other"]) for proto in labels]
        
        fig = go.Figure(data=[
            go.Pie(
                labels=labels, 
                values=values,
                marker_colors=colors,
                textinfo="label+percent",
                hoverinfo="label+value+percent",
                textfont_size=12,
                pull=[0.05 if label == max(protocol_count, key=protocol_count.get) else 0 for label in labels]
            )
        ])
        
        fig.update_layout(
            title="Protocol Distribution",
            **self.layout_defaults
        )
        
        return fig
        
    def create_traffic_volume_chart(self, packet_sizes, timestamps, time_window=None):
        """Create a time series chart showing traffic volume over time."""
        if not packet_sizes or not timestamps:
            return self._empty_chart("No traffic data available")
            
        # Convert timestamps to datetime if they're not already
        if isinstance(timestamps[0], (int, float)):
            timestamps = [datetime.fromtimestamp(ts) for ts in timestamps]
        
        # Filter data if time window is provided
        if time_window:
            # Time window in seconds
            cutoff_time = max(timestamps) - timedelta(seconds=time_window)
            filtered_data = [(ts, size) for ts, size in zip(timestamps, packet_sizes) if ts >= cutoff_time]
            if filtered_data:
                timestamps, packet_sizes = zip(*filtered_data)
            else:
                return self._empty_chart("No data within selected time window")
        
        # Create DataFrame with timestamps and sizes
        df = pd.DataFrame({
            'timestamp': timestamps,
            'size': packet_sizes
        })
        
        # Group by minute for readable visualization
        df['minute'] = df['timestamp'].apply(lambda x: x.replace(second=0, microsecond=0))
        traffic_by_minute = df.groupby('minute')['size'].sum().reset_index()
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=traffic_by_minute['minute'],
            y=traffic_by_minute['size'],
            mode='lines+markers',
            name='Traffic Volume',
            line=dict(color=self.protocol_colors["TCP"], width=2),
            hovertemplate='Time: %{x}<br>Volume: %{y} bytes<extra></extra>'
        ))
        
        # Add moving average for trend
        if len(traffic_by_minute) > 5:
            traffic_by_minute['MA'] = traffic_by_minute['size'].rolling(window=3, min_periods=1).mean()
            fig.add_trace(go.Scatter(
                x=traffic_by_minute['minute'],
                y=traffic_by_minute['MA'],
                mode='lines',
                name='Moving Avg (3 min)',
                line=dict(color='rgba(155, 155, 155, 0.7)', width=2, dash='dash'),
                hovertemplate='Time: %{x}<br>Moving Avg: %{y:.2f} bytes<extra></extra>'
            ))
        
        fig.update_layout(
            title="Network Traffic Volume Over Time",
            xaxis_title="Time",
            yaxis_title="Traffic Volume (bytes)",
            hovermode="x unified",
            **self.layout_defaults
        )
        
        return fig
    
    def create_source_destination_flow(self, src_dest_pairs, limit=15):
        """Create a Sankey diagram showing traffic flow between sources and destinations."""
        if not src_dest_pairs:
            return self._empty_chart("No source-destination data available")
            
        # Count occurrences of each source-destination pair
        pair_counts = Counter(src_dest_pairs)
        
        # Get top N pairs by count
        top_pairs = pair_counts.most_common(limit)
        
        # Extract unique sources and destinations
        all_ips = set()
        for (src, dst), _ in top_pairs:
            all_ips.add(src)
            all_ips.add(dst)
        
        # Create mapping from IP to index
        ip_to_idx = {ip: i for i, ip in enumerate(all_ips)}
        
        # Create source, target, and value lists for Sankey
        sources = []
        targets = []
        values = []
        for (src, dst), count in top_pairs:
            sources.append(ip_to_idx[src])
            targets.append(ip_to_idx[dst])
            values.append(count)
        
        # Create the Sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=list(all_ips),
                color="rgba(31, 119, 180, 0.8)"
            ),
            link=dict(
                source=sources,
                target=targets,
                value=values,
                hovertemplate='%{source.label} → %{target.label}<br>Packets: %{value}<extra></extra>'
            )
        )])
        
        fig.update_layout(
            title="Top Network Traffic Flows",
            **self.layout_defaults,
            height=500  # Sankey diagrams need more height
        )
        
        return fig
    
    def create_application_category_chart(self, category_counts):
        """Create a bar chart showing traffic by application category."""
        if not category_counts:
            return self._empty_chart("No category data available")
            
        categories = list(category_counts.keys())
        counts = list(category_counts.values())
        
        # Sort by count
        sorted_data = sorted(zip(categories, counts), key=lambda x: x[1], reverse=True)
        categories, counts = zip(*sorted_data) if sorted_data else ([], [])
        
        # Use category colors
        colors = [self.category_colors.get(cat, self.category_colors["Other"]) for cat in categories]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            x=categories,
            y=counts,
            marker_color=colors,
            hovertemplate='%{x}<br>Packets: %{y}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Traffic by Application Category",
            xaxis_title="Category",
            yaxis_title="Packet Count",
            **self.layout_defaults
        )
        
        return fig
    
    def create_port_analysis_chart(self, port_data):
        """Create a chart showing common ports used in the traffic."""
        if not port_data or not isinstance(port_data, dict):
            return self._empty_chart("No port data available")
            
        # Extract ports and their counts
        ports = list(port_data.keys())
        counts = list(port_data.values())
        
        # Sort by count
        sorted_data = sorted(zip(ports, counts), key=lambda x: x[1], reverse=True)[:15]  # Top 15
        ports, counts = zip(*sorted_data) if sorted_data else ([], [])
        
        # Add port descriptions where possible
        port_descriptions = {
            80: "HTTP (80)",
            443: "HTTPS (443)",
            22: "SSH (22)",
            21: "FTP (21)",
            25: "SMTP (25)",
            53: "DNS (53)",
            3389: "RDP (3389)",
            3306: "MySQL (3306)",
            5432: "PostgreSQL (5432)",
            8080: "HTTP Proxy (8080)",
            8443: "HTTPS Alt (8443)",
            1433: "MS SQL (1433)"
        }
        
        # Format port labels
        formatted_ports = [
            port_descriptions.get(int(p), f"Port {p}") if isinstance(p, (int, str)) and str(p).isdigit() else str(p)
            for p in ports
        ]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            x=formatted_ports,
            y=counts,
            marker_color='rgba(55, 83, 109, 0.7)',
            hovertemplate='%{x}<br>Count: %{y}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Top Ports Activity",
            xaxis_title="Port",
            yaxis_title="Count",
            **self.layout_defaults
        )
        
        return fig
    
    def create_packet_size_distribution(self, packet_sizes):
        """Create a histogram showing the distribution of packet sizes."""
        if not packet_sizes:
            return self._empty_chart("No packet size data available")
            
        fig = go.Figure()
        
        fig.add_trace(go.Histogram(
            x=packet_sizes,
            nbinsx=20,
            marker_color='rgba(107, 174, 214, 0.7)',
            marker_line_color='rgb(8, 81, 156)',
            marker_line_width=1,
            hovertemplate='Size: %{x} bytes<br>Count: %{y}<extra></extra>'
        ))
        
        # Add vertical lines for common packet size thresholds
        annotations = []
        
        # MTU size (typical 1500 bytes)
        if max(packet_sizes) > 1400:
            fig.add_vline(x=1500, line_dash="dash", line_color="red", line_width=1)
            annotations.append(dict(
                x=1500,
                y=0.95,
                xref="x",
                yref="paper",
                text="Typical MTU",
                showarrow=True,
                arrowhead=2,
                ax=30,
                ay=-30
            ))
        
        # Typical TCP header (20 bytes) + IP header (20 bytes)
        fig.add_vline(x=40, line_dash="dash", line_color="green", line_width=1)
        annotations.append(dict(
            x=40,
            y=0.85,
            xref="x",
            yref="paper",
            text="TCP/IP Headers",
            showarrow=True,
            arrowhead=2,
            ax=-30,
            ay=-30
        ))
        
        fig.update_layout(
            title="Packet Size Distribution",
            xaxis_title="Packet Size (bytes)",
            yaxis_title="Count",
            annotations=annotations,
            **self.layout_defaults
        )
        
        return fig
    
    def create_dashboard(self, data):
        """Create a comprehensive dashboard with multiple charts."""
        # Create a 2x3 subplot grid
        fig = make_subplots(
            rows=2, cols=3,
            specs=[
                [{"type": "pie", "colspan": 1}, {"type": "xy", "colspan": 2}, None],
                [{"type": "xy", "colspan": 1}, {"type": "xy", "colspan": 1}, {"type": "xy", "colspan": 1}]
            ],
            subplot_titles=(
                "Protocol Distribution", "Traffic Over Time", "",
                "Application Categories", "Top Ports", "Packet Sizes"
            )
        )
        
        # Add charts to the dashboard
        if data.get('protocol_count'):
            protocol_fig = self.create_protocol_distribution_chart(data['protocol_count'])
            fig.add_trace(protocol_fig.data[0], row=1, col=1)
        
        if data.get('packet_sizes') and data.get('timestamps'):
            traffic_fig = self.create_traffic_volume_chart(data['packet_sizes'], data['timestamps'])
            for trace in traffic_fig.data:
                fig.add_trace(trace, row=1, col=2)
        
        if data.get('application_categories'):
            category_fig = self.create_application_category_chart(data['application_categories'])
            fig.add_trace(category_fig.data[0], row=2, col=1)
        
        if data.get('port_data'):
            port_fig = self.create_port_analysis_chart(data['port_data'])
            fig.add_trace(port_fig.data[0], row=2, col=2)
        
        if data.get('packet_sizes'):
            size_fig = self.create_packet_size_distribution(data['packet_sizes'])
            fig.add_trace(size_fig.data[0], row=2, col=3)
        
        # Update layout
        fig.update_layout(
            title="Network Traffic Analysis Dashboard",
            height=800,
            showlegend=False,
            **{k: v for k, v in self.layout_defaults.items() if k != 'height'}
        )
        
        return fig
    
    def _empty_chart(self, message="No data available"):
        """Create an empty chart with a message when no data is available."""
        fig = go.Figure()
        
        fig.add_annotation(
            text=message,
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=14)
        )
        
        fig.update_layout(
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            **self.layout_defaults
        )
        
        return fig
    
    def get_html(self, fig):
        """Convert a plotly figure to HTML for embedding in a web view."""
        return pio.to_html(fig, include_plotlyjs='cdn', full_html=False)
    
    def get_pdf_image(self, fig):
        """Generate a PNG image of the figure for PDF reports."""
        img_bytes = fig.to_image(format="png", width=800, height=500, scale=2)
        return img_bytes
    
    def save_figure(self, fig, filename):
        """Save a figure to a file."""
        pio.write_image(fig, filename)
        return filename
