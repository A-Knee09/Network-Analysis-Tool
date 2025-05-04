# Network Analysis Tool

A comprehensive network traffic analysis and monitoring toolkit developed as a final year project. This application captures, analyzes, and visualizes network traffic data in real-time.

## Features

- **Real-time Packet Capture**: Capture and display network packets with detailed information
- **Protocol Analysis**: Analyze TCP, UDP, ICMP, ARP, and other network protocols
- **Filtering Capabilities**: Filter packets by protocol, IP address, or port number
- **Interactive Dashboards**:
  - Network Dashboard: Visualize network traffic flow and patterns
  - Statistics Dashboard: View protocol distribution and packet statistics
  - Device Profiler: Monitor device-specific traffic and behavior
- **PCAP Support**: Save and load packet captures in standard PCAP format
- **CSV Export**: Export packet data to CSV for further analysis
- **PDF Reporting**: Generate comprehensive PDF reports with visualizations
- **Light/Dark Mode**: Toggle between light and dark themes

## Technical Details

### Built With

- Python 3.11
- Tkinter/ttk for the GUI components
- ttkbootstrap for modern UI styling
- Kamene (Scapy fork) for packet capture and analysis
- Matplotlib and Plotly for data visualization
- FPDF for PDF report generation

### Key Components

- **Packet Capture Engine**: Interfaces with network adapters to capture raw packets
- **Analysis Module**: Processes packet data into useful information
- **Visualization System**: Converts network data into interactive charts and graphs
- **Dashboard Framework**: Organizes visualizations into meaningful, actionable displays

## Usage

1. **Select Network Interface**: Choose which network interface to monitor
2. **Start Capture**: Begin collecting packet data from the selected interface
3. **Analyze Traffic**: Use the dashboards to analyze network behavior
4. **Export Data**: Save captures for later analysis or generate reports

## Installation

The application requires Python 3.8+ and several dependencies. Follow these steps to set up the environment:

### Clone the Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/network-analysis-tool.git
cd network-analysis-tool
```

### Create and Activate Virtual Environment

#### On Windows:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

#### On macOS/Linux:
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

### Run the Application

```bash
sudo venv/bin/python3 main.py  # For linux , and for windows run it in admin mode
```

## Screenshots

### Main Interface
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/a02a4e96-4496-4b42-a014-6a6f84df7b88" alt="Light mode main interface" width="400"/></td>
    <td><img src="https://github.com/user-attachments/assets/43a8a1a6-78e9-4fe4-9ca7-fba8dc5a0218" alt="Dark mode main interface" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Light Mode</td>
    <td align="center">Dark Mode</td>
  </tr>
</table>

### Start Capture
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/71842526-d6c0-4d27-9f09-9b2c6c18f3e4" alt="Light Mode Network Dashboard" width="400"/></td>
    <td><img src="https://github.com/user-attachments/assets/23742fcb-b50f-4f41-be42-f7f300cd700b" alt="Dark Mode Network Dashboard" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Light Mode</td>
    <td align="center">Dark Mode</td>
  </tr>
</table>

### Network Dashboard
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/d8fc8d47-20ef-4758-9cef-50ab8cf3647f" alt="Light Mode Network Dashboard" width="400"/></td>
    <td><img src="https://github.com/user-attachments/assets/94b411e6-1816-4fa7-87c6-10839b336bb9" alt="Dark Mode Network Dashboard" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Light Mode</td>
    <td align="center">Dark Mode</td>
  </tr>
</table>

### Statistics Dashboard
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/6b943305-a44f-439f-a614-41d5764efd26" alt="Light Mode Statistics Dashboard" width="400"/></td>
    <td><img src="https://github.com/user-attachments/assets/4e3ba7f5-1c1d-4919-ba59-e2d3e2b930d3" alt="Dark Mode Statistics Dashboard" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Light Mode</td>
    <td align="center">Dark Mode</td>
  </tr>
</table>

### Device Profiler
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/b7f8a848-62f2-491a-abb0-5745d9e1afca" alt="Light Mode Device Profiler" width="400"/></td>
    <td><img src="https://github.com/user-attachments/assets/9ba3bccc-c5ec-4745-bfd6-75047e09480b" alt="Dark Mode Device Profiler" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Light Mode</td>
    <td align="center">Dark Mode</td>
  </tr>
</table>

### About Dialog
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/4debd0d0-af09-4f83-9aff-3d0d5b4609b3" alt="Light Mode About Dialog" width="400"/></td>
    <td><img src="https://github.com/user-attachments/assets/bfd6da9f-d78a-4194-9312-d7aaf3c08651" alt="Dark Mode About Dialog" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Light Mode</td>
    <td align="center">Dark Mode</td>
  </tr>
</table>

Note: These are placeholder image references. Replace them with actual screenshots from your application.

## Development Notes

This project was developed as a final year academic project to demonstrate network analysis principles and GUI development skills. The tool provides a practical implementation of networking concepts including:

- Packet capture and analysis
- Network protocol interpretation
- Data visualization techniques
- User interface design

## License

This project is for educational purposes only, created for academic submission.

## Author

Developed by Anirudh Saksena :D
