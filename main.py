#!/usr/bin/env python3
"""
Network Analysis Tool - Main Entry Point
This script starts the Network Analysis Tool with the enhanced dashboard capabilities.
"""

import tkinter as tk
from functionality import get_available_interfaces
from gui import NetworkAnalysisTool

def main():
    """Main entry point for the application."""
    print("Starting Network Analysis Tool...")
    
    # Get available network interfaces
    print("Detecting network interfaces...")
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("No network interfaces detected. Using simulation mode.")
        interfaces = ["eth0", "wlan0", "lo"]
    
    print(f"Found interfaces: {interfaces}")
    
    # Create the main application window
    root = tk.Tk()
    app = NetworkAnalysisTool(root, interfaces)
    
    # Start the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()