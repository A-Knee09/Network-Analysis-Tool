#!/usr/bin/env python3
"""
Network Analysis Tool - Main Entry Point
This script starts the Network Analysis Tool with the enhanced dashboard capabilities.
"""

import tkinter as tk
import ttkbootstrap as ttk
from functionality import get_available_interfaces
from gui import NetworkAnalysisTool
import logging
import matplotlib
import os
import sys
import platform

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_matplotlib():
    """Configure matplotlib to avoid font errors."""
    # Use Agg backend (non-interactive, generates PNGs)
    matplotlib.use('Agg')
    
    # Fix font caching issues in matplotlib
    try:
        # Set a specific font family to avoid font cache issues
        matplotlib.rcParams['font.family'] = 'sans-serif'
        matplotlib.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'Tahoma', 'Verdana']
        
        # Fix the specific font error by using a default font
        import matplotlib.font_manager as fm
        
        # Clear any existing font cache
        try:
            fm._get_fontconfig_fonts.cache_clear()
        except:
            logger.warning("Could not clear font cache")
        
        # Use built-in matplotlib fonts instead of system fonts
        # This avoids issues with system font paths
        matplotlib.rcParams['font.family'] = 'monospace'
        
        # Ensure we're not using any problematic font paths
        fm.fontManager.defaultFamily = {'ttf': 'DejaVu Sans',
                                       'afm': 'Helvetica'}
                
        # Get a specific font file directly from matplotlib's package
        default_font = fm.findfont(fm.FontProperties(family=['sans-serif']))
        logger.info(f"Using default font: {default_font}")
        
    except Exception as e:
        logger.warning(f"Could not configure matplotlib fonts: {e}")
        # Fallback to a more drastic solution if everything else fails
        try:
            # Force matplotlib to use a built-in font
            matplotlib.rcParams['font.family'] = 'monospace'
        except:
            pass

def main():
    """Main entry point for the application."""
    print("Starting Network Analysis Tool...")
    
    # Configure matplotlib to avoid font errors
    setup_matplotlib()
    
    # Get available network interfaces
    print("Detecting network interfaces...")
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("No network interfaces detected. Using simulation mode.")
        interfaces = [("eth0", "192.168.1.1"), ("wlan0", "192.168.1.2"), ("lo", "127.0.0.1")]
    
    print(f"Found interfaces: {interfaces}")
    
    # Create the main application window with ttkbootstrap and darkly theme
    root = ttk.Window(themename="darkly")
    root.title("Network Analysis Tool")
    app = NetworkAnalysisTool(root, interfaces)
    
    # Start the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()
