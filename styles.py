"""
Styles module for the Network Analysis Tool
This module contains functions to control styling of the application
"""

import tkinter as tk

def apply_dark_theme(root):
    """Apply dark theme to the application."""
    bg_color = "#1a1a1a"
    text_color = "#ffffff"
    accent_color = "#3498db"
    
    root.configure(bg=bg_color)
    
    # Configure styles for widgets
    style = root.tk_setPalette(
        background=bg_color,
        foreground=text_color,
        activeBackground=accent_color,
        activeForeground=text_color
    )
    
    return style

def apply_light_theme(root):
    """Apply light theme to the application."""
    bg_color = "#f9f9f9"
    text_color = "#333333"
    accent_color = "#3498db"
    
    root.configure(bg=bg_color)
    
    # Configure styles for widgets
    style = root.tk_setPalette(
        background=bg_color,
        foreground=text_color,
        activeBackground=accent_color,
        activeForeground=text_color
    )
    
    return style

def configure_treeview_style(style):
    """Configure style for ttk.Treeview widgets."""
    # Get the current theme colors
    colors = get_theme_colors(style.theme_use())
    
    # Configure the Treeview style
    style.configure(
        "Treeview",
        background=colors["background"],
        foreground=colors["text"],
        fieldbackground=colors["background"]
    )
    
    # Configure the Treeview heading style
    style.configure(
        "Treeview.Heading",
        background=colors["secondary"],
        foreground=colors["text"],
        relief="flat"
    )
    
    # Configure selection colors
    style.map(
        "Treeview",
        background=[("selected", "#3498db")],
        foreground=[("selected", "#ffffff")]
    )

def get_theme_colors(theme_name):
    """Get color scheme for the current theme."""
    if theme_name == "darkly":
        return {
            "background": "#1a1a1a",
            "secondary": "#2a2a2a",
            "text": "#ffffff",
            "accent": "#3498db"
        }
    else:  # Light theme or any other
        return {
            "background": "#f8f9fa",
            "secondary": "#e9ecef",
            "text": "#212529",
            "accent": "#3498db"
        }

def get_protocol_color(protocol):
    """Get color for the protocol."""
    protocol_colors = {
        "TCP": "#3498db",
        "UDP": "#2ecc71",
        "ICMP": "#e74c3c",
        "ARP": "#f39c12",
        "DNS": "#9b59b6",
        "HTTP": "#1abc9c",
        "HTTPS": "#16a085",
        "TLS": "#27ae60",
        "SSH": "#f1c40f",
        "FTP": "#e67e22",
        "SMTP": "#d35400",
        "Other": "#95a5a6"
    }
    
    # If protocol contains a known key, return that color
    for key in protocol_colors:
        if key in protocol:
            return protocol_colors[key]
            
    # Default color
    return protocol_colors["Other"]