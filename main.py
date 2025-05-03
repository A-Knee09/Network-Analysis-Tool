import tkinter as tk
from tkinter import messagebox
from gui import NetworkAnalysisTool
from functionality import get_available_interfaces
import sys

def main():
    """Main entry point for the application."""
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the root window initially
        
        # Check if Kamene is available
        try:
            from kamene.all import conf
        except ImportError:
            messagebox.showerror(
                "Missing Dependency", 
                "Kamene is required for this application to run. Please install it using 'pip install kamene'."
            )
            sys.exit(1)
        
        # Get available interfaces
        available_interfaces = get_available_interfaces()
        
        if not available_interfaces:
            messagebox.showerror(
                "No Interfaces", 
                "No network interfaces were detected. Please check your network configuration."
            )
            sys.exit(1)
        
        app = NetworkAnalysisTool(root, available_interfaces)
        root.deiconify()  # Show the main window after initialization
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

