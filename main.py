from src.gui import NetworkAnalysisTool  # Import the main GUI class
import tkinter as tk  # Import tkinter for the root window

def main():
    # Create the root window
    root = tk.Tk()

    # Initialize the application
    app = NetworkAnalysisTool(root)

    # Start the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()
