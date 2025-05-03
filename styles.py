from ttkbootstrap import Style, Colors


def apply_dark_theme(style):
    """Apply dark theme settings."""
    style.theme_use("darkly")


def apply_light_theme(style):
    """Apply light theme settings."""
    style.theme_use("minty")


def configure_treeview_style(style):
    """Configure styles for the treeview component."""
    # Basic treeview style
    style.configure(
        "Treeview", 
        font=("Segoe UI", 10), 
        rowheight=28, 
        fieldbackground=style.colors.inputbg
    )
    
    # Heading style
    style.configure(
        "Treeview.Heading", 
        font=("Segoe UI", 10, "bold"),
        padding=5,
        background=style.colors.primary,
        foreground=style.colors.bg
    )
    
    # Selected item style
    style.map(
        "Treeview",
        background=[("selected", style.colors.selectbg)],
        foreground=[("selected", style.colors.selectfg)]
    )
    
    # Configure ttk button styles
    style.configure("TButton", font=("Segoe UI", 10))
    style.configure("TLabel", font=("Segoe UI", 10))
    style.configure("TEntry", font=("Segoe UI", 10))
    style.configure("TCombobox", font=("Segoe UI", 10))


def get_theme_colors(theme_name):
    """Get color values for the current theme."""
    if theme_name == "darkly":
        return {
            "background": "#222222",
            "foreground": "#ffffff",
            "primary": "#375a7f",
            "secondary": "#444444",
            "success": "#00bc8c",
            "info": "#3498db",
            "warning": "#f39c12",
            "danger": "#e74c3c"
        }
    else:  # minty or default
        return {
            "background": "#ffffff",
            "foreground": "#555555",
            "primary": "#78c2ad",
            "secondary": "#f3969a",
            "success": "#56cc9d",
            "info": "#6cc3d5",
            "warning": "#ffce67",
            "danger": "#ff7851"
        }


def create_custom_styles(style):
    """Create additional custom styles for the application."""
    # Custom button styles
    style.configure(
        "primary.TButton",
        font=("Segoe UI", 10),
        background=style.colors.primary,
        foreground=style.colors.bg
    )
    
    style.configure(
        "success.TButton",
        font=("Segoe UI", 10),
        background=style.colors.success,
        foreground=style.colors.bg
    )
    
    style.configure(
        "danger.TButton",
        font=("Segoe UI", 10),
        background=style.colors.danger,
        foreground=style.colors.bg
    )
    
    # Custom label styles
    style.configure(
        "title.TLabel",
        font=("Segoe UI", 14, "bold"),
        foreground=style.colors.primary
    )
    
    style.configure(
        "subtitle.TLabel",
        font=("Segoe UI", 12),
        foreground=style.colors.secondary
    )
    
    # Custom frame styles
    style.configure(
        "card.TFrame",
        background=style.colors.bg,
        relief="raised",
        borderwidth=1
    )

