# To make things prettier :D

from ttkbootstrap import Style


def apply_dark_theme(style):
    style.theme_use("superhero")


def apply_light_theme(style):
    style.theme_use("minty")


def configure_treeview_style(style):
    style.configure("Treeview", font=("Arial", 10), rowheight=25, background="#ffffff", fieldbackground="#ffffff")
    style.configure("Treeview.Heading", font=("Arial", 10, "bold"))


