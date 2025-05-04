"""
Dashboard Package - Provides visualization and analysis dashboards for the Network Analysis Tool
"""

# Import dashboard classes to make them available when importing from this package
from .network_dashboard import NetworkDashboard
from .statistics_dashboard import StatisticsDashboard
from .device_dashboard import DeviceDashboard

# Make these classes available when importing from the dashboard package
__all__ = [
    'NetworkDashboard',
    'StatisticsDashboard',
    'DeviceDashboard'
]