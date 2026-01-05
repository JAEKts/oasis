"""
OASIS User Interface Module

Provides PyQt6-based desktop application interface for OASIS.
"""

from .main_window import MainWindow
from .theme import apply_theme

__all__ = ["MainWindow", "apply_theme"]
