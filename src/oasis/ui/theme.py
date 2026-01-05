"""
OASIS UI Theme and Styling

Provides consistent theming and styling for the OASIS desktop application.
"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtCore import Qt


def apply_theme(app: QApplication, theme: str = "dark") -> None:
    """
    Apply a consistent theme to the application.

    Args:
        app: The QApplication instance
        theme: Theme name ("dark" or "light")
    """
    if theme == "dark":
        _apply_dark_theme(app)
    else:
        _apply_light_theme(app)

    # Apply custom stylesheet
    app.setStyleSheet(_get_stylesheet(theme))


def _apply_dark_theme(app: QApplication) -> None:
    """Apply dark theme color palette."""
    palette = QPalette()

    # Base colors
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(35, 35, 35))

    # Disabled colors
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.WindowText,
        QColor(127, 127, 127),
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(127, 127, 127)
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.ButtonText,
        QColor(127, 127, 127),
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.Highlight, QColor(80, 80, 80)
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled,
        QPalette.ColorRole.HighlightedText,
        QColor(127, 127, 127),
    )

    app.setPalette(palette)


def _apply_light_theme(app: QApplication) -> None:
    """Apply light theme color palette."""
    palette = QPalette()

    # Base colors
    palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 0, 0))
    palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
    palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
    palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 0, 0))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(0, 0, 255))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 215))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))

    app.setPalette(palette)


def _get_stylesheet(theme: str) -> str:
    """
    Get custom stylesheet for the application.

    Args:
        theme: Theme name ("dark" or "light")

    Returns:
        CSS stylesheet string
    """
    if theme == "dark":
        return """
            QMainWindow {
                background-color: #353535;
            }
            
            QMenuBar {
                background-color: #2b2b2b;
                color: #ffffff;
                border-bottom: 1px solid #1a1a1a;
            }
            
            QMenuBar::item:selected {
                background-color: #2a82da;
            }
            
            QMenu {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #1a1a1a;
            }
            
            QMenu::item:selected {
                background-color: #2a82da;
            }
            
            QToolBar {
                background-color: #2b2b2b;
                border: none;
                spacing: 3px;
                padding: 3px;
            }
            
            QToolButton {
                background-color: transparent;
                border: none;
                padding: 5px;
                margin: 2px;
            }
            
            QToolButton:hover {
                background-color: #404040;
                border-radius: 3px;
            }
            
            QToolButton:pressed {
                background-color: #2a82da;
                border-radius: 3px;
            }
            
            QStatusBar {
                background-color: #2b2b2b;
                color: #ffffff;
                border-top: 1px solid #1a1a1a;
            }
            
            QTabWidget::pane {
                border: 1px solid #1a1a1a;
                background-color: #353535;
            }
            
            QTabBar::tab {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 8px 16px;
                border: 1px solid #1a1a1a;
                border-bottom: none;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background-color: #353535;
                border-bottom: 2px solid #2a82da;
            }
            
            QTabBar::tab:hover {
                background-color: #404040;
            }
            
            QTableWidget {
                background-color: #232323;
                alternate-background-color: #2b2b2b;
                gridline-color: #1a1a1a;
                selection-background-color: #2a82da;
            }
            
            QHeaderView::section {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #1a1a1a;
            }
            
            QTextEdit, QPlainTextEdit {
                background-color: #232323;
                color: #ffffff;
                border: 1px solid #1a1a1a;
                selection-background-color: #2a82da;
            }
            
            QPushButton {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #1a1a1a;
                padding: 6px 12px;
                border-radius: 3px;
            }
            
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            
            QPushButton:pressed {
                background-color: #2a82da;
            }
            
            QPushButton:disabled {
                background-color: #2b2b2b;
                color: #7f7f7f;
            }
            
            QLineEdit, QComboBox {
                background-color: #232323;
                color: #ffffff;
                border: 1px solid #1a1a1a;
                padding: 4px;
                border-radius: 3px;
            }
            
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #2a82da;
            }
            
            QScrollBar:vertical {
                background-color: #2b2b2b;
                width: 12px;
                margin: 0px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #505050;
                min-height: 20px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #606060;
            }
            
            QScrollBar:horizontal {
                background-color: #2b2b2b;
                height: 12px;
                margin: 0px;
            }
            
            QScrollBar::handle:horizontal {
                background-color: #505050;
                min-width: 20px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background-color: #606060;
            }
            
            QSplitter::handle {
                background-color: #1a1a1a;
            }
            
            QSplitter::handle:hover {
                background-color: #2a82da;
            }
        """
    else:
        return """
            QMainWindow {
                background-color: #f0f0f0;
            }
            
            QMenuBar {
                background-color: #ffffff;
                color: #000000;
                border-bottom: 1px solid #d0d0d0;
            }
            
            QMenuBar::item:selected {
                background-color: #0078d7;
                color: #ffffff;
            }
            
            QToolBar {
                background-color: #ffffff;
                border: none;
                spacing: 3px;
                padding: 3px;
            }
            
            QStatusBar {
                background-color: #ffffff;
                color: #000000;
                border-top: 1px solid #d0d0d0;
            }
            
            QTabWidget::pane {
                border: 1px solid #d0d0d0;
                background-color: #ffffff;
            }
            
            QTabBar::tab {
                background-color: #f0f0f0;
                color: #000000;
                padding: 8px 16px;
                border: 1px solid #d0d0d0;
                border-bottom: none;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-bottom: 2px solid #0078d7;
            }
            
            QPushButton {
                background-color: #e0e0e0;
                color: #000000;
                border: 1px solid #d0d0d0;
                padding: 6px 12px;
                border-radius: 3px;
            }
            
            QPushButton:hover {
                background-color: #d0d0d0;
            }
            
            QPushButton:pressed {
                background-color: #0078d7;
                color: #ffffff;
            }
        """
