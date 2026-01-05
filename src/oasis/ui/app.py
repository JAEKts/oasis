"""
OASIS Application Launcher

Provides the main application entry point for the PyQt6 GUI.
"""

import sys
from typing import Optional
from PyQt6.QtWidgets import QApplication

from .main_window import MainWindow
from .theme import apply_theme
from ..core.logging import get_logger


logger = get_logger(__name__)


class OASISApplication:
    """
    Main OASIS application class.

    Manages the PyQt6 application lifecycle and main window.
    """

    def __init__(self, theme: str = "dark") -> None:
        """
        Initialize the OASIS application.

        Args:
            theme: UI theme to apply ("dark" or "light")
        """
        self.theme = theme
        self.app: Optional[QApplication] = None
        self.main_window: Optional[MainWindow] = None

    def run(self) -> int:
        """
        Run the OASIS application.

        Returns:
            Application exit code
        """
        try:
            # Create application
            self.app = QApplication(sys.argv)
            self.app.setApplicationName("OASIS")
            self.app.setOrganizationName("OASIS Team")
            self.app.setOrganizationDomain("oasis-pentest.org")

            # Apply theme
            apply_theme(self.app, self.theme)

            # Create and show main window
            self.main_window = MainWindow()
            self.main_window.show()

            logger.info("OASIS application started")

            # Run event loop
            return self.app.exec()

        except Exception as e:
            logger.error(f"Failed to start OASIS application: {e}")
            return 1

    def quit(self) -> None:
        """Quit the application gracefully."""
        if self.app:
            self.app.quit()
            logger.info("OASIS application quit")


def launch_gui(theme: str = "dark") -> int:
    """
    Launch the OASIS GUI application.

    Args:
        theme: UI theme to apply ("dark" or "light")

    Returns:
        Application exit code
    """
    app = OASISApplication(theme=theme)
    return app.run()
