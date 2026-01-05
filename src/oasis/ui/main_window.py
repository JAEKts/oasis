"""
OASIS Main Window

Provides the main application window with tabbed interface for all tools.
"""

from typing import Optional
from PyQt6.QtWidgets import (
    QMainWindow,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QMenuBar,
    QMenu,
    QToolBar,
    QStatusBar,
    QMessageBox,
    QLabel,
    QDialog,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence

from ..core.logging import get_logger


logger = get_logger(__name__)


class MainWindow(QMainWindow):
    """
    Main application window for OASIS.

    Provides tabbed interface for all penetration testing tools with
    menu system, toolbar, and status bar.
    """

    # Signals for real-time updates
    status_updated = pyqtSignal(str)
    connection_count_changed = pyqtSignal(int)

    def __init__(self) -> None:
        """Initialize the main window."""
        super().__init__()

        self._connection_count = 0
        self._status_label: Optional[QLabel] = None
        self._connection_label: Optional[QLabel] = None

        self._setup_ui()
        self._create_menu_bar()
        self._create_toolbar()
        self._create_status_bar()
        self._setup_signals()

        logger.info("Main window initialized")

    def _setup_ui(self) -> None:
        """Set up the main UI layout."""
        self.setWindowTitle("OASIS - Open Architecture Security Interception Suite")
        self.setGeometry(100, 100, 1400, 900)

        # Create central widget with tab interface
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout(self.central_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        # Create tab widget for tools
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(False)
        self.tab_widget.setMovable(True)
        self.tab_widget.setDocumentMode(True)

        layout.addWidget(self.tab_widget)

        # Placeholder tabs will be replaced by actual tool widgets
        self._add_placeholder_tabs()

    def _add_placeholder_tabs(self) -> None:
        """Add tool tabs with actual widgets where implemented."""
        from .widgets import ProxyWidget, RepeaterWidget, ScannerWidget, IntruderWidget

        # Proxy tab (implemented)
        self.proxy_widget = ProxyWidget()
        self.tab_widget.addTab(self.proxy_widget, "Proxy")

        # Repeater tab (implemented)
        self.repeater_widget = RepeaterWidget()
        self.tab_widget.addTab(self.repeater_widget, "Repeater")

        # Scanner tab (implemented)
        self.scanner_widget = ScannerWidget()
        self.tab_widget.addTab(self.scanner_widget, "Scanner")

        # Intruder tab (implemented)
        self.intruder_widget = IntruderWidget()
        self.tab_widget.addTab(self.intruder_widget, "Intruder")

        # Placeholder tabs for remaining tools
        placeholder_tabs = [
            ("Decoder", "Data encoding/decoding"),
            ("Sequencer", "Token analysis"),
            ("Collaborator", "Out-of-band testing"),
            ("Extensions", "Plugin management"),
        ]

        for tab_name, description in placeholder_tabs:
            widget = QWidget()
            layout = QVBoxLayout(widget)
            label = QLabel(f"{tab_name}\n\n{description}\n\n(Implementation pending)")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(label)
            self.tab_widget.addTab(widget, tab_name)

        # Connect inter-widget signals
        self.proxy_widget.send_to_repeater.connect(self.repeater_widget.add_request)
        self.proxy_widget.send_to_scanner.connect(self._send_to_scanner)
        self.proxy_widget.send_to_intruder.connect(self._send_to_intruder)

    def _send_to_scanner(self, request) -> None:
        """Send request to scanner and switch to scanner tab."""
        self.tab_widget.setCurrentIndex(2)  # Scanner tab
        logger.info("Switched to scanner tab")

    def _send_to_intruder(self, request) -> None:
        """Send request to intruder and switch to intruder tab."""
        # Format request as template with injection markers
        from urllib.parse import urlparse

        parsed = urlparse(request.url)
        template = f"{request.method} {parsed.path} HTTP/1.1\n"
        template += f"Host: {parsed.netloc}\n"
        for key, value in request.headers.items():
            if key.lower() != "host":
                template += f"{key}: {value}\n"

        self.intruder_widget.set_request_template(template)
        self.tab_widget.setCurrentIndex(3)  # Intruder tab
        logger.info("Switched to intruder tab")

    def _create_menu_bar(self) -> None:
        """Create the application menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        new_project_action = QAction("&New Project", self)
        new_project_action.setShortcut(QKeySequence.StandardKey.New)
        new_project_action.triggered.connect(self._on_new_project)
        file_menu.addAction(new_project_action)

        open_project_action = QAction("&Open Project", self)
        open_project_action.setShortcut(QKeySequence.StandardKey.Open)
        open_project_action.triggered.connect(self._on_open_project)
        file_menu.addAction(open_project_action)

        save_project_action = QAction("&Save Project", self)
        save_project_action.setShortcut(QKeySequence.StandardKey.Save)
        save_project_action.triggered.connect(self._on_save_project)
        file_menu.addAction(save_project_action)

        file_menu.addSeparator()

        export_menu = file_menu.addMenu("&Export")

        export_xml_action = QAction("Export as &XML", self)
        export_xml_action.triggered.connect(lambda: self._on_export("xml"))
        export_menu.addAction(export_xml_action)

        export_json_action = QAction("Export as &JSON", self)
        export_json_action.triggered.connect(lambda: self._on_export("json"))
        export_menu.addAction(export_json_action)

        export_pdf_action = QAction("Export as &PDF", self)
        export_pdf_action.triggered.connect(lambda: self._on_export("pdf"))
        export_menu.addAction(export_pdf_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("&Edit")

        preferences_action = QAction("&Preferences", self)
        preferences_action.setShortcut(QKeySequence("Ctrl+,"))
        preferences_action.triggered.connect(self._on_preferences)
        edit_menu.addAction(preferences_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        theme_menu = view_menu.addMenu("&Theme")

        dark_theme_action = QAction("&Dark Theme", self)
        dark_theme_action.triggered.connect(lambda: self._on_change_theme("dark"))
        theme_menu.addAction(dark_theme_action)

        light_theme_action = QAction("&Light Theme", self)
        light_theme_action.triggered.connect(lambda: self._on_change_theme("light"))
        theme_menu.addAction(light_theme_action)

        # Tools menu
        tools_menu = menubar.addMenu("&Tools")

        proxy_action = QAction("&Proxy", self)
        proxy_action.setShortcut(QKeySequence("Ctrl+1"))
        proxy_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        tools_menu.addAction(proxy_action)

        repeater_action = QAction("&Repeater", self)
        repeater_action.setShortcut(QKeySequence("Ctrl+2"))
        repeater_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        tools_menu.addAction(repeater_action)

        scanner_action = QAction("&Scanner", self)
        scanner_action.setShortcut(QKeySequence("Ctrl+3"))
        scanner_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        tools_menu.addAction(scanner_action)

        intruder_action = QAction("&Intruder", self)
        intruder_action.setShortcut(QKeySequence("Ctrl+4"))
        intruder_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(3))
        tools_menu.addAction(intruder_action)

        tools_menu.addSeparator()

        search_action = QAction("&Search Project Data", self)
        search_action.setShortcut(QKeySequence.StandardKey.Find)
        search_action.triggered.connect(self._on_search_project)
        tools_menu.addAction(search_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        documentation_action = QAction("&Documentation", self)
        documentation_action.setShortcut(QKeySequence.StandardKey.HelpContents)
        documentation_action.triggered.connect(self._on_documentation)
        help_menu.addAction(documentation_action)

        help_menu.addSeparator()

        about_action = QAction("&About OASIS", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _create_toolbar(self) -> None:
        """Create the application toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Proxy control actions
        start_proxy_action = QAction("Start Proxy", self)
        start_proxy_action.triggered.connect(self._on_start_proxy)
        toolbar.addAction(start_proxy_action)

        stop_proxy_action = QAction("Stop Proxy", self)
        stop_proxy_action.triggered.connect(self._on_stop_proxy)
        toolbar.addAction(stop_proxy_action)

        toolbar.addSeparator()

        # Scanner actions
        start_scan_action = QAction("Start Scan", self)
        start_scan_action.triggered.connect(self._on_start_scan)
        toolbar.addAction(start_scan_action)

        stop_scan_action = QAction("Stop Scan", self)
        stop_scan_action.triggered.connect(self._on_stop_scan)
        toolbar.addAction(stop_scan_action)

        toolbar.addSeparator()

        # Clear history action
        clear_history_action = QAction("Clear History", self)
        clear_history_action.triggered.connect(self._on_clear_history)
        toolbar.addAction(clear_history_action)

    def _create_status_bar(self) -> None:
        """Create the application status bar with real-time updates."""
        statusbar = QStatusBar()
        self.setStatusBar(statusbar)

        # Status message label
        self._status_label = QLabel("Ready")
        statusbar.addWidget(self._status_label)

        # Spacer
        statusbar.addPermanentWidget(QLabel("  |  "))

        # Connection count label
        self._connection_label = QLabel("Connections: 0")
        statusbar.addPermanentWidget(self._connection_label)

        # Update timer for real-time status
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._update_status)
        self._status_timer.start(1000)  # Update every second

    def _setup_signals(self) -> None:
        """Set up signal connections for real-time updates."""
        self.status_updated.connect(self._on_status_updated)
        self.connection_count_changed.connect(self._on_connection_count_changed)

    def _update_status(self) -> None:
        """Update status bar with current system state."""
        # This will be connected to actual system metrics
        pass

    def _on_status_updated(self, message: str) -> None:
        """Handle status update signal."""
        if self._status_label:
            self._status_label.setText(message)
        logger.debug(f"Status updated: {message}")

    def _on_connection_count_changed(self, count: int) -> None:
        """Handle connection count change signal."""
        self._connection_count = count
        if self._connection_label:
            self._connection_label.setText(f"Connections: {count}")

    # Menu action handlers
    def _on_new_project(self) -> None:
        """Handle new project action."""
        logger.info("New project requested")

        from .dialogs import NewProjectDialog

        dialog = NewProjectDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            project_info = dialog.get_project_info()
            logger.info(f"Creating project: {project_info['name']}")

            self.update_status(f"Created project: {project_info['name']}")
            QMessageBox.information(
                self,
                "Project Created",
                f"Project '{project_info['name']}' created successfully",
            )

    def _on_open_project(self) -> None:
        """Handle open project action."""
        logger.info("Open project requested")

        from .dialogs import OpenProjectDialog

        dialog = OpenProjectDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            project_path = dialog.get_project_path()
            logger.info(f"Opening project: {project_path}")

            self.update_status(f"Opened project: {project_path}")

    def _on_save_project(self) -> None:
        """Handle save project action."""
        logger.info("Save project requested")

        self.update_status("Project saved")
        QMessageBox.information(self, "Project Saved", "Project saved successfully")

    def _on_export(self, format: str) -> None:
        """Handle export action."""
        logger.info(f"Export requested: {format}")

        from .dialogs import ExportDialog

        dialog = ExportDialog(export_format=format, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            export_info = dialog.get_export_info()
            logger.info(f"Exporting to: {export_info['path']}")

            self.update_status(f"Exported as {format.upper()}")
            QMessageBox.information(
                self, "Export Complete", f"Project exported to {export_info['path']}"
            )

    def _on_preferences(self) -> None:
        """Handle preferences action."""
        logger.info("Preferences requested")
        self.update_status("Opening preferences...")

    def _on_change_theme(self, theme: str) -> None:
        """Handle theme change action."""
        logger.info(f"Theme change requested: {theme}")
        from .theme import apply_theme

        apply_theme(
            self.window()
            .windowHandle()
            .screen()
            .grabWindow(0)
            .toImage()
            .pixelColor(0, 0),
            theme,
        )
        self.update_status(f"Applied {theme} theme")

    def _on_documentation(self) -> None:
        """Handle documentation action."""
        logger.info("Documentation requested")
        self.update_status("Opening documentation...")

    def _on_about(self) -> None:
        """Handle about action."""
        QMessageBox.about(
            self,
            "About OASIS",
            "<h2>OASIS</h2>"
            "<p>Open Architecture Security Interception Suite</p>"
            "<p>Version 0.1.0</p>"
            "<p>A comprehensive, open-source penetration testing platform</p>"
            "<p>© 2024 OASIS Team</p>",
        )

    # Toolbar action handlers
    def _on_start_proxy(self) -> None:
        """Handle start proxy action."""
        logger.info("Start proxy requested")
        self.update_status("Starting proxy...")

    def _on_stop_proxy(self) -> None:
        """Handle stop proxy action."""
        logger.info("Stop proxy requested")
        self.update_status("Stopping proxy...")

    def _on_start_scan(self) -> None:
        """Handle start scan action."""
        logger.info("Start scan requested")
        self.update_status("Starting scan...")

    def _on_stop_scan(self) -> None:
        """Handle stop scan action."""
        logger.info("Stop scan requested")
        self.update_status("Stopping scan...")

    def _on_clear_history(self) -> None:
        """Handle clear history action."""
        logger.info("Clear history requested")
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear all proxy history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.update_status("Clearing history...")

    def _on_search_project(self) -> None:
        """Handle search project data action."""
        logger.info("Search project data requested")

        from .widgets.search_widget import SearchWidget

        # Create search dialog
        search_dialog = QDialog(self)
        search_dialog.setWindowTitle("Search Project Data")
        search_dialog.setModal(False)
        search_dialog.resize(800, 600)

        layout = QVBoxLayout(search_dialog)
        search_widget = SearchWidget()
        layout.addWidget(search_widget)

        search_dialog.show()
        logger.info("Opened search dialog")

    # Public methods
    def update_status(self, message: str) -> None:
        """
        Update the status bar message.

        Args:
            message: Status message to display
        """
        self.status_updated.emit(message)

    def update_connection_count(self, count: int) -> None:
        """
        Update the connection count display.

        Args:
            count: Number of active connections
        """
        self.connection_count_changed.emit(count)

    def add_tool_tab(
        self, widget: QWidget, title: str, index: Optional[int] = None
    ) -> None:
        """
        Add or replace a tool tab.

        Args:
            widget: The widget to add as a tab
            title: Tab title
            index: Optional index to replace existing tab
        """
        if index is not None and index < self.tab_widget.count():
            self.tab_widget.removeTab(index)
            self.tab_widget.insertTab(index, widget, title)
        else:
            self.tab_widget.addTab(widget, title)

        logger.info(f"Added tool tab: {title}")
