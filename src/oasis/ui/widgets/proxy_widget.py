"""
Proxy Widget

Provides the UI for HTTP/HTTPS traffic interception and history.
"""

from typing import List, Optional
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMenu,
    QLineEdit,
    QPushButton,
    QLabel,
    QSplitter,
    QTextEdit,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor

from ...core.logging import get_logger
from ...core.models import HTTPRequest, HTTPResponse


logger = get_logger(__name__)


class ProxyWidget(QWidget):
    """
    Proxy history and traffic interception widget.

    Displays captured HTTP/HTTPS traffic with filtering and context menus.
    """

    # Signals
    request_selected = pyqtSignal(object)  # HTTPRequest
    send_to_repeater = pyqtSignal(object)  # HTTPRequest
    send_to_scanner = pyqtSignal(object)  # HTTPRequest
    send_to_intruder = pyqtSignal(object)  # HTTPRequest

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the proxy widget."""
        super().__init__(parent)

        self._flows: List[tuple] = []  # List of (request, response) tuples
        self._filtered_flows: List[tuple] = []

        self._setup_ui()

        logger.info("Proxy widget initialized")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "Enter filter (e.g., host:example.com, method:POST, status:200)"
        )
        self.filter_input.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_input)

        clear_filter_btn = QPushButton("Clear")
        clear_filter_btn.clicked.connect(self._clear_filter)
        filter_layout.addWidget(clear_filter_btn)

        layout.addLayout(filter_layout)

        # Splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)

        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels(
            ["#", "Method", "Host", "Path", "Status", "Length", "MIME Type", "Time"]
        )

        # Configure table
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.history_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSortingEnabled(True)
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        # Set column widths
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)

        # Connect signals
        self.history_table.itemSelectionChanged.connect(self._on_selection_changed)
        self.history_table.customContextMenuRequested.connect(self._show_context_menu)

        splitter.addWidget(self.history_table)

        # Details panel
        self.details_panel = QTextEdit()
        self.details_panel.setReadOnly(True)
        self.details_panel.setPlaceholderText("Select a request to view details")
        splitter.addWidget(self.details_panel)

        # Set splitter sizes (70% table, 30% details)
        splitter.setSizes([700, 300])

        layout.addWidget(splitter)

        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.count_label = QLabel("Requests: 0")
        status_layout.addWidget(self.count_label)

        layout.addLayout(status_layout)

    def _apply_filter(self) -> None:
        """Apply filter to the history table."""
        filter_text = self.filter_input.text().lower()

        if not filter_text:
            self._filtered_flows = self._flows.copy()
        else:
            self._filtered_flows = []
            for request, response in self._flows:
                # Simple filter implementation
                if (
                    filter_text in request.url.lower()
                    or filter_text in request.method.lower()
                    or (response and filter_text in str(response.status_code))
                ):
                    self._filtered_flows.append((request, response))

        self._refresh_table()

    def _clear_filter(self) -> None:
        """Clear the filter."""
        self.filter_input.clear()

    def _refresh_table(self) -> None:
        """Refresh the history table with filtered flows."""
        self.history_table.setRowCount(0)

        for idx, (request, response) in enumerate(self._filtered_flows):
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)

            # Parse URL
            from urllib.parse import urlparse

            parsed = urlparse(request.url)

            # Add items
            self.history_table.setItem(row, 0, QTableWidgetItem(str(idx + 1)))
            self.history_table.setItem(row, 1, QTableWidgetItem(request.method))
            self.history_table.setItem(row, 2, QTableWidgetItem(parsed.netloc))
            self.history_table.setItem(row, 3, QTableWidgetItem(parsed.path or "/"))

            if response:
                status_item = QTableWidgetItem(str(response.status_code))
                # Color code status
                if 200 <= response.status_code < 300:
                    status_item.setForeground(QColor(0, 200, 0))
                elif 300 <= response.status_code < 400:
                    status_item.setForeground(QColor(200, 200, 0))
                elif 400 <= response.status_code < 500:
                    status_item.setForeground(QColor(255, 165, 0))
                else:
                    status_item.setForeground(QColor(255, 0, 0))
                self.history_table.setItem(row, 4, status_item)

                length = len(response.body) if response.body else 0
                self.history_table.setItem(row, 5, QTableWidgetItem(str(length)))

                mime_type = response.headers.get("content-type", "").split(";")[0]
                self.history_table.setItem(row, 6, QTableWidgetItem(mime_type))

                self.history_table.setItem(
                    row, 7, QTableWidgetItem(f"{response.duration_ms}ms")
                )
            else:
                self.history_table.setItem(row, 4, QTableWidgetItem("-"))
                self.history_table.setItem(row, 5, QTableWidgetItem("-"))
                self.history_table.setItem(row, 6, QTableWidgetItem("-"))
                self.history_table.setItem(row, 7, QTableWidgetItem("-"))

        self.count_label.setText(f"Requests: {len(self._filtered_flows)}")

    def _on_selection_changed(self) -> None:
        """Handle selection change in the history table."""
        selected_rows = self.history_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < len(self._filtered_flows):
            request, response = self._filtered_flows[row]
            self._show_details(request, response)
            self.request_selected.emit(request)

    def _show_details(
        self, request: HTTPRequest, response: Optional[HTTPResponse]
    ) -> None:
        """Show request/response details in the details panel."""
        details = []

        # Request details
        details.append("=== REQUEST ===")
        details.append(f"{request.method} {request.url}")
        details.append("\nHeaders:")
        for key, value in request.headers.items():
            details.append(f"  {key}: {value}")

        if request.body:
            details.append(f"\nBody ({len(request.body)} bytes):")
            try:
                body_text = request.body.decode("utf-8", errors="replace")
                details.append(body_text[:1000])  # Limit to first 1000 chars
                if len(request.body) > 1000:
                    details.append("\n... (truncated)")
            except Exception:
                details.append("(binary data)")

        # Response details
        if response:
            details.append("\n\n=== RESPONSE ===")
            details.append(f"Status: {response.status_code}")
            details.append(f"Duration: {response.duration_ms}ms")
            details.append("\nHeaders:")
            for key, value in response.headers.items():
                details.append(f"  {key}: {value}")

            if response.body:
                details.append(f"\nBody ({len(response.body)} bytes):")
                try:
                    body_text = response.body.decode("utf-8", errors="replace")
                    details.append(body_text[:1000])  # Limit to first 1000 chars
                    if len(response.body) > 1000:
                        details.append("\n... (truncated)")
                except Exception:
                    details.append("(binary data)")

        self.details_panel.setPlainText("\n".join(details))

    def _show_context_menu(self, position) -> None:
        """Show context menu for selected request."""
        if not self.history_table.selectedItems():
            return

        menu = QMenu(self)

        send_to_repeater_action = QAction("Send to Repeater", self)
        send_to_repeater_action.triggered.connect(self._on_send_to_repeater)
        menu.addAction(send_to_repeater_action)

        send_to_scanner_action = QAction("Send to Scanner", self)
        send_to_scanner_action.triggered.connect(self._on_send_to_scanner)
        menu.addAction(send_to_scanner_action)

        send_to_intruder_action = QAction("Send to Intruder", self)
        send_to_intruder_action.triggered.connect(self._on_send_to_intruder)
        menu.addAction(send_to_intruder_action)

        menu.addSeparator()

        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(self._on_delete_request)
        menu.addAction(delete_action)

        menu.exec(self.history_table.viewport().mapToGlobal(position))

    def _on_send_to_repeater(self) -> None:
        """Send selected request to repeater."""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self._filtered_flows):
            request, _ = self._filtered_flows[row]
            self.send_to_repeater.emit(request)
            logger.info(f"Sent request to repeater: {request.url}")

    def _on_send_to_scanner(self) -> None:
        """Send selected request to scanner."""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self._filtered_flows):
            request, _ = self._filtered_flows[row]
            self.send_to_scanner.emit(request)
            logger.info(f"Sent request to scanner: {request.url}")

    def _on_send_to_intruder(self) -> None:
        """Send selected request to intruder."""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self._filtered_flows):
            request, _ = self._filtered_flows[row]
            self.send_to_intruder.emit(request)
            logger.info(f"Sent request to intruder: {request.url}")

    def _on_delete_request(self) -> None:
        """Delete selected request."""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self._filtered_flows):
            del self._filtered_flows[row]
            # Also remove from main flows list
            self._flows = self._filtered_flows.copy()
            self._refresh_table()
            logger.info("Deleted request from history")

    # Public methods
    def add_flow(
        self, request: HTTPRequest, response: Optional[HTTPResponse] = None
    ) -> None:
        """
        Add a new HTTP flow to the history.

        Args:
            request: The HTTP request
            response: The HTTP response (optional)
        """
        self._flows.append((request, response))
        self._apply_filter()  # Reapply filter to include new flow if it matches
        logger.debug(f"Added flow to proxy history: {request.method} {request.url}")

    def clear_history(self) -> None:
        """Clear all proxy history."""
        self._flows.clear()
        self._filtered_flows.clear()
        self._refresh_table()
        self.details_panel.clear()
        logger.info("Cleared proxy history")

    def update_status(self, message: str) -> None:
        """
        Update the status message.

        Args:
            message: Status message to display
        """
        self.status_label.setText(message)
