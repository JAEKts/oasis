"""
Intruder Widget

Provides the UI for automated attack configuration and execution.
"""

from typing import List, Optional
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPushButton,
    QLabel,
    QSplitter,
    QTextEdit,
    QComboBox,
    QSpinBox,
    QGroupBox,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ...core.logging import get_logger


logger = get_logger(__name__)


class IntruderWidget(QWidget):
    """
    Intruder attack engine widget.

    Provides attack configuration, payload management, and results display.
    """

    # Signals
    attack_started = pyqtSignal()
    attack_stopped = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the intruder widget."""
        super().__init__(parent)

        self._results: List[dict] = []
        self._is_attacking = False

        self._setup_ui()

        logger.info("Intruder widget initialized")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Configuration section
        config_group = QGroupBox("Attack Configuration")
        config_layout = QVBoxLayout(config_group)

        # Attack type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Attack Type:"))

        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(
            [
                "Sniper",
                "Battering Ram",
                "Pitchfork",
                "Cluster Bomb",
            ]
        )
        type_layout.addWidget(self.attack_type_combo)
        type_layout.addStretch()

        config_layout.addLayout(type_layout)

        # Request template
        config_layout.addWidget(QLabel("Request Template:"))

        self.request_template = QTextEdit()
        self.request_template.setPlaceholderText(
            "Enter request template with §markers§ for injection points:\n\n"
            "GET /api/user?id=§1§ HTTP/1.1\n"
            "Host: example.com\n"
            "Cookie: session=§2§\n"
        )
        self.request_template.setMaximumHeight(150)
        self.request_template.setFontFamily("Courier New")
        config_layout.addWidget(self.request_template)

        # Payload configuration
        payload_layout = QHBoxLayout()

        payload_layout.addWidget(QLabel("Payload Set:"))

        self.payload_combo = QComboBox()
        self.payload_combo.addItems(
            [
                "Numbers (1-100)",
                "Common Passwords",
                "SQL Injection",
                "XSS Payloads",
                "Directory Names",
                "Custom List",
            ]
        )
        payload_layout.addWidget(self.payload_combo)

        payload_layout.addWidget(QLabel("Threads:"))

        self.threads_spin = QSpinBox()
        self.threads_spin.setMinimum(1)
        self.threads_spin.setMaximum(50)
        self.threads_spin.setValue(10)
        payload_layout.addWidget(self.threads_spin)

        payload_layout.addWidget(QLabel("Delay (ms):"))

        self.delay_spin = QSpinBox()
        self.delay_spin.setMinimum(0)
        self.delay_spin.setMaximum(10000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSingleStep(100)
        payload_layout.addWidget(self.delay_spin)

        payload_layout.addStretch()

        config_layout.addLayout(payload_layout)

        # Control buttons
        button_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Attack")
        self.start_button.clicked.connect(self._on_start_attack)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Attack")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._on_stop_attack)
        button_layout.addWidget(self.stop_button)

        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self._on_clear_results)
        button_layout.addWidget(self.clear_button)

        button_layout.addStretch()

        config_layout.addLayout(button_layout)

        layout.addWidget(config_group)

        # Results section
        results_group = QGroupBox("Attack Results")
        results_layout = QVBoxLayout(results_group)

        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Status:"))

        self.status_filter = QComboBox()
        self.status_filter.addItems(
            ["All", "200", "301", "302", "400", "401", "403", "404", "500"]
        )
        self.status_filter.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addWidget(QLabel("Sort by:"))

        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Request #", "Status", "Length", "Time"])
        self.sort_combo.currentTextChanged.connect(self._apply_sort)
        filter_layout.addWidget(self.sort_combo)

        filter_layout.addStretch()

        results_layout.addLayout(filter_layout)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Status", "Length", "Time (ms)", "Notes"]
        )

        # Configure table
        self.results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.results_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSortingEnabled(True)

        # Set column widths
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        results_layout.addWidget(self.results_table)

        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.progress_label = QLabel("Requests: 0 / 0")
        status_layout.addWidget(self.progress_label)

        results_layout.addLayout(status_layout)

        layout.addWidget(results_group)

    def _apply_filter(self) -> None:
        """Apply status filter to results."""
        status_filter = self.status_filter.currentText()

        for row in range(self.results_table.rowCount()):
            if status_filter == "All":
                self.results_table.setRowHidden(row, False)
            else:
                status_item = self.results_table.item(row, 2)
                if status_item and status_item.text() == status_filter:
                    self.results_table.setRowHidden(row, False)
                else:
                    self.results_table.setRowHidden(row, True)

    def _apply_sort(self) -> None:
        """Apply sorting to results."""
        sort_by = self.sort_combo.currentText()

        column_map = {
            "Request #": 0,
            "Status": 2,
            "Length": 3,
            "Time": 4,
        }

        if sort_by in column_map:
            self.results_table.sortItems(column_map[sort_by])

    def _on_start_attack(self) -> None:
        """Handle start attack button click."""
        template = self.request_template.toPlainText().strip()

        if not template:
            self.status_label.setText("Error: No request template specified")
            return

        # Count injection points
        injection_count = template.count("§") // 2
        if injection_count == 0:
            self.status_label.setText("Error: No injection points marked with §")
            return

        self._is_attacking = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Attack in progress...")

        self.attack_started.emit()
        logger.info(f"Started attack with {injection_count} injection points")

    def _on_stop_attack(self) -> None:
        """Handle stop attack button click."""
        self._is_attacking = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Attack stopped")

        self.attack_stopped.emit()
        logger.info("Stopped attack")

    def _on_clear_results(self) -> None:
        """Handle clear results button click."""
        self._results.clear()
        self.results_table.setRowCount(0)
        self.progress_label.setText("Requests: 0 / 0")
        logger.info("Cleared intruder results")

    # Public methods
    def add_result(
        self,
        request_num: int,
        payload: str,
        status: int,
        length: int,
        time_ms: int,
        notes: str = "",
    ) -> None:
        """
        Add an attack result to the table.

        Args:
            request_num: Request number
            payload: Payload used
            status: HTTP status code
            length: Response length
            time_ms: Response time in milliseconds
            notes: Optional notes
        """
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        self.results_table.setItem(row, 0, QTableWidgetItem(str(request_num)))
        self.results_table.setItem(row, 1, QTableWidgetItem(payload))
        self.results_table.setItem(row, 2, QTableWidgetItem(str(status)))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(length)))
        self.results_table.setItem(row, 4, QTableWidgetItem(str(time_ms)))
        self.results_table.setItem(row, 5, QTableWidgetItem(notes))

        self._results.append(
            {
                "request_num": request_num,
                "payload": payload,
                "status": status,
                "length": length,
                "time_ms": time_ms,
                "notes": notes,
            }
        )

        logger.debug(f"Added attack result: {request_num} - {status}")

    def update_progress(self, current: int, total: int) -> None:
        """
        Update the progress display.

        Args:
            current: Current request number
            total: Total requests
        """
        self.progress_label.setText(f"Requests: {current} / {total}")

    def update_status(self, message: str) -> None:
        """
        Update the status message.

        Args:
            message: Status message to display
        """
        self.status_label.setText(message)

    def set_request_template(self, template: str) -> None:
        """
        Set the request template.

        Args:
            template: Raw HTTP request template
        """
        self.request_template.setPlainText(template)
