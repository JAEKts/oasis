"""
Scanner Widget

Provides the UI for vulnerability scanning and results display.
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
    QLineEdit,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor

from ...core.logging import get_logger
from ...core.models import Finding, Severity


logger = get_logger(__name__)


class ScannerWidget(QWidget):
    """
    Vulnerability scanner widget.

    Displays scan configuration, execution controls, and vulnerability findings.
    """

    # Signals
    scan_started = pyqtSignal(str)  # target URL
    scan_stopped = pyqtSignal()
    finding_selected = pyqtSignal(object)  # Finding

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the scanner widget."""
        super().__init__(parent)

        self._findings: List[Finding] = []
        self._filtered_findings: List[Finding] = []
        self._is_scanning = False

        self._setup_ui()

        logger.info("Scanner widget initialized")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Scan configuration
        config_layout = QHBoxLayout()

        config_layout.addWidget(QLabel("Target:"))

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        config_layout.addWidget(self.target_input)

        config_layout.addWidget(QLabel("Policy:"))

        self.policy_combo = QComboBox()
        self.policy_combo.addItems(
            [
                "OWASP Top 10",
                "SQL Injection Only",
                "XSS Only",
                "Full Scan",
                "Quick Scan",
            ]
        )
        config_layout.addWidget(self.policy_combo)

        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self._on_start_scan)
        config_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._on_stop_scan)
        config_layout.addWidget(self.stop_button)

        layout.addLayout(config_layout)

        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(
            ["All", "Critical", "High", "Medium", "Low", "Info"]
        )
        self.severity_filter.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.severity_filter)

        filter_layout.addWidget(QLabel("Search:"))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search findings...")
        self.search_input.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.search_input)

        layout.addLayout(filter_layout)

        # Splitter for findings table and details
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Findings table
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels(
            ["Severity", "Type", "URL", "Confidence", "Description"]
        )

        # Configure table
        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.findings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setSortingEnabled(True)

        # Set column widths
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        # Connect signals
        self.findings_table.itemSelectionChanged.connect(self._on_selection_changed)

        splitter.addWidget(self.findings_table)

        # Details panel
        self.details_panel = QTextEdit()
        self.details_panel.setReadOnly(True)
        self.details_panel.setPlaceholderText("Select a finding to view details")
        splitter.addWidget(self.details_panel)

        # Set splitter sizes (60% table, 40% details)
        splitter.setSizes([600, 400])

        layout.addWidget(splitter)

        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.count_label = QLabel("Findings: 0")
        status_layout.addWidget(self.count_label)

        layout.addLayout(status_layout)

    def _apply_filter(self) -> None:
        """Apply filters to the findings table."""
        severity_filter = self.severity_filter.currentText()
        search_text = self.search_input.text().lower()

        self._filtered_findings = []
        for finding in self._findings:
            # Apply severity filter
            if severity_filter != "All" and finding.severity.value != severity_filter:
                continue

            # Apply search filter
            if (
                search_text
                and search_text not in finding.title.lower()
                and search_text not in finding.description.lower()
            ):
                continue

            self._filtered_findings.append(finding)

        self._refresh_table()

    def _refresh_table(self) -> None:
        """Refresh the findings table."""
        self.findings_table.setRowCount(0)

        for finding in self._filtered_findings:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)

            # Severity with color coding
            severity_item = QTableWidgetItem(finding.severity.value)
            if finding.severity == Severity.CRITICAL:
                severity_item.setForeground(QColor(255, 0, 0))
            elif finding.severity == Severity.HIGH:
                severity_item.setForeground(QColor(255, 100, 0))
            elif finding.severity == Severity.MEDIUM:
                severity_item.setForeground(QColor(255, 165, 0))
            elif finding.severity == Severity.LOW:
                severity_item.setForeground(QColor(200, 200, 0))
            else:
                severity_item.setForeground(QColor(100, 100, 100))
            self.findings_table.setItem(row, 0, severity_item)

            # Type
            self.findings_table.setItem(
                row, 1, QTableWidgetItem(finding.vulnerability_type.value)
            )

            # URL (from evidence if available)
            url = "N/A"
            if finding.evidence and hasattr(finding.evidence, "url"):
                url = finding.evidence.url
            self.findings_table.setItem(row, 2, QTableWidgetItem(url))

            # Confidence
            self.findings_table.setItem(
                row, 3, QTableWidgetItem(finding.confidence.value)
            )

            # Description (truncated)
            desc = (
                finding.description[:100] + "..."
                if len(finding.description) > 100
                else finding.description
            )
            self.findings_table.setItem(row, 4, QTableWidgetItem(desc))

        self.count_label.setText(f"Findings: {len(self._filtered_findings)}")

    def _on_selection_changed(self) -> None:
        """Handle selection change in the findings table."""
        selected_rows = self.findings_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < len(self._filtered_findings):
            finding = self._filtered_findings[row]
            self._show_details(finding)
            self.finding_selected.emit(finding)

    def _show_details(self, finding: Finding) -> None:
        """Show finding details in the details panel."""
        details = []

        details.append(f"=== {finding.title} ===")
        details.append(f"\nSeverity: {finding.severity.value}")
        details.append(f"Confidence: {finding.confidence.value}")
        details.append(f"Type: {finding.vulnerability_type.value}")

        details.append(f"\n\nDescription:")
        details.append(finding.description)

        if finding.evidence:
            details.append(f"\n\nEvidence:")
            details.append(str(finding.evidence))

        details.append(f"\n\nRemediation:")
        details.append(finding.remediation)

        if finding.references:
            details.append(f"\n\nReferences:")
            for ref in finding.references:
                details.append(f"  - {ref}")

        self.details_panel.setPlainText("\n".join(details))

    def _on_start_scan(self) -> None:
        """Handle start scan button click."""
        target = self.target_input.text().strip()

        if not target:
            self.status_label.setText("Error: No target specified")
            return

        self._is_scanning = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText(f"Scanning {target}...")

        self.scan_started.emit(target)
        logger.info(f"Started scan: {target}")

    def _on_stop_scan(self) -> None:
        """Handle stop scan button click."""
        self._is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Scan stopped")

        self.scan_stopped.emit()
        logger.info("Stopped scan")

    # Public methods
    def add_finding(self, finding: Finding) -> None:
        """
        Add a new finding to the results.

        Args:
            finding: The vulnerability finding
        """
        self._findings.append(finding)
        self._apply_filter()
        logger.debug(f"Added finding: {finding.title}")

    def clear_findings(self) -> None:
        """Clear all findings."""
        self._findings.clear()
        self._filtered_findings.clear()
        self._refresh_table()
        self.details_panel.clear()
        logger.info("Cleared scanner findings")

    def update_status(self, message: str) -> None:
        """
        Update the status message.

        Args:
            message: Status message to display
        """
        self.status_label.setText(message)
