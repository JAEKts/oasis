"""
Export Dialog

Provides dialog for exporting project data in various formats.
"""

from typing import Optional
from pathlib import Path
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QLabel,
    QComboBox,
    QCheckBox,
    QGroupBox,
    QMessageBox,
)

from ...core.logging import get_logger


logger = get_logger(__name__)


class ExportDialog(QDialog):
    """Dialog for exporting project data."""

    def __init__(
        self, export_format: str = "xml", parent: Optional[QDialog] = None
    ) -> None:
        """
        Initialize the export dialog.

        Args:
            export_format: Default export format ("xml", "json", or "pdf")
            parent: Parent widget
        """
        super().__init__(parent)

        self.export_format = export_format
        self.export_path = ""
        self.export_options = {}

        self._setup_ui()

        logger.info(f"Export dialog opened: {export_format}")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        self.setWindowTitle(f"Export as {self.export_format.upper()}")
        self.setModal(True)
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)

        # Format selection
        format_layout = QFormLayout()

        self.format_combo = QComboBox()
        self.format_combo.addItems(["XML", "JSON", "PDF", "HTML", "CSV"])
        self.format_combo.setCurrentText(self.export_format.upper())
        self.format_combo.currentTextChanged.connect(self._on_format_changed)
        format_layout.addRow("Export Format:", self.format_combo)

        layout.addLayout(format_layout)

        # Export options
        options_group = QGroupBox("Export Options")
        options_layout = QVBoxLayout(options_group)

        self.include_proxy_history = QCheckBox("Include Proxy History")
        self.include_proxy_history.setChecked(True)
        options_layout.addWidget(self.include_proxy_history)

        self.include_scanner_findings = QCheckBox("Include Scanner Findings")
        self.include_scanner_findings.setChecked(True)
        options_layout.addWidget(self.include_scanner_findings)

        self.include_repeater_sessions = QCheckBox("Include Repeater Sessions")
        self.include_repeater_sessions.setChecked(True)
        options_layout.addWidget(self.include_repeater_sessions)

        self.include_intruder_results = QCheckBox("Include Intruder Results")
        self.include_intruder_results.setChecked(True)
        options_layout.addWidget(self.include_intruder_results)

        self.include_screenshots = QCheckBox("Include Screenshots (PDF only)")
        self.include_screenshots.setChecked(False)
        self.include_screenshots.setEnabled(self.export_format.lower() == "pdf")
        options_layout.addWidget(self.include_screenshots)

        layout.addWidget(options_group)

        # File path selection
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Save to:"))

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select export location")
        self.path_input.setReadOnly(True)
        path_layout.addWidget(self.path_input)

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._browse_path)
        path_layout.addWidget(browse_button)

        layout.addLayout(path_layout)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        export_button = QPushButton("Export")
        export_button.clicked.connect(self._on_export)
        button_layout.addWidget(export_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _on_format_changed(self, format_text: str) -> None:
        """Handle format selection change."""
        self.export_format = format_text.lower()
        self.setWindowTitle(f"Export as {format_text}")

        # Enable/disable PDF-specific options
        self.include_screenshots.setEnabled(self.export_format == "pdf")

        # Update file path extension if already set
        if self.export_path:
            path = Path(self.export_path)
            self.export_path = str(path.with_suffix(f".{self.export_format}"))
            self.path_input.setText(self.export_path)

    def _browse_path(self) -> None:
        """Browse for export location."""
        format_filters = {
            "xml": "XML Files (*.xml)",
            "json": "JSON Files (*.json)",
            "pdf": "PDF Files (*.pdf)",
            "html": "HTML Files (*.html)",
            "csv": "CSV Files (*.csv)",
        }

        file_filter = format_filters.get(self.export_format, "All Files (*)")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Project",
            str(Path.home() / f"oasis_export.{self.export_format}"),
            file_filter,
        )

        if path:
            self.path_input.setText(path)

    def _on_export(self) -> None:
        """Handle export button click."""
        self.export_path = self.path_input.text().strip()

        # Validate inputs
        if not self.export_path:
            QMessageBox.warning(self, "Validation Error", "Export location is required")
            return

        # Collect export options
        self.export_options = {
            "format": self.export_format,
            "include_proxy_history": self.include_proxy_history.isChecked(),
            "include_scanner_findings": self.include_scanner_findings.isChecked(),
            "include_repeater_sessions": self.include_repeater_sessions.isChecked(),
            "include_intruder_results": self.include_intruder_results.isChecked(),
            "include_screenshots": self.include_screenshots.isChecked(),
        }

        logger.info(f"Exporting to: {self.export_path}")
        self.accept()

    def get_export_info(self) -> dict:
        """
        Get the export information.

        Returns:
            Dictionary with export details
        """
        return {
            "path": self.export_path,
            "format": self.export_format,
            "options": self.export_options,
        }
