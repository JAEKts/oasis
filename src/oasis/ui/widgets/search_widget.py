"""
Search Widget

Provides advanced search and filtering capabilities for project data.
"""

from typing import Optional, List
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QComboBox,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ...core.logging import get_logger


logger = get_logger(__name__)


class SearchWidget(QWidget):
    """
    Advanced search widget for project data.

    Provides search, filtering, and tagging capabilities across all project data.
    """

    # Signals
    result_selected = pyqtSignal(object)  # Selected result

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the search widget."""
        super().__init__(parent)

        self._results: List[dict] = []

        self._setup_ui()

        logger.info("Search widget initialized")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Search bar
        search_layout = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search across all project data...")
        self.search_input.returnPressed.connect(self._on_search)
        search_layout.addWidget(self.search_input)

        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self._on_search)
        search_layout.addWidget(self.search_button)

        layout.addLayout(search_layout)

        # Filter options
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("Filter by:"))

        self.type_filter = QComboBox()
        self.type_filter.addItems(
            [
                "All Types",
                "Proxy History",
                "Scanner Findings",
                "Repeater Sessions",
                "Intruder Results",
            ]
        )
        self.type_filter.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.type_filter)

        filter_layout.addWidget(QLabel("Method:"))

        self.method_filter = QComboBox()
        self.method_filter.addItems(["All", "GET", "POST", "PUT", "DELETE", "PATCH"])
        self.method_filter.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.method_filter)

        filter_layout.addWidget(QLabel("Status:"))

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "2xx", "3xx", "4xx", "5xx"])
        self.status_filter.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addStretch()

        clear_button = QPushButton("Clear Filters")
        clear_button.clicked.connect(self._clear_filters)
        filter_layout.addWidget(clear_button)

        layout.addLayout(filter_layout)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(
            ["Type", "Method", "URL", "Status", "Time", "Tags"]
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
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        # Connect signals
        self.results_table.itemSelectionChanged.connect(self._on_selection_changed)

        layout.addWidget(self.results_table)

        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.count_label = QLabel("Results: 0")
        status_layout.addWidget(self.count_label)

        layout.addLayout(status_layout)

    def _on_search(self) -> None:
        """Handle search button click."""
        query = self.search_input.text().strip()

        if not query:
            self.status_label.setText("Enter a search query")
            return

        self.status_label.setText(f"Searching for: {query}")

        logger.info(f"Search query: {query}")

        # Placeholder: show empty results
        self._results = []
        self._apply_filters()

    def _apply_filters(self) -> None:
        """Apply filters to search results."""
        type_filter = self.type_filter.currentText()
        method_filter = self.method_filter.currentText()
        status_filter = self.status_filter.currentText()

        filtered_results = []

        for result in self._results:
            # Apply type filter
            if type_filter != "All Types" and result.get("type") != type_filter:
                continue

            # Apply method filter
            if method_filter != "All" and result.get("method") != method_filter:
                continue

            # Apply status filter
            if status_filter != "All":
                status = result.get("status", 0)
                status_range = status_filter[0]  # Get first digit
                if not (
                    int(status_range) * 100 <= status < (int(status_range) + 1) * 100
                ):
                    continue

            filtered_results.append(result)

        self._refresh_table(filtered_results)

    def _refresh_table(self, results: List[dict]) -> None:
        """Refresh the results table."""
        self.results_table.setRowCount(0)

        for result in results:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)

            self.results_table.setItem(row, 0, QTableWidgetItem(result.get("type", "")))
            self.results_table.setItem(
                row, 1, QTableWidgetItem(result.get("method", ""))
            )
            self.results_table.setItem(row, 2, QTableWidgetItem(result.get("url", "")))
            self.results_table.setItem(
                row, 3, QTableWidgetItem(str(result.get("status", "")))
            )
            self.results_table.setItem(row, 4, QTableWidgetItem(result.get("time", "")))
            self.results_table.setItem(
                row, 5, QTableWidgetItem(", ".join(result.get("tags", [])))
            )

        self.count_label.setText(f"Results: {len(results)}")

    def _clear_filters(self) -> None:
        """Clear all filters."""
        self.type_filter.setCurrentIndex(0)
        self.method_filter.setCurrentIndex(0)
        self.status_filter.setCurrentIndex(0)
        self.search_input.clear()
        self.status_label.setText("Ready")

    def _on_selection_changed(self) -> None:
        """Handle selection change in results table."""
        selected_rows = self.results_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < len(self._results):
            result = self._results[row]
            self.result_selected.emit(result)

    # Public methods
    def add_result(self, result: dict) -> None:
        """
        Add a search result.

        Args:
            result: Dictionary with result data
        """
        self._results.append(result)
        self._apply_filters()

    def clear_results(self) -> None:
        """Clear all search results."""
        self._results.clear()
        self.results_table.setRowCount(0)
        self.count_label.setText("Results: 0")
