"""
Project Management Dialogs

Provides dialogs for creating, opening, and managing projects.
"""

from typing import Optional
from pathlib import Path
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLineEdit,
    QTextEdit,
    QPushButton,
    QFileDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
)
from PyQt6.QtCore import Qt

from ...core.logging import get_logger


logger = get_logger(__name__)


class NewProjectDialog(QDialog):
    """Dialog for creating a new project."""

    def __init__(self, parent: Optional[QDialog] = None) -> None:
        """Initialize the new project dialog."""
        super().__init__(parent)

        self.project_name = ""
        self.project_description = ""
        self.project_path = ""

        self._setup_ui()

        logger.info("New project dialog opened")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        self.setWindowTitle("New Project")
        self.setModal(True)
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)

        # Form layout for project details
        form_layout = QFormLayout()

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter project name")
        form_layout.addRow("Project Name:", self.name_input)

        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText(
            "Enter project description (optional)"
        )
        self.description_input.setMaximumHeight(100)
        form_layout.addRow("Description:", self.description_input)

        # Path selection
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select project location")
        self.path_input.setReadOnly(True)
        path_layout.addWidget(self.path_input)

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._browse_path)
        path_layout.addWidget(browse_button)

        form_layout.addRow("Location:", path_layout)

        layout.addLayout(form_layout)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        create_button = QPushButton("Create")
        create_button.clicked.connect(self._on_create)
        button_layout.addWidget(create_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _browse_path(self) -> None:
        """Browse for project location."""
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Project Location",
            str(Path.home()),
        )

        if path:
            self.path_input.setText(path)

    def _on_create(self) -> None:
        """Handle create button click."""
        self.project_name = self.name_input.text().strip()
        self.project_description = self.description_input.toPlainText().strip()
        self.project_path = self.path_input.text().strip()

        # Validate inputs
        if not self.project_name:
            QMessageBox.warning(self, "Validation Error", "Project name is required")
            return

        if not self.project_path:
            QMessageBox.warning(
                self, "Validation Error", "Project location is required"
            )
            return

        # Check if project directory already exists
        project_dir = Path(self.project_path) / self.project_name
        if project_dir.exists():
            reply = QMessageBox.question(
                self,
                "Directory Exists",
                f"Directory '{project_dir}' already exists. Continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                return

        logger.info(f"Creating new project: {self.project_name}")
        self.accept()

    def get_project_info(self) -> dict:
        """
        Get the project information.

        Returns:
            Dictionary with project details
        """
        return {
            "name": self.project_name,
            "description": self.project_description,
            "path": self.project_path,
        }


class OpenProjectDialog(QDialog):
    """Dialog for opening an existing project."""

    def __init__(self, parent: Optional[QDialog] = None) -> None:
        """Initialize the open project dialog."""
        super().__init__(parent)

        self.selected_project_path = ""

        self._setup_ui()
        self._load_recent_projects()

        logger.info("Open project dialog opened")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        self.setWindowTitle("Open Project")
        self.setModal(True)
        self.setMinimumSize(600, 400)

        layout = QVBoxLayout(self)

        # Recent projects list
        layout.addWidget(QLabel("Recent Projects:"))

        self.projects_list = QListWidget()
        self.projects_list.itemDoubleClicked.connect(self._on_project_selected)
        layout.addWidget(self.projects_list)

        # Browse for other project
        browse_layout = QHBoxLayout()
        browse_layout.addWidget(QLabel("Or browse for project:"))

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._browse_project)
        browse_layout.addWidget(browse_button)
        browse_layout.addStretch()

        layout.addLayout(browse_layout)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        open_button = QPushButton("Open")
        open_button.clicked.connect(self._on_open)
        button_layout.addWidget(open_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _load_recent_projects(self) -> None:
        """Load recent projects list."""
        placeholder_item = QListWidgetItem("No recent projects")
        placeholder_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.projects_list.addItem(placeholder_item)

    def _browse_project(self) -> None:
        """Browse for project file."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project",
            str(Path.home()),
            "OASIS Project Files (*.oasis);;All Files (*)",
        )

        if path:
            self.selected_project_path = path
            self.accept()

    def _on_project_selected(self, item: QListWidgetItem) -> None:
        """Handle project selection from list."""
        self.selected_project_path = item.text()
        self.accept()

    def _on_open(self) -> None:
        """Handle open button click."""
        current_item = self.projects_list.currentItem()
        if current_item and current_item.flags() & Qt.ItemFlag.ItemIsEnabled:
            self._on_project_selected(current_item)
        else:
            QMessageBox.warning(
                self, "No Selection", "Please select a project or browse for one"
            )

    def get_project_path(self) -> str:
        """
        Get the selected project path.

        Returns:
            Path to the selected project
        """
        return self.selected_project_path
