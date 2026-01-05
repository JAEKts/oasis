"""
Repeater Widget

Provides the UI for manual HTTP request testing and modification.
"""

from typing import Optional
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QTextEdit,
    QPushButton,
    QSplitter,
    QLabel,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ...core.logging import get_logger
from ...core.models import HTTPRequest, HTTPResponse


logger = get_logger(__name__)


class RepeaterTab(QWidget):
    """Individual repeater tab for a single request/response pair."""

    # Signals
    request_sent = pyqtSignal(object)  # HTTPRequest

    def __init__(
        self, request: Optional[HTTPRequest] = None, parent: Optional[QWidget] = None
    ) -> None:
        """
        Initialize a repeater tab.

        Args:
            request: Initial HTTP request to load
            parent: Parent widget
        """
        super().__init__(parent)

        self._request = request
        self._response: Optional[HTTPResponse] = None

        self._setup_ui()

        if request:
            self._load_request(request)

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Action buttons
        button_layout = QHBoxLayout()

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self._on_send)
        button_layout.addWidget(self.send_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        button_layout.addWidget(self.cancel_button)

        button_layout.addStretch()

        self.status_label = QLabel("Ready")
        button_layout.addWidget(self.status_label)

        layout.addLayout(button_layout)

        # Splitter for request/response
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Request editor
        request_widget = QWidget()
        request_layout = QVBoxLayout(request_widget)
        request_layout.setContentsMargins(0, 0, 0, 0)

        request_layout.addWidget(QLabel("Request:"))

        self.request_editor = QTextEdit()
        self.request_editor.setPlaceholderText(
            "Enter raw HTTP request:\n\n"
            "GET /path HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: OASIS\n"
            "\n"
        )
        self.request_editor.setFontFamily("Courier New")
        request_layout.addWidget(self.request_editor)

        splitter.addWidget(request_widget)

        # Response viewer
        response_widget = QWidget()
        response_layout = QVBoxLayout(response_widget)
        response_layout.setContentsMargins(0, 0, 0, 0)

        response_layout.addWidget(QLabel("Response:"))

        self.response_viewer = QTextEdit()
        self.response_viewer.setReadOnly(True)
        self.response_viewer.setPlaceholderText(
            "Response will appear here after sending request"
        )
        self.response_viewer.setFontFamily("Courier New")
        response_layout.addWidget(self.response_viewer)

        splitter.addWidget(response_widget)

        # Set equal sizes
        splitter.setSizes([500, 500])

        layout.addWidget(splitter)

    def _load_request(self, request: HTTPRequest) -> None:
        """Load a request into the editor."""
        raw_request = self._format_request(request)
        self.request_editor.setPlainText(raw_request)
        self._request = request

    def _format_request(self, request: HTTPRequest) -> str:
        """Format an HTTPRequest as raw HTTP."""
        from urllib.parse import urlparse

        parsed = urlparse(request.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{request.method} {path} HTTP/1.1"]

        # Add headers
        for key, value in request.headers.items():
            lines.append(f"{key}: {value}")

        # Add body if present
        if request.body:
            lines.append("")
            try:
                body_text = request.body.decode("utf-8", errors="replace")
                lines.append(body_text)
            except Exception:
                lines.append("(binary data)")

        return "\n".join(lines)

    def _format_response(self, response: HTTPResponse) -> str:
        """Format an HTTPResponse as raw HTTP."""
        lines = [f"HTTP/1.1 {response.status_code}"]

        # Add headers
        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")

        lines.append("")
        lines.append(f"Duration: {response.duration_ms}ms")
        lines.append("")

        # Add body if present
        if response.body:
            try:
                body_text = response.body.decode("utf-8", errors="replace")
                lines.append(body_text)
            except Exception:
                lines.append("(binary data)")

        return "\n".join(lines)

    def _on_send(self) -> None:
        """Handle send button click."""
        raw_request = self.request_editor.toPlainText()

        if not raw_request.strip():
            self.status_label.setText("Error: Empty request")
            return

        try:
            # Parse raw HTTP request
            request = self._parse_raw_request(raw_request)
            self._request = request

            # Emit signal (actual sending will be handled by parent)
            self.request_sent.emit(request)

            self.status_label.setText("Sending request...")
            self.send_button.setEnabled(False)
            self.cancel_button.setEnabled(True)

            logger.info(f"Sending request: {request.method} {request.url}")

        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
            logger.error(f"Failed to parse request: {e}")

    def _parse_raw_request(self, raw: str) -> HTTPRequest:
        """Parse raw HTTP request text into HTTPRequest object."""
        from datetime import datetime
        from ...core.models import RequestSource

        lines = raw.split("\n")
        if not lines:
            raise ValueError("Empty request")

        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) < 2:
            raise ValueError("Invalid request line")

        method = parts[0]
        path = parts[1]

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        # Get host from headers
        host = headers.get("Host", "")
        if not host:
            raise ValueError("Missing Host header")

        # Construct URL
        scheme = "https" if "443" in host else "http"
        url = f"{scheme}://{host}{path}"

        # Parse body
        body = None
        if body_start < len(lines):
            body_text = "\n".join(lines[body_start:])
            if body_text.strip():
                body = body_text.encode("utf-8")

        return HTTPRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            timestamp=datetime.now(),
            source=RequestSource.REPEATER,
        )

    def set_response(self, response: HTTPResponse) -> None:
        """
        Set the response to display.

        Args:
            response: The HTTP response
        """
        self._response = response
        raw_response = self._format_response(response)
        self.response_viewer.setPlainText(raw_response)

        self.status_label.setText(f"Response received: {response.status_code}")
        self.send_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

        logger.info(f"Response received: {response.status_code}")

    def get_request(self) -> Optional[HTTPRequest]:
        """Get the current request."""
        return self._request


class RepeaterWidget(QWidget):
    """
    Repeater tool widget with tabbed interface.

    Provides HTTP request editor and response viewer with session persistence.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the repeater widget."""
        super().__init__(parent)

        self._setup_ui()

        logger.info("Repeater widget initialized")

    def _setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget for multiple requests
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)

        layout.addWidget(self.tab_widget)

        # Add initial tab
        self._add_new_tab()

    def _add_new_tab(self, request: Optional[HTTPRequest] = None) -> RepeaterTab:
        """
        Add a new repeater tab.

        Args:
            request: Optional request to load in the new tab

        Returns:
            The created RepeaterTab
        """
        tab = RepeaterTab(request)

        # Generate tab title
        if request:
            from urllib.parse import urlparse

            parsed = urlparse(request.url)
            title = f"{request.method} {parsed.netloc}"
        else:
            title = f"Request {self.tab_widget.count() + 1}"

        index = self.tab_widget.addTab(tab, title)
        self.tab_widget.setCurrentIndex(index)

        logger.info(f"Added repeater tab: {title}")

        return tab

    def _close_tab(self, index: int) -> None:
        """Close a repeater tab."""
        if self.tab_widget.count() > 1:
            self.tab_widget.removeTab(index)
            logger.info(f"Closed repeater tab at index {index}")
        else:
            logger.warning("Cannot close last repeater tab")

    def add_request(self, request: HTTPRequest) -> None:
        """
        Add a new request in a new tab.

        Args:
            request: The HTTP request to add
        """
        self._add_new_tab(request)

    def get_current_tab(self) -> Optional[RepeaterTab]:
        """Get the currently active repeater tab."""
        current_widget = self.tab_widget.currentWidget()
        if isinstance(current_widget, RepeaterTab):
            return current_widget
        return None
