"""
Repeater Session Management

Provides session persistence, tab management, and request history with undo/redo.
"""

import uuid
import json
from datetime import datetime, UTC
from typing import Dict, List, Optional, Any
from pathlib import Path

import aiohttp

from ..core.models import HTTPRequest, HTTPResponse, RequestSource
from ..core.exceptions import OASISException
from .editor import HTTPRequestEditor


class RepeaterError(OASISException):
    """Exception raised for repeater-specific errors."""

    pass


class RequestHistoryEntry:
    """Entry in request modification history."""

    def __init__(self, request: HTTPRequest, timestamp: Optional[datetime] = None):
        self.request = request
        self.timestamp = timestamp or datetime.now(UTC)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        import base64

        request_dict = self.request.model_dump()
        # Convert datetime objects to ISO format strings
        if "timestamp" in request_dict and hasattr(
            request_dict["timestamp"], "isoformat"
        ):
            request_dict["timestamp"] = request_dict["timestamp"].isoformat()
        # Convert bytes to base64 string
        if "body" in request_dict and isinstance(request_dict["body"], bytes):
            request_dict["body"] = base64.b64encode(request_dict["body"]).decode(
                "ascii"
            )
            request_dict["body_encoding"] = "base64"

        return {"request": request_dict, "timestamp": self.timestamp.isoformat()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RequestHistoryEntry":
        """Create from dictionary."""
        import base64

        request_data = data["request"]
        # Decode base64 body if present
        if "body" in request_data and request_data.get("body_encoding") == "base64":
            request_data["body"] = base64.b64decode(request_data["body"])
            del request_data["body_encoding"]

        request = HTTPRequest(**request_data)
        timestamp = datetime.fromisoformat(data["timestamp"])
        return cls(request, timestamp)


class RequestHistory:
    """
    Request modification history with undo/redo support.

    Maintains a stack of request modifications to support undo/redo operations.
    """

    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._history: List[RequestHistoryEntry] = []
        self._current_index: int = -1

    def add(self, request: HTTPRequest) -> None:
        """
        Add a request to history.

        Args:
            request: HTTPRequest to add
        """
        # Remove any entries after current index (when adding after undo)
        if self._current_index < len(self._history) - 1:
            self._history = self._history[: self._current_index + 1]

        # Add new entry
        entry = RequestHistoryEntry(request)
        self._history.append(entry)

        # Maintain max size
        if len(self._history) > self.max_size:
            self._history.pop(0)
        else:
            self._current_index += 1

    def undo(self) -> Optional[HTTPRequest]:
        """
        Undo to previous request.

        Returns:
            Previous HTTPRequest or None if at beginning
        """
        if self._current_index > 0:
            self._current_index -= 1
            return self._history[self._current_index].request
        return None

    def redo(self) -> Optional[HTTPRequest]:
        """
        Redo to next request.

        Returns:
            Next HTTPRequest or None if at end
        """
        if self._current_index < len(self._history) - 1:
            self._current_index += 1
            return self._history[self._current_index].request
        return None

    def current(self) -> Optional[HTTPRequest]:
        """
        Get current request.

        Returns:
            Current HTTPRequest or None if history is empty
        """
        if 0 <= self._current_index < len(self._history):
            return self._history[self._current_index].request
        return None

    def can_undo(self) -> bool:
        """Check if undo is available."""
        return self._current_index > 0

    def can_redo(self) -> bool:
        """Check if redo is available."""
        return self._current_index < len(self._history) - 1

    def clear(self) -> None:
        """Clear all history."""
        self._history.clear()
        self._current_index = -1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "history": [entry.to_dict() for entry in self._history],
            "current_index": self._current_index,
            "max_size": self.max_size,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RequestHistory":
        """Create from dictionary."""
        history = cls(max_size=data.get("max_size", 100))
        history._history = [
            RequestHistoryEntry.from_dict(entry) for entry in data.get("history", [])
        ]
        history._current_index = data.get("current_index", -1)
        return history


class RepeaterTab:
    """
    Individual repeater tab for request testing.

    Each tab maintains its own request, response, and modification history.
    """

    def __init__(self, name: str, request: Optional[HTTPRequest] = None):
        self.id = uuid.uuid4()
        self.name = name
        self.request = request
        self.response: Optional[HTTPResponse] = None
        self.history = RequestHistory()
        self.created_at = datetime.now(UTC)
        self.modified_at = datetime.now(UTC)

        # Add initial request to history if provided
        if request:
            self.history.add(request)

    def update_request(self, request: HTTPRequest) -> None:
        """
        Update the current request and add to history.

        Args:
            request: New HTTPRequest
        """
        self.request = request
        self.history.add(request)
        self.modified_at = datetime.now(UTC)

    def undo(self) -> bool:
        """
        Undo to previous request.

        Returns:
            True if undo was successful, False otherwise
        """
        previous = self.history.undo()
        if previous:
            self.request = previous
            self.modified_at = datetime.now(UTC)
            return True
        return False

    def redo(self) -> bool:
        """
        Redo to next request.

        Returns:
            True if redo was successful, False otherwise
        """
        next_req = self.history.redo()
        if next_req:
            self.request = next_req
            self.modified_at = datetime.now(UTC)
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        request_dict = None
        if self.request:
            request_dict = self.request.model_dump()
            # Convert datetime to ISO format
            if "timestamp" in request_dict and hasattr(
                request_dict["timestamp"], "isoformat"
            ):
                request_dict["timestamp"] = request_dict["timestamp"].isoformat()
            # Convert bytes to base64 string
            if "body" in request_dict and isinstance(request_dict["body"], bytes):
                import base64

                request_dict["body"] = base64.b64encode(request_dict["body"]).decode(
                    "ascii"
                )
                request_dict["body_encoding"] = "base64"

        response_dict = None
        if self.response:
            response_dict = self.response.model_dump()
            # Convert datetime to ISO format
            if "timestamp" in response_dict and hasattr(
                response_dict["timestamp"], "isoformat"
            ):
                response_dict["timestamp"] = response_dict["timestamp"].isoformat()
            # Convert bytes to base64 string
            if "body" in response_dict and isinstance(response_dict["body"], bytes):
                import base64

                response_dict["body"] = base64.b64encode(response_dict["body"]).decode(
                    "ascii"
                )
                response_dict["body_encoding"] = "base64"

        return {
            "id": str(self.id),
            "name": self.name,
            "request": request_dict,
            "response": response_dict,
            "history": self.history.to_dict(),
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RepeaterTab":
        """Create from dictionary."""
        import base64

        request = None
        if data.get("request"):
            request_data = data["request"]
            # Decode base64 body if present
            if "body" in request_data and request_data.get("body_encoding") == "base64":
                request_data["body"] = base64.b64decode(request_data["body"])
                del request_data["body_encoding"]
            request = HTTPRequest(**request_data)

        tab = cls(name=data["name"], request=request)
        tab.id = uuid.UUID(data["id"])

        if data.get("response"):
            response_data = data["response"]
            # Decode base64 body if present
            if (
                "body" in response_data
                and response_data.get("body_encoding") == "base64"
            ):
                response_data["body"] = base64.b64decode(response_data["body"])
                del response_data["body_encoding"]
            tab.response = HTTPResponse(**response_data)

        if data.get("history"):
            tab.history = RequestHistory.from_dict(data["history"])

        tab.created_at = datetime.fromisoformat(data["created_at"])
        tab.modified_at = datetime.fromisoformat(data["modified_at"])

        return tab


class RepeaterSession:
    """
    Repeater session with multi-tab support and persistence.

    Manages multiple repeater tabs and provides session save/load functionality.
    """

    def __init__(self, project_id: Optional[uuid.UUID] = None):
        self.id = uuid.uuid4()
        self.project_id = project_id
        self.tabs: Dict[uuid.UUID, RepeaterTab] = {}
        self.active_tab_id: Optional[uuid.UUID] = None
        self.created_at = datetime.now(UTC)
        self.editor = HTTPRequestEditor()

    def create_tab(
        self, name: str, request: Optional[HTTPRequest] = None
    ) -> RepeaterTab:
        """
        Create a new repeater tab.

        Args:
            name: Tab name
            request: Initial HTTPRequest (optional)

        Returns:
            Created RepeaterTab
        """
        tab = RepeaterTab(name, request)
        self.tabs[tab.id] = tab
        self.active_tab_id = tab.id
        return tab

    def close_tab(self, tab_id: uuid.UUID) -> bool:
        """
        Close a repeater tab.

        Args:
            tab_id: ID of tab to close

        Returns:
            True if tab was closed, False if not found
        """
        if tab_id in self.tabs:
            del self.tabs[tab_id]

            # Update active tab if closed tab was active
            if self.active_tab_id == tab_id:
                self.active_tab_id = next(iter(self.tabs.keys())) if self.tabs else None

            return True
        return False

    def get_tab(self, tab_id: uuid.UUID) -> Optional[RepeaterTab]:
        """Get a tab by ID."""
        return self.tabs.get(tab_id)

    def get_active_tab(self) -> Optional[RepeaterTab]:
        """Get the currently active tab."""
        if self.active_tab_id:
            return self.tabs.get(self.active_tab_id)
        return None

    def set_active_tab(self, tab_id: uuid.UUID) -> bool:
        """
        Set the active tab.

        Args:
            tab_id: ID of tab to activate

        Returns:
            True if tab was activated, False if not found
        """
        if tab_id in self.tabs:
            self.active_tab_id = tab_id
            return True
        return False

    async def send_request(self, request: HTTPRequest) -> HTTPResponse:
        """
        Send an HTTP request and capture the response.

        Args:
            request: HTTPRequest to send

        Returns:
            HTTPResponse received

        Raises:
            RepeaterError: If request sending fails
        """
        start_time = datetime.now(UTC)

        try:
            # Prepare request
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Convert headers to aiohttp format
                headers = dict(request.headers)

                # Send request
                async with session.request(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    data=request.body,
                    allow_redirects=False,
                    ssl=False,  # Allow self-signed certificates for testing
                ) as response:
                    # Read response body
                    body = await response.read()

                    # Calculate duration
                    end_time = datetime.now(UTC)
                    duration_ms = int((end_time - start_time).total_seconds() * 1000)

                    # Build response object
                    response_headers = dict(response.headers)

                    return HTTPResponse(
                        status_code=response.status,
                        headers=response_headers,
                        body=body if body else None,
                        timestamp=end_time,
                        duration_ms=duration_ms,
                    )

        except aiohttp.ClientError as e:
            raise RepeaterError(f"Failed to send request: {e}")
        except Exception as e:
            raise RepeaterError(f"Unexpected error sending request: {e}")

    def save_session(self, filepath: Path) -> None:
        """
        Save session to file.

        Args:
            filepath: Path to save session file
        """
        data = {
            "id": str(self.id),
            "project_id": str(self.project_id) if self.project_id else None,
            "tabs": [tab.to_dict() for tab in self.tabs.values()],
            "active_tab_id": str(self.active_tab_id) if self.active_tab_id else None,
            "created_at": self.created_at.isoformat(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_session(cls, filepath: Path) -> "RepeaterSession":
        """
        Load session from file.

        Args:
            filepath: Path to session file

        Returns:
            Loaded RepeaterSession

        Raises:
            RepeaterError: If loading fails
        """
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            project_id = (
                uuid.UUID(data["project_id"]) if data.get("project_id") else None
            )
            session = cls(project_id=project_id)
            session.id = uuid.UUID(data["id"])
            session.created_at = datetime.fromisoformat(data["created_at"])

            # Load tabs
            for tab_data in data.get("tabs", []):
                tab = RepeaterTab.from_dict(tab_data)
                session.tabs[tab.id] = tab

            # Set active tab
            if data.get("active_tab_id"):
                session.active_tab_id = uuid.UUID(data["active_tab_id"])

            return session

        except Exception as e:
            raise RepeaterError(f"Failed to load session: {e}")
