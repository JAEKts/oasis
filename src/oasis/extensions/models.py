"""
Extension Framework Data Models

Defines data structures for extension metadata, permissions, and audit logging.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set
from uuid import UUID, uuid4


class ExtensionStatus(Enum):
    """Extension lifecycle status"""

    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


class ExtensionPermission(Enum):
    """Permissions that can be granted to extensions"""

    # HTTP traffic access
    READ_HTTP_TRAFFIC = "read_http_traffic"
    MODIFY_HTTP_TRAFFIC = "modify_http_traffic"

    # Scanner access
    READ_SCAN_RESULTS = "read_scan_results"
    MODIFY_SCAN_RESULTS = "modify_scan_results"
    TRIGGER_SCANS = "trigger_scans"

    # UI access
    ADD_UI_COMPONENTS = "add_ui_components"
    MODIFY_UI_COMPONENTS = "modify_ui_components"

    # Storage access
    READ_PROJECT_DATA = "read_project_data"
    WRITE_PROJECT_DATA = "write_project_data"

    # System access
    EXECUTE_COMMANDS = "execute_commands"
    NETWORK_ACCESS = "network_access"
    FILE_SYSTEM_ACCESS = "file_system_access"


@dataclass
class ExtensionMetadata:
    """Metadata describing an extension"""

    name: str
    version: str
    author: str
    description: str
    homepage: Optional[str] = None
    license: Optional[str] = None
    required_permissions: Set[ExtensionPermission] = field(default_factory=set)
    dependencies: List[str] = field(default_factory=list)
    python_version: str = ">=3.11"
    oasis_version: str = ">=1.0.0"


@dataclass
class Extension:
    """Represents a loaded extension"""

    id: UUID = field(default_factory=uuid4)
    metadata: ExtensionMetadata = field(
        default_factory=lambda: ExtensionMetadata("", "", "", "")
    )
    status: ExtensionStatus = ExtensionStatus.UNLOADED
    granted_permissions: Set[ExtensionPermission] = field(default_factory=set)
    module_path: Optional[str] = None
    entry_point: Optional[str] = None
    loaded_at: Optional[datetime] = None
    error_message: Optional[str] = None
    instance: Optional[object] = None


@dataclass
class ExtensionAuditLog:
    """Audit log entry for extension actions"""

    id: UUID = field(default_factory=uuid4)
    extension_id: UUID = field(default_factory=uuid4)
    extension_name: str = ""
    action: str = ""
    resource_type: str = ""
    resource_id: Optional[str] = None
    details: Dict[str, any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class ExtensionCapability:
    """Describes a capability provided by an extension"""

    name: str
    description: str
    version: str
    provides: List[str] = field(default_factory=list)
