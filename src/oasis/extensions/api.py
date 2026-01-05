"""
Extension API

Provides the public API that extensions can use to interact with OASIS.
All extension access to OASIS functionality goes through this controlled interface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..core.models import HTTPRequest, HTTPResponse, Finding
from .models import ExtensionPermission, ExtensionAuditLog


class ExtensionContext:
    """
    Context object provided to extensions containing their identity and permissions.
    """

    def __init__(
        self,
        extension_id: UUID,
        extension_name: str,
        granted_permissions: set[ExtensionPermission],
        audit_logger: "AuditLogger",
    ):
        self.extension_id = extension_id
        self.extension_name = extension_name
        self.granted_permissions = granted_permissions
        self._audit_logger = audit_logger

    def has_permission(self, permission: ExtensionPermission) -> bool:
        """Check if extension has a specific permission"""
        return permission in self.granted_permissions

    def log_action(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> None:
        """Log an action performed by the extension"""
        self._audit_logger.log(
            extension_id=self.extension_id,
            extension_name=self.extension_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
            error_message=error_message,
        )


class AuditLogger:
    """Handles audit logging for extension actions"""

    def __init__(self):
        self._logs: List[ExtensionAuditLog] = []

    def log(
        self,
        extension_id: UUID,
        extension_name: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> ExtensionAuditLog:
        """Create and store an audit log entry"""
        log_entry = ExtensionAuditLog(
            extension_id=extension_id,
            extension_name=extension_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
            error_message=error_message,
        )
        self._logs.append(log_entry)
        return log_entry

    def get_logs(
        self,
        extension_id: Optional[UUID] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[ExtensionAuditLog]:
        """Retrieve audit logs with optional filtering"""
        logs = self._logs

        if extension_id:
            logs = [log for log in logs if log.extension_id == extension_id]
        if action:
            logs = [log for log in logs if log.action == action]
        if resource_type:
            logs = [log for log in logs if log.resource_type == resource_type]

        return logs


class ExtensionAPI(ABC):
    """
    Abstract base class defining the API available to extensions.
    Extensions interact with OASIS through implementations of this interface.
    """

    def __init__(self, context: ExtensionContext):
        self.context = context

    # HTTP Traffic Access

    @abstractmethod
    async def get_http_flows(
        self, project_id: Optional[UUID] = None, limit: int = 100
    ) -> List[tuple[HTTPRequest, Optional[HTTPResponse]]]:
        """
        Retrieve HTTP traffic flows.
        Requires: READ_HTTP_TRAFFIC permission
        """
        pass

    @abstractmethod
    async def modify_http_request(
        self, flow_id: UUID, modified_request: HTTPRequest
    ) -> bool:
        """
        Modify an HTTP request before it's sent.
        Requires: MODIFY_HTTP_TRAFFIC permission
        """
        pass

    @abstractmethod
    async def modify_http_response(
        self, flow_id: UUID, modified_response: HTTPResponse
    ) -> bool:
        """
        Modify an HTTP response before it's delivered.
        Requires: MODIFY_HTTP_TRAFFIC permission
        """
        pass

    # Scanner Access

    @abstractmethod
    async def get_scan_results(
        self, project_id: Optional[UUID] = None, severity: Optional[str] = None
    ) -> List[Finding]:
        """
        Retrieve vulnerability scan results.
        Requires: READ_SCAN_RESULTS permission
        """
        pass

    @abstractmethod
    async def add_finding(self, finding: Finding) -> UUID:
        """
        Add a new vulnerability finding.
        Requires: MODIFY_SCAN_RESULTS permission
        """
        pass

    @abstractmethod
    async def trigger_scan(
        self, target_url: str, scan_policy: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        Trigger a vulnerability scan.
        Requires: TRIGGER_SCANS permission
        """
        pass

    # Project Data Access

    @abstractmethod
    async def get_project_data(
        self, project_id: UUID, data_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve project data.
        Requires: READ_PROJECT_DATA permission
        """
        pass

    @abstractmethod
    async def save_project_data(
        self, project_id: UUID, data_type: str, data: Dict[str, Any]
    ) -> bool:
        """
        Save project data.
        Requires: WRITE_PROJECT_DATA permission
        """
        pass

    # UI Integration

    @abstractmethod
    def register_ui_component(
        self, component_type: str, component_config: Dict[str, Any]
    ) -> str:
        """
        Register a UI component (menu item, panel, etc.).
        Requires: ADD_UI_COMPONENTS permission
        """
        pass

    # Utility Methods

    def check_permission(self, permission: ExtensionPermission) -> None:
        """
        Check if extension has permission, raise exception if not.
        """
        if not self.context.has_permission(permission):
            raise PermissionError(
                f"Extension '{self.context.extension_name}' does not have "
                f"permission: {permission.value}"
            )


class ExtensionCapability:
    """
    Describes a capability that an extension provides to the system.
    """

    def __init__(self, name: str, description: str, handler: callable):
        self.name = name
        self.description = description
        self.handler = handler

    async def invoke(self, *args, **kwargs) -> Any:
        """Invoke the capability handler"""
        return await self.handler(*args, **kwargs)
