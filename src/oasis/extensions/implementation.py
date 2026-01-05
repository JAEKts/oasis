"""
Extension API Implementation

Concrete implementation of the ExtensionAPI that provides controlled access
to OASIS components with permission checks and audit logging.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from ..core.models import HTTPRequest, HTTPResponse, Finding
from .api import ExtensionAPI, ExtensionContext
from .models import ExtensionPermission


class OASISExtensionAPI(ExtensionAPI):
    """
    Concrete implementation of ExtensionAPI providing controlled access to OASIS.

    All methods enforce permission checks and log actions for audit trails.
    """

    def __init__(
        self,
        context: ExtensionContext,
        http_traffic_provider: Optional[Any] = None,
        scanner_provider: Optional[Any] = None,
        project_data_provider: Optional[Any] = None,
        ui_provider: Optional[Any] = None,
    ):
        super().__init__(context)
        self._http_traffic_provider = http_traffic_provider
        self._scanner_provider = scanner_provider
        self._project_data_provider = project_data_provider
        self._ui_provider = ui_provider

    # HTTP Traffic Access

    async def get_http_flows(
        self, project_id: Optional[UUID] = None, limit: int = 100
    ) -> List[tuple[HTTPRequest, Optional[HTTPResponse]]]:
        """
        Retrieve HTTP traffic flows.
        Requires: READ_HTTP_TRAFFIC permission
        """
        self.check_permission(ExtensionPermission.READ_HTTP_TRAFFIC)

        self.context.log_action(
            action="get_http_flows",
            resource_type="http_flow",
            resource_id=str(project_id) if project_id else None,
            details={"limit": limit},
            success=True,
        )

        if self._http_traffic_provider:
            return await self._http_traffic_provider.get_flows(project_id, limit)
        return []

    async def modify_http_request(
        self, flow_id: UUID, modified_request: HTTPRequest
    ) -> bool:
        """
        Modify an HTTP request before it's sent.
        Requires: MODIFY_HTTP_TRAFFIC permission
        """
        self.check_permission(ExtensionPermission.MODIFY_HTTP_TRAFFIC)

        try:
            if self._http_traffic_provider:
                result = await self._http_traffic_provider.modify_request(
                    flow_id, modified_request
                )

                self.context.log_action(
                    action="modify_http_request",
                    resource_type="http_flow",
                    resource_id=str(flow_id),
                    details={
                        "method": modified_request.method,
                        "url": modified_request.url,
                    },
                    success=result,
                )

                return result

            return False

        except Exception as e:
            self.context.log_action(
                action="modify_http_request",
                resource_type="http_flow",
                resource_id=str(flow_id),
                success=False,
                error_message=str(e),
            )
            raise

    async def modify_http_response(
        self, flow_id: UUID, modified_response: HTTPResponse
    ) -> bool:
        """
        Modify an HTTP response before it's delivered.
        Requires: MODIFY_HTTP_TRAFFIC permission
        """
        self.check_permission(ExtensionPermission.MODIFY_HTTP_TRAFFIC)

        try:
            if self._http_traffic_provider:
                result = await self._http_traffic_provider.modify_response(
                    flow_id, modified_response
                )

                self.context.log_action(
                    action="modify_http_response",
                    resource_type="http_flow",
                    resource_id=str(flow_id),
                    details={"status_code": modified_response.status_code},
                    success=result,
                )

                return result

            return False

        except Exception as e:
            self.context.log_action(
                action="modify_http_response",
                resource_type="http_flow",
                resource_id=str(flow_id),
                success=False,
                error_message=str(e),
            )
            raise

    # Scanner Access

    async def get_scan_results(
        self, project_id: Optional[UUID] = None, severity: Optional[str] = None
    ) -> List[Finding]:
        """
        Retrieve vulnerability scan results.
        Requires: READ_SCAN_RESULTS permission
        """
        self.check_permission(ExtensionPermission.READ_SCAN_RESULTS)

        self.context.log_action(
            action="get_scan_results",
            resource_type="finding",
            resource_id=str(project_id) if project_id else None,
            details={"severity": severity} if severity else {},
            success=True,
        )

        if self._scanner_provider:
            return await self._scanner_provider.get_findings(project_id, severity)
        return []

    async def add_finding(self, finding: Finding) -> UUID:
        """
        Add a new vulnerability finding.
        Requires: MODIFY_SCAN_RESULTS permission
        """
        self.check_permission(ExtensionPermission.MODIFY_SCAN_RESULTS)

        try:
            if self._scanner_provider:
                finding_id = await self._scanner_provider.add_finding(finding)

                self.context.log_action(
                    action="add_finding",
                    resource_type="finding",
                    resource_id=str(finding_id),
                    details={
                        "vulnerability_type": finding.vulnerability_type,
                        "severity": finding.severity,
                    },
                    success=True,
                )

                return finding_id

            raise RuntimeError("Scanner provider not available")

        except Exception as e:
            self.context.log_action(
                action="add_finding",
                resource_type="finding",
                success=False,
                error_message=str(e),
            )
            raise

    async def trigger_scan(
        self, target_url: str, scan_policy: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        Trigger a vulnerability scan.
        Requires: TRIGGER_SCANS permission
        """
        self.check_permission(ExtensionPermission.TRIGGER_SCANS)

        try:
            if self._scanner_provider:
                scan_id = await self._scanner_provider.start_scan(
                    target_url, scan_policy
                )

                self.context.log_action(
                    action="trigger_scan",
                    resource_type="scan",
                    resource_id=str(scan_id),
                    details={"target_url": target_url},
                    success=True,
                )

                return scan_id

            raise RuntimeError("Scanner provider not available")

        except Exception as e:
            self.context.log_action(
                action="trigger_scan",
                resource_type="scan",
                details={"target_url": target_url},
                success=False,
                error_message=str(e),
            )
            raise

    # Project Data Access

    async def get_project_data(
        self, project_id: UUID, data_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve project data.
        Requires: READ_PROJECT_DATA permission
        """
        self.check_permission(ExtensionPermission.READ_PROJECT_DATA)

        self.context.log_action(
            action="get_project_data",
            resource_type="project_data",
            resource_id=str(project_id),
            details={"data_type": data_type},
            success=True,
        )

        if self._project_data_provider:
            return await self._project_data_provider.get_data(project_id, data_type)
        return None

    async def save_project_data(
        self, project_id: UUID, data_type: str, data: Dict[str, Any]
    ) -> bool:
        """
        Save project data.
        Requires: WRITE_PROJECT_DATA permission
        """
        self.check_permission(ExtensionPermission.WRITE_PROJECT_DATA)

        try:
            if self._project_data_provider:
                result = await self._project_data_provider.save_data(
                    project_id, data_type, data
                )

                self.context.log_action(
                    action="save_project_data",
                    resource_type="project_data",
                    resource_id=str(project_id),
                    details={"data_type": data_type},
                    success=result,
                )

                return result

            return False

        except Exception as e:
            self.context.log_action(
                action="save_project_data",
                resource_type="project_data",
                resource_id=str(project_id),
                details={"data_type": data_type},
                success=False,
                error_message=str(e),
            )
            raise

    # UI Integration

    def register_ui_component(
        self, component_type: str, component_config: Dict[str, Any]
    ) -> str:
        """
        Register a UI component (menu item, panel, etc.).
        Requires: ADD_UI_COMPONENTS permission
        """
        self.check_permission(ExtensionPermission.ADD_UI_COMPONENTS)

        try:
            if self._ui_provider:
                component_id = self._ui_provider.register_component(
                    component_type, component_config
                )

                self.context.log_action(
                    action="register_ui_component",
                    resource_type="ui_component",
                    resource_id=component_id,
                    details={"component_type": component_type},
                    success=True,
                )

                return component_id

            raise RuntimeError("UI provider not available")

        except Exception as e:
            self.context.log_action(
                action="register_ui_component",
                resource_type="ui_component",
                details={"component_type": component_type},
                success=False,
                error_message=str(e),
            )
            raise


class RollbackManager:
    """
    Manages rollback capabilities for extension-modified data.

    Tracks changes made by extensions and provides rollback functionality.
    """

    def __init__(self):
        self._snapshots: Dict[str, List[Dict[str, Any]]] = {}

    def create_snapshot(
        self, resource_type: str, resource_id: str, data: Dict[str, Any]
    ) -> str:
        """
        Create a snapshot of data before modification.

        Args:
            resource_type: Type of resource (e.g., 'http_flow', 'finding')
            resource_id: Unique identifier for the resource
            data: Current state of the data

        Returns:
            Snapshot ID
        """
        snapshot_key = f"{resource_type}:{resource_id}"

        if snapshot_key not in self._snapshots:
            self._snapshots[snapshot_key] = []

        snapshot = {
            "snapshot_id": f"{snapshot_key}:{len(self._snapshots[snapshot_key])}",
            "data": data.copy(),
        }

        self._snapshots[snapshot_key].append(snapshot)

        return snapshot["snapshot_id"]

    def rollback(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """
        Rollback to a previous snapshot.

        Args:
            snapshot_id: ID of the snapshot to rollback to

        Returns:
            The snapshot data if found, None otherwise
        """
        # Parse snapshot_id to get resource key and index
        parts = snapshot_id.rsplit(":", 1)
        if len(parts) != 2:
            return None

        snapshot_key = parts[0]
        try:
            snapshot_index = int(parts[1])
        except ValueError:
            return None

        if snapshot_key not in self._snapshots:
            return None

        snapshots = self._snapshots[snapshot_key]
        if snapshot_index >= len(snapshots):
            return None

        return snapshots[snapshot_index]["data"]

    def get_snapshots(
        self, resource_type: Optional[str] = None, resource_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all snapshots, optionally filtered by resource type and ID.

        Args:
            resource_type: Filter by resource type
            resource_id: Filter by resource ID

        Returns:
            List of snapshots matching the filters
        """
        results = []

        for snapshot_key, snapshots in self._snapshots.items():
            # Parse the key
            key_parts = snapshot_key.split(":", 1)
            if len(key_parts) != 2:
                continue

            key_resource_type, key_resource_id = key_parts

            # Apply filters
            if resource_type and key_resource_type != resource_type:
                continue
            if resource_id and key_resource_id != resource_id:
                continue

            results.extend(snapshots)

        return results

    def clear_snapshots(
        self, resource_type: Optional[str] = None, resource_id: Optional[str] = None
    ) -> int:
        """
        Clear snapshots, optionally filtered by resource type and ID.

        Args:
            resource_type: Filter by resource type
            resource_id: Filter by resource ID

        Returns:
            Number of snapshots cleared
        """
        if resource_type is None and resource_id is None:
            # Clear all
            count = sum(len(snapshots) for snapshots in self._snapshots.values())
            self._snapshots.clear()
            return count

        # Clear filtered
        keys_to_remove = []
        count = 0

        for snapshot_key, snapshots in self._snapshots.items():
            key_parts = snapshot_key.split(":", 1)
            if len(key_parts) != 2:
                continue

            key_resource_type, key_resource_id = key_parts

            if resource_type and key_resource_type != resource_type:
                continue
            if resource_id and key_resource_id != resource_id:
                continue

            keys_to_remove.append(snapshot_key)
            count += len(snapshots)

        for key in keys_to_remove:
            del self._snapshots[key]

        return count
