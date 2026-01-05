"""
Extension Manager

Manages the lifecycle of extensions including loading, unloading, and updating.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set
from uuid import UUID

from .models import (
    Extension,
    ExtensionMetadata,
    ExtensionPermission,
    ExtensionStatus,
    ExtensionAuditLog,
)
from .sandbox import ExtensionSandbox
from .api import ExtensionAPI, ExtensionContext, AuditLogger


class ExtensionManager:
    """
    Manages extension lifecycle: loading, unloading, updating, and permission management.
    """

    def __init__(self):
        self.audit_logger = AuditLogger()
        self.sandbox = ExtensionSandbox(self.audit_logger)
        self._extensions: Dict[UUID, Extension] = {}
        self._extension_apis: Dict[UUID, ExtensionAPI] = {}
        self._lock = asyncio.Lock()

    async def load_extension(
        self,
        module_path: Path,
        metadata: ExtensionMetadata,
        granted_permissions: Optional[Set[ExtensionPermission]] = None,
        entry_point: str = "initialize",
    ) -> Optional[UUID]:
        """
        Load an extension from a module path.

        Args:
            module_path: Path to the extension module
            metadata: Extension metadata
            granted_permissions: Permissions to grant (defaults to required permissions)
            entry_point: Name of the initialization function

        Returns:
            Extension ID if loaded successfully, None otherwise
        """
        async with self._lock:
            # Create extension object
            extension = Extension(
                metadata=metadata,
                granted_permissions=granted_permissions
                or metadata.required_permissions,
            )

            # Validate permissions
            if not extension.granted_permissions.issuperset(
                metadata.required_permissions
            ):
                missing = metadata.required_permissions - extension.granted_permissions
                extension.status = ExtensionStatus.ERROR
                extension.error_message = f"Missing required permissions: {missing}"
                return None

            # Load extension in sandbox
            success = self.sandbox.load_extension(extension, module_path, entry_point)

            if not success:
                return None

            # Initialize the extension
            try:
                context = self.sandbox.create_context(extension)
                entry_func = getattr(extension.instance, entry_point)

                # Call initialization function
                result = entry_func(context)
                if asyncio.iscoroutine(result):
                    await result

                extension.status = ExtensionStatus.ACTIVE
                extension.loaded_at = datetime.now(timezone.utc)

                # Store extension
                self._extensions[extension.id] = extension

                return extension.id

            except Exception as e:
                extension.status = ExtensionStatus.ERROR
                extension.error_message = f"Initialization failed: {str(e)}"

                self.audit_logger.log(
                    extension_id=extension.id,
                    extension_name=extension.metadata.name,
                    action="initialize",
                    resource_type="extension",
                    resource_id=str(extension.id),
                    success=False,
                    error_message=str(e),
                )

                return None

    async def unload_extension(self, extension_id: UUID) -> bool:
        """
        Unload an extension.

        Args:
            extension_id: ID of extension to unload

        Returns:
            True if unloaded successfully, False otherwise
        """
        async with self._lock:
            extension = self._extensions.get(extension_id)
            if not extension:
                return False

            success = self.sandbox.unload_extension(extension)

            if success:
                # Remove from tracking
                del self._extensions[extension_id]
                if extension_id in self._extension_apis:
                    del self._extension_apis[extension_id]

            return success

    async def reload_extension(self, extension_id: UUID) -> bool:
        """
        Reload an extension (unload and load again).

        Args:
            extension_id: ID of extension to reload

        Returns:
            True if reloaded successfully, False otherwise
        """
        extension = self._extensions.get(extension_id)
        if not extension or not extension.module_path:
            return False

        # Store configuration
        module_path = Path(extension.module_path)
        metadata = extension.metadata
        granted_permissions = extension.granted_permissions
        entry_point = extension.entry_point or "initialize"

        # Unload
        await self.unload_extension(extension_id)

        # Reload
        new_id = await self.load_extension(
            module_path, metadata, granted_permissions, entry_point
        )

        return new_id is not None

    def get_extension(self, extension_id: UUID) -> Optional[Extension]:
        """Get extension by ID"""
        return self._extensions.get(extension_id)

    def get_all_extensions(self) -> List[Extension]:
        """Get all loaded extensions"""
        return list(self._extensions.values())

    def get_extensions_by_status(self, status: ExtensionStatus) -> List[Extension]:
        """Get extensions filtered by status"""
        return [ext for ext in self._extensions.values() if ext.status == status]

    async def enable_extension(self, extension_id: UUID) -> bool:
        """
        Enable a disabled extension.

        Args:
            extension_id: ID of extension to enable

        Returns:
            True if enabled successfully, False otherwise
        """
        extension = self._extensions.get(extension_id)
        if not extension or extension.status != ExtensionStatus.DISABLED:
            return False

        extension.status = ExtensionStatus.ACTIVE

        self.audit_logger.log(
            extension_id=extension.id,
            extension_name=extension.metadata.name,
            action="enable",
            resource_type="extension",
            resource_id=str(extension.id),
            success=True,
        )

        return True

    async def disable_extension(self, extension_id: UUID) -> bool:
        """
        Disable an active extension without unloading it.

        Args:
            extension_id: ID of extension to disable

        Returns:
            True if disabled successfully, False otherwise
        """
        extension = self._extensions.get(extension_id)
        if not extension or extension.status != ExtensionStatus.ACTIVE:
            return False

        extension.status = ExtensionStatus.DISABLED

        self.audit_logger.log(
            extension_id=extension.id,
            extension_name=extension.metadata.name,
            action="disable",
            resource_type="extension",
            resource_id=str(extension.id),
            success=True,
        )

        return True

    def get_audit_logs(
        self,
        extension_id: Optional[UUID] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[ExtensionAuditLog]:
        """
        Retrieve audit logs with optional filtering.

        Args:
            extension_id: Filter by extension ID
            action: Filter by action type
            resource_type: Filter by resource type

        Returns:
            List of matching audit log entries
        """
        return self.audit_logger.get_logs(extension_id, action, resource_type)

    async def grant_permission(
        self, extension_id: UUID, permission: ExtensionPermission
    ) -> bool:
        """
        Grant a permission to an extension.

        Args:
            extension_id: ID of extension
            permission: Permission to grant

        Returns:
            True if granted successfully, False otherwise
        """
        extension = self._extensions.get(extension_id)
        if not extension:
            return False

        extension.granted_permissions.add(permission)

        self.audit_logger.log(
            extension_id=extension.id,
            extension_name=extension.metadata.name,
            action="grant_permission",
            resource_type="permission",
            details={"permission": permission.value},
            success=True,
        )

        return True

    async def revoke_permission(
        self, extension_id: UUID, permission: ExtensionPermission
    ) -> bool:
        """
        Revoke a permission from an extension.

        Args:
            extension_id: ID of extension
            permission: Permission to revoke

        Returns:
            True if revoked successfully, False otherwise
        """
        extension = self._extensions.get(extension_id)
        if not extension:
            return False

        if permission in extension.granted_permissions:
            extension.granted_permissions.remove(permission)

            self.audit_logger.log(
                extension_id=extension.id,
                extension_name=extension.metadata.name,
                action="revoke_permission",
                resource_type="permission",
                details={"permission": permission.value},
                success=True,
            )

            return True

        return False
