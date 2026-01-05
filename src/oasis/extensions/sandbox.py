"""
Extension Sandbox

Provides security sandboxing for extensions to prevent malicious code from
compromising the OASIS system.
"""

import sys
import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional, Set
from uuid import UUID

from .models import Extension, ExtensionPermission, ExtensionStatus
from .api import ExtensionContext, AuditLogger


class ExtensionSandbox:
    """
    Security sandbox for loading and executing extensions with restricted access.
    """

    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self._restricted_modules = {
            "os",
            "subprocess",
            "sys",
            "__builtin__",
            "builtins",
        }
        self._allowed_builtins = {
            "abs",
            "all",
            "any",
            "bool",
            "bytes",
            "dict",
            "enumerate",
            "filter",
            "float",
            "int",
            "isinstance",
            "len",
            "list",
            "map",
            "max",
            "min",
            "range",
            "set",
            "str",
            "sum",
            "tuple",
            "zip",
        }

    def load_extension(
        self,
        extension: Extension,
        module_path: Path,
        entry_point: str = "initialize",
    ) -> bool:
        """
        Load an extension from a Python module with security restrictions.

        Args:
            extension: Extension object to populate
            module_path: Path to the extension module
            entry_point: Name of the initialization function

        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            extension.status = ExtensionStatus.LOADING
            extension.module_path = str(module_path)
            extension.entry_point = entry_point

            # Validate module path
            if not module_path.exists():
                raise FileNotFoundError(f"Extension module not found: {module_path}")

            # Check if extension has dangerous permissions
            self._validate_permissions(extension)

            # Load the module
            spec = importlib.util.spec_from_file_location(
                f"oasis_extension_{extension.id}", module_path
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot load module from {module_path}")

            module = importlib.util.module_from_spec(spec)

            # Apply sandbox restrictions if extension doesn't have system access
            if (
                ExtensionPermission.EXECUTE_COMMANDS
                not in extension.granted_permissions
            ):
                self._apply_sandbox_restrictions(module)

            # Load the module
            spec.loader.exec_module(module)

            # Get the entry point function
            if not hasattr(module, entry_point):
                raise AttributeError(
                    f"Extension module missing entry point: {entry_point}"
                )

            entry_func = getattr(module, entry_point)
            if not callable(entry_func):
                raise TypeError(f"Entry point {entry_point} is not callable")

            # Store the module instance
            extension.instance = module
            extension.status = ExtensionStatus.LOADED

            # Log successful load
            self.audit_logger.log(
                extension_id=extension.id,
                extension_name=extension.metadata.name,
                action="load",
                resource_type="extension",
                resource_id=str(extension.id),
                success=True,
            )

            return True

        except Exception as e:
            extension.status = ExtensionStatus.ERROR
            extension.error_message = str(e)

            # Log failed load
            self.audit_logger.log(
                extension_id=extension.id,
                extension_name=extension.metadata.name,
                action="load",
                resource_type="extension",
                resource_id=str(extension.id),
                success=False,
                error_message=str(e),
            )

            return False

    def unload_extension(self, extension: Extension) -> bool:
        """
        Unload an extension and clean up its resources.

        Args:
            extension: Extension to unload

        Returns:
            True if unloaded successfully, False otherwise
        """
        try:
            # Call cleanup function if it exists
            if extension.instance and hasattr(extension.instance, "cleanup"):
                cleanup_func = getattr(extension.instance, "cleanup")
                if callable(cleanup_func):
                    cleanup_func()

            # Remove from sys.modules if present
            module_name = f"oasis_extension_{extension.id}"
            if module_name in sys.modules:
                del sys.modules[module_name]

            extension.instance = None
            extension.status = ExtensionStatus.UNLOADED

            # Log successful unload
            self.audit_logger.log(
                extension_id=extension.id,
                extension_name=extension.metadata.name,
                action="unload",
                resource_type="extension",
                resource_id=str(extension.id),
                success=True,
            )

            return True

        except Exception as e:
            extension.error_message = str(e)

            # Log failed unload
            self.audit_logger.log(
                extension_id=extension.id,
                extension_name=extension.metadata.name,
                action="unload",
                resource_type="extension",
                resource_id=str(extension.id),
                success=False,
                error_message=str(e),
            )

            return False

    def _validate_permissions(self, extension: Extension) -> None:
        """
        Validate that requested permissions are reasonable.

        Args:
            extension: Extension to validate

        Raises:
            PermissionError: If dangerous permission combinations are detected
        """
        dangerous_perms = {
            ExtensionPermission.EXECUTE_COMMANDS,
            ExtensionPermission.FILE_SYSTEM_ACCESS,
        }

        requested_dangerous = extension.metadata.required_permissions & dangerous_perms

        if requested_dangerous and not extension.granted_permissions.issuperset(
            requested_dangerous
        ):
            raise PermissionError(
                f"Extension requests dangerous permissions that were not granted: "
                f"{requested_dangerous}"
            )

    def _apply_sandbox_restrictions(self, module: Any) -> None:
        """
        Apply sandbox restrictions to a module to limit dangerous operations.

        Args:
            module: Module to restrict
        """
        # Restrict built-in functions
        restricted_builtins = {}
        for name in self._allowed_builtins:
            if hasattr(__builtins__, name):
                restricted_builtins[name] = getattr(__builtins__, name)

        # Override __builtins__ in the module
        module.__builtins__ = restricted_builtins

    def create_context(self, extension: Extension) -> ExtensionContext:
        """
        Create an execution context for an extension.

        Args:
            extension: Extension to create context for

        Returns:
            ExtensionContext with appropriate permissions
        """
        return ExtensionContext(
            extension_id=extension.id,
            extension_name=extension.metadata.name,
            granted_permissions=extension.granted_permissions,
            audit_logger=self.audit_logger,
        )
