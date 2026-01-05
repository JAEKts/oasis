"""
OASIS Extension Framework

Provides plugin architecture for extending OASIS functionality with custom tools
and integrations while maintaining security isolation and audit trails.
"""

from .api import ExtensionAPI, ExtensionContext, ExtensionCapability
from .manager import ExtensionManager
from .sandbox import ExtensionSandbox
from .implementation import OASISExtensionAPI, RollbackManager
from .models import (
    Extension,
    ExtensionMetadata,
    ExtensionStatus,
    ExtensionPermission,
    ExtensionAuditLog,
)

__all__ = [
    "ExtensionAPI",
    "ExtensionContext",
    "ExtensionCapability",
    "ExtensionManager",
    "ExtensionSandbox",
    "OASISExtensionAPI",
    "RollbackManager",
    "Extension",
    "ExtensionMetadata",
    "ExtensionStatus",
    "ExtensionPermission",
    "ExtensionAuditLog",
]
