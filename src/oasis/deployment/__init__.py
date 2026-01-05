"""
OASIS Deployment Module

Provides secure update mechanisms, vulnerability disclosure, and deployment packaging.
"""

from .updater import UpdateManager, UpdateInfo, UpdateVerifier
from .packager import DeploymentPackager, PlatformPackage
from .security import VulnerabilityDisclosure, SecurityUpdatePipeline

__all__ = [
    "UpdateManager",
    "UpdateInfo",
    "UpdateVerifier",
    "DeploymentPackager",
    "PlatformPackage",
    "VulnerabilityDisclosure",
    "SecurityUpdatePipeline",
]
