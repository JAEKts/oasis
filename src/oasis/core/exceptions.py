"""
OASIS Exception Hierarchy

Defines the complete exception hierarchy for error handling throughout the system.
"""

from typing import Any, Dict, Optional


class OASISException(Exception):
    """Base exception for all OASIS errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ProxyError(OASISException):
    """Proxy-related errors (connection, certificate, interception)."""

    pass


class ScanError(OASISException):
    """Scanner-related errors (target unreachable, policy invalid)."""

    pass


class StorageError(OASISException):
    """Data storage and retrieval errors."""

    pass


class SecurityError(OASISException):
    """Security-related errors (authentication, authorization, encryption)."""

    pass


class ConfigurationError(OASISException):
    """Configuration-related errors."""

    pass


class ValidationError(OASISException):
    """Data validation errors."""

    pass


class NetworkError(OASISException):
    """Network-related errors."""

    pass


class PluginError(OASISException):
    """Plugin/extension-related errors."""

    pass
