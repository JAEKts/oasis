"""
OASIS Security Module

Provides encryption, authentication, and audit logging capabilities.
"""

from .encryption import (
    EncryptionService,
    KeyManager,
    encrypt_data,
    decrypt_data,
    hash_password,
    verify_password,
)
from .audit import AuditLogger, AuditEvent, AuditEventType
from .auth import AuthenticationManager, AuthProvider, AuthProviderType
from .compliance import ComplianceReporter, ComplianceStandard

__all__ = [
    "EncryptionService",
    "KeyManager",
    "encrypt_data",
    "decrypt_data",
    "hash_password",
    "verify_password",
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuthenticationManager",
    "AuthProvider",
    "AuthProviderType",
    "ComplianceReporter",
    "ComplianceStandard",
]
