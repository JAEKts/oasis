"""
OASIS Collaborator Service

Out-of-band application security testing (OAST) service for detecting blind vulnerabilities.
"""

from .service import CollaboratorService
from .models import (
    CollaboratorPayload,
    Interaction,
    PayloadType,
    Protocol,
    DNSQuery,
    SMTPMessage,
)
from .notifications import InteractionNotifier, InteractionLogger
from .forensics import ForensicAnalyzer

__all__ = [
    "CollaboratorService",
    "CollaboratorPayload",
    "Interaction",
    "PayloadType",
    "Protocol",
    "DNSQuery",
    "SMTPMessage",
    "InteractionNotifier",
    "InteractionLogger",
    "ForensicAnalyzer",
]
