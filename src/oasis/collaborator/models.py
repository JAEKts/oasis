"""
Collaborator Service Data Models

Defines data structures for out-of-band interaction detection.
"""

import uuid
from datetime import datetime, UTC
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Protocol(str, Enum):
    """Supported interaction protocols."""

    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    LDAP = "ldap"


class PayloadType(str, Enum):
    """Types of collaborator payloads."""

    DNS_LOOKUP = "dns_lookup"
    HTTP_REQUEST = "http_request"
    SMTP_CONNECTION = "smtp_connection"
    LDAP_QUERY = "ldap_query"


class CollaboratorPayload(BaseModel):
    """Collaborator payload for out-of-band testing."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique payload ID")
    payload_type: PayloadType = Field(description="Type of payload")
    subdomain: str = Field(description="Unique subdomain for this payload")
    full_domain: str = Field(description="Full domain including base domain")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional payload metadata"
    )

    def get_dns_payload(self) -> str:
        """Get DNS lookup payload."""
        return self.full_domain

    def get_http_payload(self, protocol: str = "http") -> str:
        """Get HTTP request payload."""
        return f"{protocol}://{self.full_domain}"


class DNSQuery(BaseModel):
    """DNS query interaction."""

    query_name: str = Field(description="DNS query name")
    query_type: str = Field(description="DNS query type (A, AAAA, MX, TXT, etc.)")
    source_ip: str = Field(description="Source IP address")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Query timestamp"
    )
    raw_data: Optional[str] = Field(default=None, description="Raw DNS query data")


class SMTPMessage(BaseModel):
    """SMTP message interaction."""

    from_address: str = Field(description="Sender email address")
    to_address: str = Field(description="Recipient email address")
    subject: Optional[str] = Field(default=None, description="Email subject")
    body: Optional[str] = Field(default=None, description="Email body")
    source_ip: str = Field(description="Source IP address")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Message timestamp"
    )
    raw_data: Optional[str] = Field(default=None, description="Raw SMTP data")


class Interaction(BaseModel):
    """Out-of-band interaction record."""

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique interaction ID"
    )
    payload_id: uuid.UUID = Field(description="Associated payload ID")
    protocol: Protocol = Field(description="Interaction protocol")
    source_ip: str = Field(description="Source IP address")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Interaction timestamp"
    )

    # Protocol-specific data
    dns_query: Optional[DNSQuery] = Field(default=None, description="DNS query data")
    http_request: Optional[Dict[str, Any]] = Field(
        default=None, description="HTTP request data"
    )
    smtp_message: Optional[SMTPMessage] = Field(
        default=None, description="SMTP message data"
    )

    # Forensic information
    user_agent: Optional[str] = Field(default=None, description="User agent string")
    headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    raw_data: Optional[str] = Field(default=None, description="Raw interaction data")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )
