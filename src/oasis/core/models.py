"""
OASIS Core Data Models

Defines the core data structures used throughout the OASIS system.
"""

import uuid
from datetime import datetime, UTC
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, ConfigDict


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Finding confidence levels."""

    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities that can be detected."""

    SQL_INJECTION = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    CSRF = "csrf"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    BROKEN_AUTHENTICATION = "broken_authentication"
    BROKEN_ACCESS_CONTROL = "broken_access_control"


class RequestSource(str, Enum):
    """Source of HTTP requests."""

    PROXY = "proxy"
    REPEATER = "repeater"
    SCANNER = "scanner"
    INTRUDER = "intruder"
    MANUAL = "manual"


class HTTPRequest(BaseModel):
    """HTTP request data model."""

    method: str = Field(description="HTTP method")
    url: str = Field(description="Request URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: Optional[bytes] = Field(default=None, description="Request body")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Request timestamp"
    )
    source: RequestSource = Field(
        default=RequestSource.PROXY, description="Request source"
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        valid_methods = {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "TRACE",
        }
        if v.upper() not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {v}")
        return v.upper()


class HTTPResponse(BaseModel):
    """HTTP response data model."""

    status_code: int = Field(description="HTTP status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: Optional[bytes] = Field(default=None, description="Response body")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Response timestamp"
    )
    duration_ms: int = Field(description="Response time in milliseconds")

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator("status_code")
    @classmethod
    def validate_status_code(cls, v: int) -> int:
        if not (100 <= v <= 599):
            raise ValueError(f"Invalid HTTP status code: {v}")
        return v


class Evidence(BaseModel):
    """Evidence for a security finding."""

    request: Optional[HTTPRequest] = Field(
        default=None, description="Associated request"
    )
    response: Optional[HTTPResponse] = Field(
        default=None, description="Associated response"
    )
    payload: Optional[str] = Field(default=None, description="Attack payload used")
    location: Optional[str] = Field(
        default=None, description="Location of vulnerability"
    )
    proof_of_concept: Optional[str] = Field(
        default=None, description="Proof of concept"
    )
    additional_data: Dict[str, Any] = Field(
        default_factory=dict, description="Additional evidence data"
    )


class Finding(BaseModel):
    """Security finding/vulnerability."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique finding ID")
    vulnerability_type: VulnerabilityType = Field(description="Type of vulnerability")
    severity: Severity = Field(description="Severity level")
    confidence: Confidence = Field(description="Confidence level")
    title: str = Field(description="Finding title")
    description: str = Field(description="Detailed description")
    evidence: Evidence = Field(description="Supporting evidence")
    remediation: str = Field(description="Remediation guidance")
    references: List[str] = Field(
        default_factory=list, description="External references"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Last update timestamp"
    )


class ProjectSettings(BaseModel):
    """Project-specific settings."""

    target_scope: List[str] = Field(
        default_factory=list, description="Target scope patterns"
    )
    excluded_scope: List[str] = Field(
        default_factory=list, description="Excluded scope patterns"
    )
    scan_policy: Optional[str] = Field(default=None, description="Default scan policy")
    rate_limiting: Dict[str, Any] = Field(
        default_factory=dict, description="Rate limiting settings"
    )
    custom_headers: Dict[str, str] = Field(
        default_factory=dict, description="Custom headers to add"
    )


class User(BaseModel):
    """User data model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique user ID")
    username: str = Field(description="Username")
    email: str = Field(description="Email address")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )
    last_login: Optional[datetime] = Field(
        default=None, description="Last login timestamp"
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        import re

        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid email address: {v}")
        return v


class Project(BaseModel):
    """Project data model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique project ID")
    name: str = Field(description="Project name")
    description: str = Field(default="", description="Project description")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )
    settings: ProjectSettings = Field(
        default_factory=ProjectSettings, description="Project settings"
    )
    collaborators: List[User] = Field(
        default_factory=list, description="Project collaborators"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Project name cannot be empty")
        return v.strip()


class FlowMetadata(BaseModel):
    """Metadata for HTTP flows."""

    project_id: Optional[uuid.UUID] = Field(
        default=None, description="Associated project ID"
    )
    tags: List[str] = Field(default_factory=list, description="Flow tags")
    notes: str = Field(default="", description="User notes")
    starred: bool = Field(default=False, description="Whether flow is starred")
    reviewed: bool = Field(default=False, description="Whether flow has been reviewed")


class HTTPFlow(BaseModel):
    """Complete HTTP request-response flow."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique flow ID")
    request: HTTPRequest = Field(description="HTTP request")
    response: Optional[HTTPResponse] = Field(default=None, description="HTTP response")
    metadata: FlowMetadata = Field(
        default_factory=FlowMetadata, description="Flow metadata"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )


# Serialization helpers
def serialize_model(model: BaseModel) -> Dict[str, Any]:
    """Serialize a Pydantic model to a dictionary with proper type handling."""
    return model.model_dump(by_alias=True, exclude_none=False)


def deserialize_model(model_class: type, data: Dict[str, Any]) -> BaseModel:
    """Deserialize a dictionary to a Pydantic model with validation."""
    return model_class(**data)


# Export format support
class ExportFormat(str, Enum):
    """Supported export formats."""

    JSON = "json"
    XML = "xml"
    CSV = "csv"
    PDF = "pdf"


# Traffic filtering models
class FilterAction(str, Enum):
    """Actions for traffic filtering."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class FilterType(str, Enum):
    """Types of traffic filters."""

    HOST = "host"
    PATH = "path"
    FILE_TYPE = "file_type"
    METHOD = "method"
    STATUS_CODE = "status_code"
    CONTENT_TYPE = "content_type"


class TrafficFilter(BaseModel):
    """Traffic filter rule."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique filter ID")
    name: str = Field(description="Filter name")
    filter_type: FilterType = Field(description="Type of filter")
    action: FilterAction = Field(description="Filter action")
    pattern: str = Field(description="Pattern to match")
    case_sensitive: bool = Field(
        default=False, description="Whether pattern matching is case sensitive"
    )
    regex: bool = Field(
        default=False, description="Whether pattern is a regular expression"
    )
    enabled: bool = Field(default=True, description="Whether filter is enabled")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Filter pattern cannot be empty")
        return v.strip()


class FilterSet(BaseModel):
    """Collection of traffic filters."""

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique filter set ID"
    )
    name: str = Field(description="Filter set name")
    description: str = Field(default="", description="Filter set description")
    filters: List[TrafficFilter] = Field(
        default_factory=list, description="List of filters"
    )
    default_action: FilterAction = Field(
        default=FilterAction.INCLUDE, description="Default action when no filters match"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Filter set name cannot be empty")
        return v.strip()


# Additional model configurations for better JSON schema generation
HTTPRequest.model_rebuild()
HTTPResponse.model_rebuild()
Evidence.model_rebuild()
Finding.model_rebuild()
Project.model_rebuild()
HTTPFlow.model_rebuild()
TrafficFilter.model_rebuild()
FilterSet.model_rebuild()
