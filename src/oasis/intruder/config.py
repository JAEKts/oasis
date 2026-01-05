"""
Attack Configuration Models

Defines attack types, injection points, and payload processing configurations.
"""

import uuid
from enum import Enum
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime, UTC
from pydantic import BaseModel, Field, field_validator

from ..core.models import HTTPRequest


class AttackType(str, Enum):
    """
    Types of attacks supported by the intruder engine.

    - SNIPER: Single payload set, one injection point at a time
    - BATTERING_RAM: Single payload set, all injection points simultaneously with same payload
    - PITCHFORK: Multiple payload sets, synchronized iteration (one-to-one)
    - CLUSTER_BOMB: Multiple payload sets, all combinations (cartesian product)
    """

    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


class InjectionPoint(BaseModel):
    """
    Defines a location in the HTTP request where payloads will be injected.
    """

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique injection point ID"
    )
    name: str = Field(description="Human-readable name for this injection point")
    location: str = Field(
        description="Location type: header, param, body, path, cookie"
    )
    key: Optional[str] = Field(
        default=None, description="Key/name for the parameter or header"
    )
    marker: str = Field(
        description="Marker string in the request template (e.g., §payload§)"
    )

    @field_validator("location")
    @classmethod
    def validate_location(cls, v: str) -> str:
        valid_locations = {"header", "param", "body", "path", "cookie", "url"}
        if v.lower() not in valid_locations:
            raise ValueError(f"Invalid location: {v}. Must be one of {valid_locations}")
        return v.lower()

    @field_validator("marker")
    @classmethod
    def validate_marker(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Marker cannot be empty")
        return v


class ProcessorType(str, Enum):
    """Types of payload processors."""

    URL_ENCODE = "url_encode"
    URL_DECODE = "url_decode"
    BASE64_ENCODE = "base64_encode"
    BASE64_DECODE = "base64_decode"
    HTML_ENCODE = "html_encode"
    HTML_DECODE = "html_decode"
    HEX_ENCODE = "hex_encode"
    HEX_DECODE = "hex_decode"
    MD5_HASH = "md5_hash"
    SHA1_HASH = "sha1_hash"
    SHA256_HASH = "sha256_hash"
    UPPERCASE = "uppercase"
    LOWERCASE = "lowercase"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    REPLACE = "replace"
    CUSTOM = "custom"


class PayloadProcessor(BaseModel):
    """
    Processes payloads before injection (encoding, hashing, transformation).
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique processor ID")
    name: str = Field(description="Processor name")
    processor_type: ProcessorType = Field(description="Type of processing to apply")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Processor-specific parameters"
    )
    enabled: bool = Field(default=True, description="Whether processor is enabled")

    def process(self, payload: str) -> str:
        """
        Process a payload according to the processor type.

        Args:
            payload: Input payload string

        Returns:
            Processed payload string
        """
        if not self.enabled:
            return payload

        import urllib.parse
        import base64
        import html
        import hashlib

        if self.processor_type == ProcessorType.URL_ENCODE:
            return urllib.parse.quote(payload, safe="")

        elif self.processor_type == ProcessorType.URL_DECODE:
            return urllib.parse.unquote(payload)

        elif self.processor_type == ProcessorType.BASE64_ENCODE:
            return base64.b64encode(payload.encode()).decode()

        elif self.processor_type == ProcessorType.BASE64_DECODE:
            try:
                return base64.b64decode(payload).decode()
            except Exception:
                return payload

        elif self.processor_type == ProcessorType.HTML_ENCODE:
            return html.escape(payload)

        elif self.processor_type == ProcessorType.HTML_DECODE:
            return html.unescape(payload)

        elif self.processor_type == ProcessorType.HEX_ENCODE:
            return payload.encode().hex()

        elif self.processor_type == ProcessorType.HEX_DECODE:
            try:
                return bytes.fromhex(payload).decode()
            except Exception:
                return payload

        elif self.processor_type == ProcessorType.MD5_HASH:
            return hashlib.md5(payload.encode()).hexdigest()

        elif self.processor_type == ProcessorType.SHA1_HASH:
            return hashlib.sha1(payload.encode()).hexdigest()

        elif self.processor_type == ProcessorType.SHA256_HASH:
            return hashlib.sha256(payload.encode()).hexdigest()

        elif self.processor_type == ProcessorType.UPPERCASE:
            return payload.upper()

        elif self.processor_type == ProcessorType.LOWERCASE:
            return payload.lower()

        elif self.processor_type == ProcessorType.PREFIX:
            prefix = self.parameters.get("prefix", "")
            return f"{prefix}{payload}"

        elif self.processor_type == ProcessorType.SUFFIX:
            suffix = self.parameters.get("suffix", "")
            return f"{payload}{suffix}"

        elif self.processor_type == ProcessorType.REPLACE:
            old = self.parameters.get("old", "")
            new = self.parameters.get("new", "")
            return payload.replace(old, new)

        elif self.processor_type == ProcessorType.CUSTOM:
            # Custom processor would use a user-provided function
            # For now, return payload unchanged
            return payload

        return payload


class PayloadSet(BaseModel):
    """
    A set of payloads to be used in an attack.
    """

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique payload set ID"
    )
    name: str = Field(description="Payload set name")
    description: str = Field(default="", description="Description of the payload set")
    generator_type: str = Field(
        description="Type of generator: wordlist, numbers, charset, custom"
    )
    generator_config: Dict[str, Any] = Field(
        default_factory=dict, description="Generator configuration"
    )
    processors: List[PayloadProcessor] = Field(
        default_factory=list, description="Payload processors to apply"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Payload set name cannot be empty")
        return v.strip()

    @field_validator("generator_type")
    @classmethod
    def validate_generator_type(cls, v: str) -> str:
        valid_types = {"wordlist", "numbers", "charset", "custom", "runtime"}
        if v.lower() not in valid_types:
            raise ValueError(
                f"Invalid generator type: {v}. Must be one of {valid_types}"
            )
        return v.lower()


class RateLimitConfig(BaseModel):
    """Rate limiting configuration for attacks."""

    requests_per_second: Optional[float] = Field(
        default=None, description="Maximum requests per second"
    )
    delay_ms: int = Field(
        default=0, description="Delay between requests in milliseconds"
    )
    concurrent_requests: int = Field(
        default=10, description="Maximum concurrent requests"
    )

    @field_validator("concurrent_requests")
    @classmethod
    def validate_concurrent_requests(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Concurrent requests must be at least 1")
        if v > 100:
            raise ValueError("Concurrent requests cannot exceed 100")
        return v

    @field_validator("delay_ms")
    @classmethod
    def validate_delay_ms(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Delay cannot be negative")
        return v


class AttackConfig(BaseModel):
    """
    Complete configuration for an intruder attack.
    """

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique attack config ID"
    )
    name: str = Field(description="Attack configuration name")
    description: str = Field(default="", description="Attack description")
    attack_type: AttackType = Field(description="Type of attack to perform")
    base_request: HTTPRequest = Field(description="Base HTTP request template")
    injection_points: List[InjectionPoint] = Field(
        description="Injection points in the request"
    )
    payload_sets: List[PayloadSet] = Field(description="Payload sets to use")
    rate_limiting: RateLimitConfig = Field(
        default_factory=RateLimitConfig, description="Rate limiting config"
    )
    follow_redirects: bool = Field(
        default=False, description="Whether to follow HTTP redirects"
    )
    timeout_seconds: int = Field(default=30, description="Request timeout in seconds")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Attack name cannot be empty")
        return v.strip()

    @field_validator("injection_points")
    @classmethod
    def validate_injection_points(cls, v: List[InjectionPoint]) -> List[InjectionPoint]:
        if not v:
            raise ValueError("At least one injection point is required")
        return v

    @field_validator("payload_sets")
    @classmethod
    def validate_payload_sets(cls, v: List[PayloadSet]) -> List[PayloadSet]:
        if not v:
            raise ValueError("At least one payload set is required")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Timeout must be at least 1 second")
        if v > 300:
            raise ValueError("Timeout cannot exceed 300 seconds")
        return v

    def validate_attack_configuration(self) -> None:
        """
        Validate that the attack configuration is consistent.

        Raises:
            ValueError: If configuration is invalid
        """
        # For SNIPER, only one payload set is allowed
        if self.attack_type == AttackType.SNIPER and len(self.payload_sets) != 1:
            raise ValueError("SNIPER attack requires exactly one payload set")

        # For BATTERING_RAM, only one payload set is allowed
        if self.attack_type == AttackType.BATTERING_RAM and len(self.payload_sets) != 1:
            raise ValueError("BATTERING_RAM attack requires exactly one payload set")

        # For PITCHFORK, number of payload sets must match number of injection points
        if self.attack_type == AttackType.PITCHFORK:
            if len(self.payload_sets) != len(self.injection_points):
                raise ValueError(
                    f"PITCHFORK attack requires equal number of payload sets ({len(self.payload_sets)}) "
                    f"and injection points ({len(self.injection_points)})"
                )

        # For CLUSTER_BOMB, number of payload sets must match number of injection points
        if self.attack_type == AttackType.CLUSTER_BOMB:
            if len(self.payload_sets) != len(self.injection_points):
                raise ValueError(
                    f"CLUSTER_BOMB attack requires equal number of payload sets ({len(self.payload_sets)}) "
                    f"and injection points ({len(self.injection_points)})"
                )
