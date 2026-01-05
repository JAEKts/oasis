"""
Scan Policy Configuration

Defines scan policies and intensity levels for vulnerability scanning.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ScanIntensity(str, Enum):
    """Scan intensity levels."""

    LIGHT = "light"
    NORMAL = "normal"
    THOROUGH = "thorough"
    AGGRESSIVE = "aggressive"


class RateLimitConfig(BaseModel):
    """Rate limiting configuration for scans."""

    requests_per_second: float = Field(
        default=10.0, description="Maximum requests per second"
    )
    concurrent_requests: int = Field(
        default=5, description="Maximum concurrent requests"
    )
    delay_between_requests_ms: int = Field(
        default=0, description="Delay between requests in milliseconds"
    )


class ScanPolicy(BaseModel):
    """Scan policy configuration."""

    name: str = Field(description="Policy name")
    description: str = Field(default="", description="Policy description")
    enabled_checks: List[str] = Field(
        default_factory=lambda: [
            "sql_injection",
            "xss",
            "csrf",
            "ssrf",
            "xxe",
        ],
        description="List of enabled vulnerability checks",
    )
    scan_intensity: ScanIntensity = Field(
        default=ScanIntensity.NORMAL, description="Scan intensity level"
    )
    rate_limiting: RateLimitConfig = Field(
        default_factory=RateLimitConfig, description="Rate limiting configuration"
    )
    max_depth: int = Field(default=3, description="Maximum crawl depth")
    follow_redirects: bool = Field(
        default=True, description="Whether to follow redirects"
    )
    test_query_params: bool = Field(
        default=True, description="Whether to test query parameters"
    )
    test_post_params: bool = Field(
        default=True, description="Whether to test POST parameters"
    )
    test_headers: bool = Field(default=False, description="Whether to test headers")
    test_cookies: bool = Field(default=True, description="Whether to test cookies")
    custom_payloads: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Custom payloads for specific vulnerability types",
    )
    timeout_seconds: int = Field(default=30, description="Request timeout in seconds")

    @classmethod
    def default_policy(cls) -> "ScanPolicy":
        """Create a default scan policy."""
        return cls(
            name="Default Policy", description="Standard vulnerability scanning policy"
        )

    @classmethod
    def passive_only_policy(cls) -> "ScanPolicy":
        """Create a passive-only scan policy."""
        return cls(
            name="Passive Only",
            description="Passive analysis without active probing",
            enabled_checks=[],
            scan_intensity=ScanIntensity.LIGHT,
        )

    @classmethod
    def aggressive_policy(cls) -> "ScanPolicy":
        """Create an aggressive scan policy."""
        return cls(
            name="Aggressive Scan",
            description="Thorough scanning with all checks enabled",
            enabled_checks=[
                "sql_injection",
                "xss",
                "csrf",
                "ssrf",
                "xxe",
                "idor",
                "security_misconfiguration",
                "sensitive_data_exposure",
            ],
            scan_intensity=ScanIntensity.AGGRESSIVE,
            rate_limiting=RateLimitConfig(
                requests_per_second=20.0,
                concurrent_requests=10,
            ),
            test_headers=True,
        )
