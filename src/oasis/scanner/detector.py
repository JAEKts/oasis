"""
Base Vulnerability Detector

Provides the base class and context for vulnerability detection.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from ..core.models import HTTPFlow, Finding, HTTPRequest, HTTPResponse


@dataclass
class ScanContext:
    """Context information for vulnerability detection."""

    flow: HTTPFlow
    policy: Any  # ScanPolicy - avoid circular import
    project_id: Optional[str] = None
    scan_session_id: Optional[str] = None
    additional_data: Dict[str, Any] = None

    def __post_init__(self):
        if self.additional_data is None:
            self.additional_data = {}


class VulnerabilityDetector(ABC):
    """Base class for vulnerability detectors."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    async def detect(self, context: ScanContext) -> List[Finding]:
        """
        Detect vulnerabilities in the given context.

        Args:
            context: Scan context containing flow and policy information

        Returns:
            List of findings detected
        """
        pass

    def is_enabled(self, policy: Any) -> bool:
        """Check if this detector is enabled in the given policy."""
        return self.name in policy.enabled_checks

    async def analyze(self, context: ScanContext) -> List[Finding]:
        """
        Analyze the context and return findings if detector is enabled.

        Args:
            context: Scan context

        Returns:
            List of findings, or empty list if detector is disabled
        """
        if not self.is_enabled(context.policy):
            return []

        return await self.detect(context)
