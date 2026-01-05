"""
Scan Engine

Core scanning engine that orchestrates vulnerability detection.
"""

import uuid
import asyncio
from datetime import datetime, UTC
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from ..core.models import HTTPFlow, Finding
from ..core.exceptions import ScanError
from .policy import ScanPolicy
from .detector import VulnerabilityDetector, ScanContext
from .passive import PassiveScanner
from .active import ActiveScanner


class ScanStatus(str, Enum):
    """Scan session status."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTarget(BaseModel):
    """Scan target configuration."""

    base_url: str = Field(description="Base URL to scan")
    scope_patterns: List[str] = Field(
        default_factory=list, description="URL patterns in scope"
    )
    excluded_patterns: List[str] = Field(
        default_factory=list, description="URL patterns to exclude"
    )

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in scope."""
        import re

        # If no scope patterns, everything is in scope
        if not self.scope_patterns:
            return True

        # Check if URL matches any scope pattern
        for pattern in self.scope_patterns:
            if re.search(pattern, url):
                # Check if it's excluded
                for excluded in self.excluded_patterns:
                    if re.search(excluded, url):
                        return False
                return True

        return False


class ScanStatistics(BaseModel):
    """Statistics for a scan session."""

    total_requests: int = Field(default=0, description="Total requests made")
    total_findings: int = Field(default=0, description="Total findings discovered")
    findings_by_severity: Dict[str, int] = Field(
        default_factory=dict, description="Findings grouped by severity"
    )
    start_time: Optional[datetime] = Field(default=None, description="Scan start time")
    end_time: Optional[datetime] = Field(default=None, description="Scan end time")
    duration_seconds: float = Field(default=0.0, description="Scan duration in seconds")


class ScanSession(BaseModel):
    """Scan session tracking."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique session ID")
    project_id: Optional[uuid.UUID] = Field(
        default=None, description="Associated project ID"
    )
    target: ScanTarget = Field(description="Scan target")
    policy: ScanPolicy = Field(description="Scan policy")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Scan status")
    findings: List[Finding] = Field(
        default_factory=list, description="Discovered findings"
    )
    statistics: ScanStatistics = Field(
        default_factory=ScanStatistics, description="Scan statistics"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Last update timestamp"
    )
    error_message: Optional[str] = Field(
        default=None, description="Error message if scan failed"
    )


class ScanEngine:
    """
    Core scanning engine that orchestrates vulnerability detection.

    Supports both passive analysis of intercepted traffic and active probing.
    """

    def __init__(self):
        self.passive_scanner = PassiveScanner()
        self.active_scanner = ActiveScanner()
        self._active_sessions: Dict[uuid.UUID, ScanSession] = {}

    async def start_scan(
        self,
        target: ScanTarget,
        policy: ScanPolicy,
        project_id: Optional[uuid.UUID] = None,
    ) -> ScanSession:
        """
        Start a new scan session.

        Args:
            target: Scan target configuration
            policy: Scan policy to use
            project_id: Optional project ID to associate with scan

        Returns:
            ScanSession object tracking the scan

        Raises:
            ScanError: If scan cannot be started
        """
        # Create scan session
        session = ScanSession(
            project_id=project_id,
            target=target,
            policy=policy,
            status=ScanStatus.RUNNING,
        )

        # Update statistics
        session.statistics.start_time = datetime.now(UTC)

        # Store active session
        self._active_sessions[session.id] = session

        try:
            # Run the scan
            await self._execute_scan(session)

            # Mark as completed
            session.status = ScanStatus.COMPLETED
            session.statistics.end_time = datetime.now(UTC)

            if session.statistics.start_time:
                duration = session.statistics.end_time - session.statistics.start_time
                session.statistics.duration_seconds = duration.total_seconds()

        except Exception as e:
            session.status = ScanStatus.FAILED
            session.error_message = str(e)
            raise ScanError(f"Scan failed: {e}", {"session_id": str(session.id)})

        finally:
            session.updated_at = datetime.now(UTC)

        return session

    async def passive_scan(
        self, flows: List[HTTPFlow], policy: Optional[ScanPolicy] = None
    ) -> List[Finding]:
        """
        Perform passive analysis on intercepted HTTP traffic.

        Args:
            flows: List of HTTP flows to analyze
            policy: Optional scan policy (uses default if not provided)

        Returns:
            List of findings from passive analysis
        """
        if policy is None:
            policy = ScanPolicy.passive_only_policy()

        findings = []

        for flow in flows:
            context = ScanContext(flow=flow, policy=policy)
            flow_findings = await self.passive_scanner.analyze_flow(context)
            findings.extend(flow_findings)

        return findings

    async def active_scan(
        self, flows: List[HTTPFlow], policy: ScanPolicy, target: ScanTarget
    ) -> List[Finding]:
        """
        Perform active probing on HTTP flows.

        Args:
            flows: List of HTTP flows to use as basis for active probing
            policy: Scan policy
            target: Scan target for scope checking

        Returns:
            List of findings from active probing
        """
        findings = []

        for flow in flows:
            # Check if flow is in scope
            if not target.is_in_scope(flow.request.url):
                continue

            context = ScanContext(flow=flow, policy=policy)
            flow_findings = await self.active_scanner.probe_flow(context)
            findings.extend(flow_findings)

        return findings

    async def _execute_scan(self, session: ScanSession) -> None:
        """Execute the scan session."""
        # This is a placeholder for the full scan execution
        # In a complete implementation, this would:
        # 1. Crawl the target
        # 2. Collect HTTP flows
        # 3. Run passive analysis
        # 4. Run active probing
        # 5. Aggregate findings

        # For now, we'll just initialize the statistics
        session.statistics.total_requests = 0
        session.statistics.total_findings = 0
        session.statistics.findings_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def get_session(self, session_id: uuid.UUID) -> Optional[ScanSession]:
        """Get a scan session by ID."""
        return self._active_sessions.get(session_id)

    def list_sessions(self) -> List[ScanSession]:
        """List all active scan sessions."""
        return list(self._active_sessions.values())

    async def cancel_scan(self, session_id: uuid.UUID) -> bool:
        """
        Cancel a running scan session.

        Args:
            session_id: ID of session to cancel

        Returns:
            True if cancelled, False if session not found or not running
        """
        session = self._active_sessions.get(session_id)
        if session and session.status == ScanStatus.RUNNING:
            session.status = ScanStatus.CANCELLED
            session.updated_at = datetime.now(UTC)
            return True
        return False
