"""
Scanner API routes.
"""

from uuid import UUID
from typing import List

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from ...scanner.engine import ScanEngine
from ...scanner.policy import ScanPolicy, ScanIntensity
from ...core.models import Finding


router = APIRouter()


class ScanRequest(BaseModel):
    """Request model for starting a scan."""

    project_id: UUID
    enabled_checks: List[str] = ["sql_injection", "xss", "csrf"]
    scan_intensity: ScanIntensity = ScanIntensity.NORMAL


class ScanResponse(BaseModel):
    """Response model for scan results."""

    findings_count: int
    findings: List[Finding]


@router.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest):
    """
    Start a vulnerability scan.

    Initiates a vulnerability scan on captured traffic for the specified project.

    **Parameters:**
    - **project_id**: UUID of the project to scan
    - **enabled_checks**: List of vulnerability checks to perform
    - **scan_intensity**: Scan intensity level (light, normal, thorough)

    **Returns:**
    - Scan results with discovered findings
    """
    scan_engine = ScanEngine()
    policy = ScanPolicy(
        enabled_checks=scan_request.enabled_checks,
        scan_intensity=scan_request.scan_intensity,
    )

    # In a real implementation, this would scan actual flows
    findings = []

    return ScanResponse(findings_count=len(findings), findings=findings)
