"""
Vulnerability findings API routes.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from ...core.models import Finding, Severity, VulnerabilityType
from ...storage.vault import VaultStorage


router = APIRouter()


def get_vault() -> VaultStorage:
    from pathlib import Path

    return VaultStorage(Path("./data/vault"))


class FindingResponse(BaseModel):
    """Response model for findings."""

    id: UUID
    vulnerability_type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    created_at: str


@router.get("/{project_id}/findings", response_model=List[FindingResponse])
async def list_findings(
    project_id: UUID,
    severity: Severity | None = None,
    limit: int = Query(100, ge=1, le=1000),
    vault: VaultStorage = Depends(get_vault),
):
    """List vulnerability findings for a project."""
    findings = vault.get_findings(project_id)

    # Filter by severity if specified
    if severity:
        findings = [f for f in findings if f.severity == severity]

    # Apply limit
    findings = findings[:limit]

    return [
        FindingResponse(
            id=f.id,
            vulnerability_type=f.vulnerability_type,
            severity=f.severity,
            title=f.title,
            description=f.description,
            created_at=f.created_at.isoformat(),
        )
        for f in findings
    ]


@router.get("/{project_id}/findings/{finding_id}", response_model=Finding)
async def get_finding(
    project_id: UUID, finding_id: UUID, vault: VaultStorage = Depends(get_vault)
):
    """Get specific vulnerability finding."""
    finding = vault.get_finding(project_id, finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding
