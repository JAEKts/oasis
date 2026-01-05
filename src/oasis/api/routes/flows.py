"""
HTTP flow API routes.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from ...core.models import HTTPFlow, HTTPRequest, HTTPResponse, FlowMetadata
from ...storage.vault import VaultStorage


router = APIRouter()


# Dependency
def get_vault() -> VaultStorage:
    """Get vault storage instance."""
    from pathlib import Path

    return VaultStorage(Path("./data/vault"))


class FlowResponse(BaseModel):
    """Response model for HTTP flow."""

    id: UUID
    request: HTTPRequest
    response: HTTPResponse | None
    metadata: FlowMetadata
    created_at: str


@router.get("/{project_id}/flows", response_model=List[FlowResponse])
async def list_flows(
    project_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    vault: VaultStorage = Depends(get_vault),
):
    """
    List HTTP flows for a project.

    Returns captured HTTP request/response flows for the specified project.

    **Parameters:**
    - **project_id**: UUID of the project
    - **limit**: Maximum number of flows to return (1-1000, default 100)
    - **offset**: Number of flows to skip (for pagination)

    **Returns:**
    - List of HTTP flows with request, response, and metadata

    **Example Response:**
    ```json
    [
        {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "request": {
                "method": "GET",
                "url": "https://example.com/api/users",
                "headers": {"Host": "example.com"},
                "body": null
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "...",
                "duration_ms": 45
            },
            "metadata": {
                "tags": ["api"],
                "starred": false
            }
        }
    ]
    ```
    """
    flows = vault.get_flows(project_id)

    # Apply pagination
    paginated_flows = flows[offset : offset + limit]

    return [
        FlowResponse(
            id=flow.id,
            request=flow.request,
            response=flow.response,
            metadata=flow.metadata,
            created_at=flow.created_at.isoformat(),
        )
        for flow in paginated_flows
    ]


@router.get("/{project_id}/flows/{flow_id}", response_model=FlowResponse)
async def get_flow(
    project_id: UUID, flow_id: UUID, vault: VaultStorage = Depends(get_vault)
):
    """
    Get specific HTTP flow.

    Retrieves detailed information about a specific HTTP flow.

    **Parameters:**
    - **project_id**: UUID of the project
    - **flow_id**: UUID of the flow

    **Returns:**
    - Complete HTTP flow with request, response, and metadata

    **Errors:**
    - 404: Flow not found
    """
    flow = vault.get_flow(project_id, flow_id)

    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")

    return FlowResponse(
        id=flow.id,
        request=flow.request,
        response=flow.response,
        metadata=flow.metadata,
        created_at=flow.created_at.isoformat(),
    )


@router.post("/{project_id}/flows", response_model=FlowResponse, status_code=201)
async def create_flow(
    project_id: UUID, flow: HTTPFlow, vault: VaultStorage = Depends(get_vault)
):
    """
    Create a new HTTP flow.

    Stores a new HTTP request/response flow in the project.

    **Parameters:**
    - **project_id**: UUID of the project
    - **flow**: Complete HTTP flow data

    **Returns:**
    - Created flow with generated ID
    """
    flow_id = vault.store_flow(project_id, flow)
    stored_flow = vault.get_flow(project_id, flow_id)

    if not stored_flow:
        raise HTTPException(status_code=500, detail="Failed to create flow")

    return FlowResponse(
        id=stored_flow.id,
        request=stored_flow.request,
        response=stored_flow.response,
        metadata=stored_flow.metadata,
        created_at=stored_flow.created_at.isoformat(),
    )
