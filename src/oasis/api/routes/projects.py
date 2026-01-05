"""
Project management API routes.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from ...core.models import Project, ProjectSettings
from ...storage.vault import VaultStorage


router = APIRouter()


# Request/Response models
class ProjectCreate(BaseModel):
    """Request model for creating a project."""

    name: str
    description: str = ""
    settings: ProjectSettings = ProjectSettings()


class ProjectUpdate(BaseModel):
    """Request model for updating a project."""

    name: str | None = None
    description: str | None = None
    settings: ProjectSettings | None = None


class ProjectResponse(BaseModel):
    """Response model for project data."""

    id: UUID
    name: str
    description: str
    created_at: str
    settings: ProjectSettings


# Dependency to get vault storage
def get_vault() -> VaultStorage:
    """Get vault storage instance."""
    # In production, this would be properly configured
    from pathlib import Path

    return VaultStorage(Path("./data/vault"))


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(
    project_data: ProjectCreate, vault: VaultStorage = Depends(get_vault)
):
    """
    Create a new project.

    Creates a new penetration testing project with the specified settings.

    **Parameters:**
    - **name**: Project name (required)
    - **description**: Project description (optional)
    - **settings**: Project settings including scope and configuration

    **Returns:**
    - Created project with generated ID

    **Example:**
    ```json
    {
        "name": "Web App Pentest",
        "description": "Security assessment of example.com",
        "settings": {
            "target_scope": ["https://example.com/*"],
            "excluded_scope": ["https://example.com/admin/*"]
        }
    }
    ```
    """
    project = Project(
        name=project_data.name,
        description=project_data.description,
        settings=project_data.settings,
    )

    project_id = vault.create_project(project)
    created_project = vault.get_project(project_id)

    if not created_project:
        raise HTTPException(status_code=500, detail="Failed to create project")

    return ProjectResponse(
        id=created_project.id,
        name=created_project.name,
        description=created_project.description,
        created_at=created_project.created_at.isoformat(),
        settings=created_project.settings,
    )


@router.get("/", response_model=List[ProjectResponse])
async def list_projects(vault: VaultStorage = Depends(get_vault)):
    """
    List all projects.

    Returns a list of all penetration testing projects.

    **Returns:**
    - List of projects with basic information
    """
    projects = vault.list_projects()

    return [
        ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            created_at=p.created_at.isoformat(),
            settings=p.settings,
        )
        for p in projects
    ]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: UUID, vault: VaultStorage = Depends(get_vault)):
    """
    Get project by ID.

    Retrieves detailed information about a specific project.

    **Parameters:**
    - **project_id**: UUID of the project

    **Returns:**
    - Project details

    **Errors:**
    - 404: Project not found
    """
    project = vault.get_project(project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at.isoformat(),
        settings=project.settings,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID,
    project_data: ProjectUpdate,
    vault: VaultStorage = Depends(get_vault),
):
    """
    Update project.

    Updates project information and settings.

    **Parameters:**
    - **project_id**: UUID of the project
    - **name**: New project name (optional)
    - **description**: New description (optional)
    - **settings**: New settings (optional)

    **Returns:**
    - Updated project details

    **Errors:**
    - 404: Project not found
    """
    project = vault.get_project(project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Update fields if provided
    if project_data.name is not None:
        project.name = project_data.name
    if project_data.description is not None:
        project.description = project_data.description
    if project_data.settings is not None:
        project.settings = project_data.settings

    # Update in vault
    if hasattr(vault, "update_project"):
        vault.update_project(project)

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at.isoformat(),
        settings=project.settings,
    )


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: UUID, vault: VaultStorage = Depends(get_vault)):
    """
    Delete project.

    Permanently deletes a project and all associated data.

    **Parameters:**
    - **project_id**: UUID of the project

    **Errors:**
    - 404: Project not found

    **Warning:**
    This operation cannot be undone. All flows, findings, and project data will be permanently deleted.
    """
    project = vault.get_project(project_id)

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if hasattr(vault, "delete_project"):
        vault.delete_project(project_id)
    else:
        raise HTTPException(status_code=501, detail="Delete operation not implemented")

    return None
