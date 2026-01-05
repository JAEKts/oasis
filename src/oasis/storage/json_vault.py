"""
OASIS JSON Vault Storage System (Legacy)

Provides hierarchical project-based storage with JSON files.
"""

import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.config import get_config, get_vault_path
from ..core.exceptions import StorageError
from ..core.logging import get_logger
from ..core.models import HTTPFlow, Project, ProjectSettings, User

logger = get_logger(__name__)


class JSONVaultStorage:
    """
    JSON-based vault storage system for managing projects and data with hierarchical organization.

    Provides:
    - Project-based data organization
    - Version control and change tracking
    - Automatic backup and recovery
    - Efficient data serialization
    """

    def __init__(self, base_path: Optional[Path] = None) -> None:
        """
        Initialize vault storage.

        Args:
            base_path: Base directory for vault storage (uses config if None)
        """
        if base_path:
            self.base_path = base_path
        else:
            try:
                self.base_path = get_vault_path()
            except Exception:
                # Fallback if config is not available
                self.base_path = Path.home() / ".oasis" / "vault"

        try:
            self.config = get_config()
        except Exception:
            # Fallback config if not available
            self.config = None

        # Ensure vault directory structure exists
        self._initialize_vault()

    def _initialize_vault(self) -> None:
        """Initialize vault directory structure."""
        try:
            # Create main directories
            (self.base_path / "projects").mkdir(parents=True, exist_ok=True)
            (self.base_path / "backups").mkdir(parents=True, exist_ok=True)
            (self.base_path / "temp").mkdir(parents=True, exist_ok=True)

            # Create vault metadata file if it doesn't exist
            vault_meta_path = self.base_path / "vault.json"
            if not vault_meta_path.exists():
                vault_meta = {
                    "version": "1.0",
                    "created_at": datetime.utcnow().isoformat(),
                    "last_backup": None,
                    "projects": {},
                }
                self._write_json(vault_meta_path, vault_meta)

            logger.info(f"Vault initialized at {self.base_path}")

        except Exception as e:
            raise StorageError(f"Failed to initialize vault: {e}")

    def _write_json(self, path: Path, data: Any) -> None:
        """Write data to JSON file with error handling."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        except Exception as e:
            raise StorageError(f"Failed to write JSON to {path}: {e}")

    def _read_json(self, path: Path) -> Any:
        """Read data from JSON file with error handling."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            raise StorageError(f"File not found: {path}")
        except json.JSONDecodeError as e:
            raise StorageError(f"Invalid JSON in {path}: {e}")
        except Exception as e:
            raise StorageError(f"Failed to read JSON from {path}: {e}")

    def create_project(
        self,
        name: str,
        description: str = "",
        settings: Optional[ProjectSettings] = None,
    ) -> Project:
        """
        Create a new project.

        Args:
            name: Project name
            description: Project description
            settings: Project settings (uses defaults if None)

        Returns:
            Created project instance

        Raises:
            StorageError: If project creation fails
        """
        try:
            project = Project(
                name=name,
                description=description,
                settings=settings or ProjectSettings(),
            )

            # Create project directory structure
            project_path = self.base_path / "projects" / str(project.id)
            project_path.mkdir(parents=True, exist_ok=True)

            # Create subdirectories
            (project_path / "flows").mkdir(exist_ok=True)
            (project_path / "findings").mkdir(exist_ok=True)
            (project_path / "sessions").mkdir(exist_ok=True)
            (project_path / "exports").mkdir(exist_ok=True)

            # Save project metadata
            project_data = project.model_dump()
            self._write_json(project_path / "project.json", project_data)

            # Update vault metadata
            vault_meta_path = self.base_path / "vault.json"
            vault_meta = self._read_json(vault_meta_path)
            vault_meta["projects"][str(project.id)] = {
                "name": name,
                "created_at": project.created_at.isoformat(),
                "path": str(project_path.relative_to(self.base_path)),
            }
            self._write_json(vault_meta_path, vault_meta)

            logger.info(f"Created project: {name} ({project.id})")
            return project

        except Exception as e:
            raise StorageError(f"Failed to create project '{name}': {e}")

    def get_project(self, project_id: Union[str, uuid.UUID]) -> Optional[Project]:
        """
        Get project by ID.

        Args:
            project_id: Project ID

        Returns:
            Project instance or None if not found
        """
        try:
            project_path = self.base_path / "projects" / str(project_id)
            if not project_path.exists():
                return None

            project_data = self._read_json(project_path / "project.json")
            return Project(**project_data)

        except Exception as e:
            logger.error(f"Failed to get project {project_id}: {e}")
            return None

    def list_projects(self) -> List[Project]:
        """
        List all projects in the vault.

        Returns:
            List of project instances
        """
        projects = []
        try:
            vault_meta = self._read_json(self.base_path / "vault.json")

            for project_id in vault_meta.get("projects", {}):
                project = self.get_project(project_id)
                if project:
                    projects.append(project)

        except Exception as e:
            logger.error(f"Failed to list projects: {e}")

        return projects

    def update_project(self, project: Project) -> bool:
        """
        Update an existing project.

        Args:
            project: Updated project instance

        Returns:
            True if successful, False otherwise
        """
        try:
            project_path = self.base_path / "projects" / str(project.id)
            if not project_path.exists():
                raise StorageError(f"Project {project.id} not found")

            # Save updated project data
            project_data = project.model_dump()
            self._write_json(project_path / "project.json", project_data)

            logger.info(f"Updated project: {project.name} ({project.id})")
            return True

        except Exception as e:
            logger.error(f"Failed to update project {project.id}: {e}")
            return False

    def delete_project(self, project_id: Union[str, uuid.UUID]) -> bool:
        """
        Delete a project and all its data.

        Args:
            project_id: Project ID

        Returns:
            True if successful, False otherwise
        """
        try:
            project_path = self.base_path / "projects" / str(project_id)
            if not project_path.exists():
                return False

            # Create backup before deletion if enabled
            if (
                self.config
                and hasattr(self.config, "vault")
                and self.config.vault.backup_enabled
            ):
                self._backup_project(project_id)

            # Remove project directory
            shutil.rmtree(project_path)

            # Update vault metadata
            vault_meta_path = self.base_path / "vault.json"
            vault_meta = self._read_json(vault_meta_path)
            vault_meta["projects"].pop(str(project_id), None)
            self._write_json(vault_meta_path, vault_meta)

            logger.info(f"Deleted project: {project_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete project {project_id}: {e}")
            return False

    def store_flow(self, project_id: Union[str, uuid.UUID], flow: HTTPFlow) -> bool:
        """
        Store an HTTP flow in a project.

        Args:
            project_id: Project ID
            flow: HTTP flow to store

        Returns:
            True if successful, False otherwise
        """
        try:
            project_path = self.base_path / "projects" / str(project_id)
            if not project_path.exists():
                raise StorageError(f"Project {project_id} not found")

            flows_path = project_path / "flows"
            flow_file = flows_path / f"{flow.id}.json"

            # Convert flow to dict and handle bytes serialization
            flow_data = flow.model_dump()
            if flow_data.get("request", {}).get("body"):
                flow_data["request"]["body"] = flow_data["request"]["body"].hex()
            if flow_data.get("response", {}).get("body"):
                flow_data["response"]["body"] = flow_data["response"]["body"].hex()

            self._write_json(flow_file, flow_data)

            logger.debug(f"Stored flow {flow.id} in project {project_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store flow {flow.id}: {e}")
            return False

    def get_flows(
        self, project_id: Union[str, uuid.UUID], limit: Optional[int] = None
    ) -> List[HTTPFlow]:
        """
        Get HTTP flows for a project.

        Args:
            project_id: Project ID
            limit: Maximum number of flows to return

        Returns:
            List of HTTP flows
        """
        flows = []
        try:
            project_path = self.base_path / "projects" / str(project_id)
            flows_path = project_path / "flows"

            if not flows_path.exists():
                return flows

            flow_files = sorted(
                flows_path.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True
            )

            if limit:
                flow_files = flow_files[:limit]

            for flow_file in flow_files:
                try:
                    flow_data = self._read_json(flow_file)

                    # Convert hex-encoded bytes back to bytes
                    if flow_data.get("request", {}).get("body"):
                        flow_data["request"]["body"] = bytes.fromhex(
                            flow_data["request"]["body"]
                        )
                    if flow_data.get("response", {}).get("body"):
                        flow_data["response"]["body"] = bytes.fromhex(
                            flow_data["response"]["body"]
                        )

                    flow = HTTPFlow(**flow_data)
                    flows.append(flow)

                except Exception as e:
                    logger.warning(f"Failed to load flow from {flow_file}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to get flows for project {project_id}: {e}")

        return flows

    def _backup_project(self, project_id: Union[str, uuid.UUID]) -> bool:
        """
        Create a backup of a project.

        Args:
            project_id: Project ID

        Returns:
            True if successful, False otherwise
        """
        try:
            project_path = self.base_path / "projects" / str(project_id)
            if not project_path.exists():
                return False

            backup_name = f"{project_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            backup_path = self.base_path / "backups" / backup_name

            shutil.copytree(project_path, backup_path)

            # Clean up old backups if needed
            self._cleanup_old_backups()

            logger.info(f"Created backup for project {project_id}: {backup_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to backup project {project_id}: {e}")
            return False

    def _cleanup_old_backups(self) -> None:
        """Clean up old backups based on configuration."""
        try:
            backups_path = self.base_path / "backups"
            if not backups_path.exists():
                return

            backups = sorted(
                backups_path.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True
            )

            # Keep only the configured number of backups
            max_backups = 10  # Default fallback
            if self.config and hasattr(self.config, "vault"):
                max_backups = getattr(self.config.vault, "max_backups", 10)

            if len(backups) > max_backups:
                for backup in backups[max_backups:]:
                    if backup.is_dir():
                        shutil.rmtree(backup)
                    else:
                        backup.unlink()

        except Exception as e:
            logger.warning(f"Failed to cleanup old backups: {e}")

    def get_vault_info(self) -> Dict[str, Any]:
        """
        Get vault information and statistics.

        Returns:
            Dictionary containing vault information
        """
        try:
            vault_meta = self._read_json(self.base_path / "vault.json")

            # Calculate storage usage
            total_size = sum(
                f.stat().st_size for f in self.base_path.rglob("*") if f.is_file()
            )

            # Count projects and flows
            project_count = len(vault_meta.get("projects", {}))
            total_flows = 0

            for project_id in vault_meta.get("projects", {}):
                flows_path = self.base_path / "projects" / project_id / "flows"
                if flows_path.exists():
                    total_flows += len(list(flows_path.glob("*.json")))

            return {
                "version": vault_meta.get("version"),
                "created_at": vault_meta.get("created_at"),
                "last_backup": vault_meta.get("last_backup"),
                "base_path": str(self.base_path),
                "total_size_bytes": total_size,
                "project_count": project_count,
                "total_flows": total_flows,
            }

        except Exception as e:
            logger.error(f"Failed to get vault info: {e}")
            return {}
