"""
OASIS Storage Management System

Provides configurable storage limits, automatic cleanup, and data archiving
to maintain system performance without losing critical information.
"""

import asyncio
import gzip
import json
import logging
import shutil
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from ..core.config import get_config
from ..core.exceptions import StorageError
from ..core.models import HTTPFlow, Project, Finding, Severity
from ..core.memory import StreamingBuffer, MemoryConfig, get_memory_monitor
from .vault import VaultStorage


logger = logging.getLogger(__name__)


class StorageConfig:
    """Configuration for storage management."""

    def __init__(self):
        """Initialize with default values."""
        # Storage limits
        self.max_flows_per_project = 10000
        self.max_total_flows = 100000
        self.max_database_size_mb = 1000
        self.max_flow_age_days = 30

        # Archive settings
        self.enable_archiving = True
        self.archive_compression = True
        self.archive_path = None  # Will use vault_path/archives

        # Cleanup settings
        self.cleanup_interval_hours = 24
        self.cleanup_batch_size = 1000
        self.preserve_critical_findings = True
        self.preserve_starred_flows = True

        # Performance settings
        self.async_cleanup = True
        self.cleanup_during_low_activity = True

        # Load from config if available
        self._load_from_config()

    def _load_from_config(self) -> None:
        """Load settings from application config."""
        try:
            config = get_config()
            storage_config = config.get("storage_management", {})

            # Update values from config
            for key, value in storage_config.items():
                if hasattr(self, key):
                    setattr(self, key, value)

        except Exception as e:
            logger.debug(f"Could not load storage config: {e}")


class ArchiveManager:
    """Manages data archiving operations."""

    def __init__(self, archive_path: Path, compression: bool = True):
        """
        Initialize archive manager.

        Args:
            archive_path: Path to archive directory
            compression: Whether to compress archived data
        """
        self.archive_path = archive_path
        self.compression = compression

        # Ensure archive directory exists
        self.archive_path.mkdir(parents=True, exist_ok=True)

    def archive_flows(self, flows: List[HTTPFlow], project_id: uuid.UUID) -> bool:
        """
        Archive a list of flows to compressed storage.

        Args:
            flows: List of flows to archive
            project_id: Project ID for organization

        Returns:
            True if successful, False otherwise
        """
        try:
            if not flows:
                return True

            # Create archive file path
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            archive_name = f"flows_{project_id}_{timestamp}.json"

            if self.compression:
                archive_name += ".gz"

            archive_file = self.archive_path / archive_name

            # Serialize flows
            flows_data = []
            for flow in flows:
                flow_data = {
                    "id": str(flow.id),
                    "request": self._serialize_request(flow.request),
                    "response": (
                        self._serialize_response(flow.response)
                        if flow.response
                        else None
                    ),
                    "metadata": self._serialize_metadata(flow.metadata),
                    "created_at": flow.created_at.isoformat(),
                    "archived_at": datetime.now(UTC).isoformat(),
                }
                flows_data.append(flow_data)

            archive_data = {
                "project_id": str(project_id),
                "flow_count": len(flows),
                "archived_at": datetime.now(UTC).isoformat(),
                "flows": flows_data,
            }

            # Write archive file
            if self.compression:
                with gzip.open(archive_file, "wt", encoding="utf-8") as f:
                    json.dump(archive_data, f, indent=2)
            else:
                with open(archive_file, "w", encoding="utf-8") as f:
                    json.dump(archive_data, f, indent=2)

            logger.info(f"Archived {len(flows)} flows to {archive_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to archive flows: {e}")
            return False

    def _serialize_request(self, request) -> Dict[str, Any]:
        """Serialize HTTP request for archiving."""
        return {
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "body": request.body.hex() if request.body else None,
            "timestamp": request.timestamp.isoformat(),
            "source": request.source.value,
        }

    def _serialize_response(self, response) -> Dict[str, Any]:
        """Serialize HTTP response for archiving."""
        return {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body.hex() if response.body else None,
            "timestamp": response.timestamp.isoformat(),
            "duration_ms": response.duration_ms,
        }

    def _serialize_metadata(self, metadata) -> Dict[str, Any]:
        """Serialize flow metadata for archiving."""
        return {
            "project_id": str(metadata.project_id) if metadata.project_id else None,
            "tags": metadata.tags,
            "notes": metadata.notes,
            "starred": metadata.starred,
            "reviewed": metadata.reviewed,
        }

    def list_archives(
        self, project_id: Optional[uuid.UUID] = None
    ) -> List[Dict[str, Any]]:
        """
        List available archives.

        Args:
            project_id: Filter by project ID (optional)

        Returns:
            List of archive information
        """
        archives = []
        try:
            pattern = f"flows_{project_id}_*.json*" if project_id else "flows_*.json*"

            for archive_file in self.archive_path.glob(pattern):
                try:
                    # Extract metadata from filename
                    name_parts = archive_file.stem.split("_")
                    if len(name_parts) >= 3:
                        archive_project_id = name_parts[1]
                        archive_timestamp = name_parts[2]

                        archive_info = {
                            "file_path": str(archive_file),
                            "project_id": archive_project_id,
                            "timestamp": archive_timestamp,
                            "size_bytes": archive_file.stat().st_size,
                            "compressed": archive_file.suffix == ".gz",
                        }
                        archives.append(archive_info)

                except Exception as e:
                    logger.warning(f"Failed to parse archive file {archive_file}: {e}")
                    continue

            # Sort by timestamp (newest first)
            archives.sort(key=lambda x: x["timestamp"], reverse=True)

        except Exception as e:
            logger.error(f"Failed to list archives: {e}")

        return archives

    def get_archive_size(self) -> int:
        """
        Get total size of all archives in bytes.

        Returns:
            Total archive size in bytes
        """
        total_size = 0
        try:
            for archive_file in self.archive_path.glob("*.json*"):
                total_size += archive_file.stat().st_size
        except Exception as e:
            logger.error(f"Failed to calculate archive size: {e}")

        return total_size


class StorageManager:
    """
    Main storage management system with configurable limits and archiving.

    Provides automatic cleanup, data archiving, and performance optimization
    while preserving critical information.
    """

    def __init__(
        self,
        vault_storage: Optional[VaultStorage] = None,
        config: Optional[StorageConfig] = None,
    ):
        """
        Initialize storage manager.

        Args:
            vault_storage: Vault storage instance (creates default if None)
            config: Storage configuration (uses defaults if None)
        """
        self.vault = vault_storage or VaultStorage()
        self.config = config or StorageConfig()

        # Initialize archive manager
        archive_path = (
            Path(self.config.archive_path)
            if self.config.archive_path
            else (self.vault.base_path / "archives")
        )
        self.archive_manager = ArchiveManager(
            archive_path, self.config.archive_compression
        )

        # Initialize memory monitor
        self.memory_monitor = get_memory_monitor()

        # Cleanup state
        self._last_cleanup = datetime.now(UTC)
        self._cleanup_running = False

    async def check_and_cleanup(self, force: bool = False) -> Dict[str, Any]:
        """
        Check storage limits and perform cleanup if needed.

        Args:
            force: If True, bypass cleanup checks and force cleanup

        Returns:
            Dictionary with cleanup results and statistics
        """
        if self._cleanup_running:
            return {"status": "cleanup_already_running"}

        try:
            self._cleanup_running = True

            # Check if cleanup is needed (skip check if forced)
            if not force:
                cleanup_needed = await self._should_cleanup()
                if not cleanup_needed:
                    return {"status": "no_cleanup_needed"}

            logger.info("Starting storage cleanup...")

            # Perform cleanup operations
            results = {
                "status": "completed",
                "flows_archived": 0,
                "flows_deleted": 0,
                "projects_cleaned": 0,
                "space_freed_bytes": 0,
                "cleanup_duration_seconds": 0,
            }

            start_time = datetime.now(UTC)

            # Get all projects for cleanup
            projects = self.vault.list_projects()

            for project in projects:
                project_results = await self._cleanup_project(project)
                results["flows_archived"] += project_results["flows_archived"]
                results["flows_deleted"] += project_results["flows_deleted"]
                results["space_freed_bytes"] += project_results["space_freed_bytes"]

                if (
                    project_results["flows_archived"] > 0
                    or project_results["flows_deleted"] > 0
                ):
                    results["projects_cleaned"] += 1

            # Update cleanup timestamp
            self._last_cleanup = datetime.now(UTC)
            results["cleanup_duration_seconds"] = (
                self._last_cleanup - start_time
            ).total_seconds()

            logger.info(f"Storage cleanup completed: {results}")
            return results

        except Exception as e:
            logger.error(f"Storage cleanup failed: {e}")
            return {"status": "failed", "error": str(e)}
        finally:
            self._cleanup_running = False

    async def _should_cleanup(self) -> bool:
        """Check if cleanup is needed based on configured limits."""
        try:
            # Check time-based cleanup
            time_since_cleanup = datetime.now(UTC) - self._last_cleanup
            if time_since_cleanup.total_seconds() >= (
                self.config.cleanup_interval_hours * 3600
            ):
                return True

            # Check database size
            vault_info = self.vault.get_vault_info()
            db_size_mb = vault_info.get("database_size_bytes", 0) / (1024 * 1024)
            if db_size_mb >= self.config.max_database_size_mb:
                logger.info(
                    f"Database size ({db_size_mb:.1f}MB) exceeds limit ({self.config.max_database_size_mb}MB)"
                )
                return True

            # Check total flow count
            total_flows = vault_info.get("total_flows", 0)
            if total_flows >= self.config.max_total_flows:
                logger.info(
                    f"Total flows ({total_flows}) exceeds limit ({self.config.max_total_flows})"
                )
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to check cleanup conditions: {e}")
            return False

    async def _cleanup_project(self, project: Project) -> Dict[str, Any]:
        """
        Clean up a single project's data.

        Args:
            project: Project to clean up

        Returns:
            Dictionary with cleanup results for this project
        """
        results = {"flows_archived": 0, "flows_deleted": 0, "space_freed_bytes": 0}

        try:
            # Get all flows for the project
            flows = self.vault.get_flows(project.id)

            if not flows:
                return results

            # Categorize flows for cleanup
            flows_to_archive = []
            flows_to_delete = []

            cutoff_date = datetime.now(UTC) - timedelta(
                days=self.config.max_flow_age_days
            )

            for flow in flows:
                # Skip starred flows if configured to preserve them
                if self.config.preserve_starred_flows and flow.metadata.starred:
                    continue

                # Skip flows associated with critical findings
                if self.config.preserve_critical_findings:
                    if await self._has_critical_findings(project.id, flow):
                        continue

                # Check age - ensure both datetimes are timezone-aware for comparison
                flow_created_at = flow.created_at
                if flow_created_at.tzinfo is None:
                    # If flow.created_at is naive, assume it's UTC
                    flow_created_at = flow_created_at.replace(tzinfo=UTC)

                if flow_created_at < cutoff_date:
                    if self.config.enable_archiving:
                        flows_to_archive.append(flow)
                    else:
                        flows_to_delete.append(flow)

            # Check project-specific limits
            remaining_flows = len(flows) - len(flows_to_archive) - len(flows_to_delete)
            if remaining_flows > self.config.max_flows_per_project:
                # Need to archive/delete more flows (oldest first)
                excess_count = remaining_flows - self.config.max_flows_per_project

                # Get flows not already marked for cleanup, sorted by age
                remaining_flow_candidates = [
                    f
                    for f in flows
                    if f not in flows_to_archive and f not in flows_to_delete
                ]
                remaining_flow_candidates.sort(key=lambda x: x.created_at)

                for flow in remaining_flow_candidates[:excess_count]:
                    if self.config.enable_archiving:
                        flows_to_archive.append(flow)
                    else:
                        flows_to_delete.append(flow)

            # Perform archiving
            if flows_to_archive:
                if self.archive_manager.archive_flows(flows_to_archive, project.id):
                    # Remove archived flows from database
                    for flow in flows_to_archive:
                        try:
                            # Actually delete the flow from the database
                            self.vault.delete_flow(project.id, flow.id)
                            # Calculate approximate space freed (rough estimate)
                            space_freed = self._estimate_flow_size(flow)
                            results["space_freed_bytes"] += space_freed
                        except Exception as e:
                            logger.warning(
                                f"Failed to delete archived flow {flow.id}: {e}"
                            )

                    results["flows_archived"] = len(flows_to_archive)
                    logger.info(
                        f"Archived {len(flows_to_archive)} flows from project {project.name}"
                    )

            # Perform deletion (for flows not archived)
            if flows_to_delete:
                for flow in flows_to_delete:
                    try:
                        # Delete the flow from the database
                        self.vault.delete_flow(project.id, flow.id)
                        space_freed = self._estimate_flow_size(flow)
                        results["space_freed_bytes"] += space_freed
                    except Exception as e:
                        logger.warning(f"Failed to delete flow {flow.id}: {e}")

                results["flows_deleted"] = len(flows_to_delete)
                logger.info(
                    f"Deleted {len(flows_to_delete)} flows from project {project.name}"
                )

            return results

        except Exception as e:
            logger.error(f"Failed to cleanup project {project.id}: {e}")
            return results

    async def _has_critical_findings(
        self, project_id: uuid.UUID, flow: HTTPFlow
    ) -> bool:
        """
        Check if a flow is associated with critical security findings.

        Args:
            project_id: Project ID
            flow: HTTP flow to check

        Returns:
            True if flow has critical findings, False otherwise
        """
        try:
            # Get critical findings for the project
            critical_findings = self.vault.get_findings(
                project_id, severity_filter=Severity.CRITICAL.value
            )
            high_findings = self.vault.get_findings(
                project_id, severity_filter=Severity.HIGH.value
            )

            # Check if any findings reference this flow
            for finding in critical_findings + high_findings:
                if (
                    finding.evidence.request
                    and finding.evidence.request.url == flow.request.url
                ):
                    return True
                if finding.evidence.response and flow.response:
                    # Could add more sophisticated matching here
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to check critical findings for flow {flow.id}: {e}")
            return False

    def _estimate_flow_size(self, flow: HTTPFlow) -> int:
        """
        Estimate the storage size of a flow in bytes.

        Args:
            flow: HTTP flow

        Returns:
            Estimated size in bytes
        """
        size = 0

        # Request size
        size += len(flow.request.url.encode("utf-8"))
        size += sum(
            len(k.encode("utf-8")) + len(v.encode("utf-8"))
            for k, v in flow.request.headers.items()
        )
        if flow.request.body:
            size += len(flow.request.body)

        # Response size
        if flow.response:
            size += sum(
                len(k.encode("utf-8")) + len(v.encode("utf-8"))
                for k, v in flow.response.headers.items()
            )
            if flow.response.body:
                size += len(flow.response.body)

        # Metadata and overhead (rough estimate)
        size += 500

        return size

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        try:
            vault_info = self.vault.get_vault_info()

            # Get archive statistics
            archive_size = self.archive_manager.get_archive_size()
            archive_count = len(self.archive_manager.list_archives())

            # Calculate usage percentages
            db_size_mb = vault_info.get("database_size_bytes", 0) / (1024 * 1024)
            db_usage_percent = (db_size_mb / self.config.max_database_size_mb) * 100

            total_flows = vault_info.get("total_flows", 0)
            flow_usage_percent = (total_flows / self.config.max_total_flows) * 100

            # Get memory statistics
            memory_stats = self.memory_monitor.get_stats()

            return {
                "vault_info": vault_info,
                "database_size_mb": db_size_mb,
                "database_usage_percent": db_usage_percent,
                "flow_usage_percent": flow_usage_percent,
                "archive_size_bytes": archive_size,
                "archive_count": archive_count,
                "memory_stats": memory_stats,
                "last_cleanup": self._last_cleanup.isoformat(),
                "cleanup_running": self._cleanup_running,
                "config": {
                    "max_flows_per_project": self.config.max_flows_per_project,
                    "max_total_flows": self.config.max_total_flows,
                    "max_database_size_mb": self.config.max_database_size_mb,
                    "max_flow_age_days": self.config.max_flow_age_days,
                    "enable_archiving": self.config.enable_archiving,
                },
            }

        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {}

    def force_cleanup(self) -> Dict[str, Any]:
        """
        Force immediate cleanup regardless of configured intervals.

        Returns:
            Dictionary with cleanup results
        """
        if self.config.async_cleanup:
            # Run cleanup asynchronously
            try:
                # Try to get the running event loop
                try:
                    loop = asyncio.get_running_loop()
                    # If we're already in an async context, create a task
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(
                            asyncio.run, self.check_and_cleanup(force=True)
                        )
                        return future.result()
                except RuntimeError:
                    # No running loop, create a new one
                    return asyncio.run(self.check_and_cleanup(force=True))
            except Exception:
                # Fallback to simple asyncio.run
                return asyncio.run(self.check_and_cleanup(force=True))
        else:
            # Run cleanup synchronously (blocking)
            return asyncio.run(self.check_and_cleanup(force=True))

    def update_config(self, new_config: StorageConfig) -> None:
        """
        Update storage configuration.

        Args:
            new_config: New storage configuration
        """
        self.config = new_config

        # Update archive manager if path changed
        if new_config.archive_path:
            archive_path = Path(new_config.archive_path)
            self.archive_manager = ArchiveManager(
                archive_path, new_config.archive_compression
            )
