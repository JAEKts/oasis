"""
OASIS SQLite Vault Storage System

Provides hierarchical project-based storage with SQLite backend, version control and change tracking.
"""

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.config import get_config, get_vault_path
from ..core.exceptions import StorageError
from ..core.logging import get_logger
from ..core.models import (
    HTTPFlow,
    Project,
    ProjectSettings,
    User,
    Finding,
    serialize_model,
    deserialize_model,
)

logger = get_logger(__name__)


class SQLiteVaultStorage:
    """
    SQLite-based vault storage system for managing projects and data with hierarchical organization.

    Provides:
    - Project-based data organization with SQLite backend
    - Version control and change tracking
    - Automatic backup and recovery
    - Efficient data serialization and querying
    - Database schema migration system
    """

    def __init__(self, base_path: Optional[Path] = None) -> None:
        """
        Initialize SQLite vault storage.

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

        self.db_path = self.base_path / "vault.db"

        # Ensure vault directory exists
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper configuration."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
        conn.execute(
            "PRAGMA journal_mode = WAL"
        )  # Enable WAL mode for better concurrency
        return conn

    def _initialize_database(self) -> None:
        """Initialize database schema."""
        try:
            with self._get_connection() as conn:
                # Create schema version table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_version (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )

                # Check current schema version
                cursor = conn.execute(
                    "SELECT MAX(version) as version FROM schema_version"
                )
                current_version = cursor.fetchone()["version"] or 0

                # Apply migrations
                self._apply_migrations(conn, current_version)

            logger.info(f"SQLite vault initialized at {self.db_path}")

        except Exception as e:
            raise StorageError(f"Failed to initialize SQLite vault: {e}")

    def _apply_migrations(self, conn: sqlite3.Connection, current_version: int) -> None:
        """Apply database migrations."""
        migrations = [
            # Migration 1: Initial schema
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                settings_json TEXT DEFAULT '{}',
                collaborators_json TEXT DEFAULT '[]'
            );
            
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            );
            
            CREATE TABLE IF NOT EXISTS http_flows (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                request_json TEXT NOT NULL,
                response_json TEXT NULL,
                metadata_json TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT DEFAULT '{}',
                remediation TEXT NOT NULL,
                references_json TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS project_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                changes_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT NULL,
                FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
            );
            
            CREATE INDEX IF NOT EXISTS idx_http_flows_project_id ON http_flows (project_id);
            CREATE INDEX IF NOT EXISTS idx_http_flows_created_at ON http_flows (created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_project_id ON findings (project_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
            CREATE INDEX IF NOT EXISTS idx_project_versions_project_id ON project_versions (project_id);
            """,
            # Migration 2: Add full-text search
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS flows_fts USING fts5(
                flow_id,
                url,
                method,
                request_headers,
                request_body,
                response_headers,
                response_body,
                content='http_flows'
            );
            
            CREATE TRIGGER IF NOT EXISTS flows_fts_insert AFTER INSERT ON http_flows BEGIN
                INSERT INTO flows_fts(flow_id, url, method, request_headers, request_body, response_headers, response_body)
                VALUES (
                    new.id,
                    json_extract(new.request_json, '$.url'),
                    json_extract(new.request_json, '$.method'),
                    json_extract(new.request_json, '$.headers'),
                    json_extract(new.request_json, '$.body'),
                    json_extract(new.response_json, '$.headers'),
                    json_extract(new.response_json, '$.body')
                );
            END;
            """,
            # Migration 3: Add project statistics table
            """
            CREATE TABLE IF NOT EXISTS project_stats (
                project_id TEXT PRIMARY KEY,
                flow_count INTEGER DEFAULT 0,
                finding_count INTEGER DEFAULT 0,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_size_bytes INTEGER DEFAULT 0,
                FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
            );
            
            CREATE TRIGGER IF NOT EXISTS update_project_stats_flows AFTER INSERT ON http_flows BEGIN
                INSERT OR REPLACE INTO project_stats (project_id, flow_count, last_activity)
                VALUES (
                    new.project_id,
                    (SELECT COUNT(*) FROM http_flows WHERE project_id = new.project_id),
                    CURRENT_TIMESTAMP
                );
            END;
            
            CREATE TRIGGER IF NOT EXISTS update_project_stats_findings AFTER INSERT ON findings BEGIN
                INSERT OR REPLACE INTO project_stats (project_id, finding_count, last_activity)
                VALUES (
                    new.project_id,
                    (SELECT COUNT(*) FROM findings WHERE project_id = new.project_id),
                    CURRENT_TIMESTAMP
                );
            END;
            """,
        ]

        for i, migration in enumerate(migrations, 1):
            if i > current_version:
                try:
                    # Execute migration
                    conn.executescript(migration)

                    # Record migration
                    conn.execute(
                        "INSERT INTO schema_version (version) VALUES (?)", (i,)
                    )

                    logger.info(f"Applied migration {i}")

                except Exception as e:
                    raise StorageError(f"Failed to apply migration {i}: {e}")

    def create_project(
        self,
        name: Union[str, Project],
        description: str = "",
        settings: Optional[ProjectSettings] = None,
    ) -> Union[Project, uuid.UUID]:
        """
        Create a new project.

        Args:
            name: Project name (str) or Project object
            description: Project description (ignored if name is a Project)
            settings: Project settings (ignored if name is a Project, uses defaults if None)

        Returns:
            Created project instance if name is str, or project ID if name is Project

        Raises:
            StorageError: If project creation fails
        """
        try:
            # Handle both Project object and individual parameters
            if isinstance(name, Project):
                project = name
                return_project_id = True
            else:
                project = Project(
                    name=name,
                    description=description,
                    settings=settings or ProjectSettings(),
                )
                return_project_id = False

            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO projects (id, name, description, settings_json, collaborators_json)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        str(project.id),
                        project.name,
                        project.description,
                        json.dumps(serialize_model(project.settings)),
                        json.dumps(
                            [serialize_model(user) for user in project.collaborators]
                        ),
                    ),
                )

                # Initialize project stats
                conn.execute(
                    """
                    INSERT INTO project_stats (project_id, flow_count, finding_count)
                    VALUES (?, 0, 0)
                """,
                    (str(project.id),),
                )

                # Create initial version record
                self._create_version_record(conn, project.id, "Project created", None)

            logger.info(f"Created project: {project.name} ({project.id})")

            # Return project ID if a Project object was passed, otherwise return the Project
            return project.id if return_project_id else project

        except Exception as e:
            raise StorageError(
                f"Failed to create project '{project.name if isinstance(name, Project) else name}': {e}"
            )

    def get_project(self, project_id: Union[str, uuid.UUID]) -> Optional[Project]:
        """
        Get project by ID.

        Args:
            project_id: Project ID

        Returns:
            Project instance or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT id, name, description, created_at, settings_json, collaborators_json
                    FROM projects WHERE id = ?
                """,
                    (str(project_id),),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                # Deserialize settings and collaborators
                settings_data = json.loads(row["settings_json"])
                collaborators_data = json.loads(row["collaborators_json"])

                settings = deserialize_model(ProjectSettings, settings_data)
                collaborators = [
                    deserialize_model(User, user_data)
                    for user_data in collaborators_data
                ]

                return Project(
                    id=uuid.UUID(row["id"]),
                    name=row["name"],
                    description=row["description"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    settings=settings,
                    collaborators=collaborators,
                )

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
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT p.id, p.name, p.description, p.created_at, p.settings_json, p.collaborators_json,
                           ps.flow_count, ps.finding_count, ps.last_activity
                    FROM projects p
                    LEFT JOIN project_stats ps ON p.id = ps.project_id
                    ORDER BY p.created_at DESC
                """
                )

                for row in cursor.fetchall():
                    try:
                        # Deserialize settings and collaborators
                        settings_data = json.loads(row["settings_json"])
                        collaborators_data = json.loads(row["collaborators_json"])

                        settings = deserialize_model(ProjectSettings, settings_data)
                        collaborators = [
                            deserialize_model(User, user_data)
                            for user_data in collaborators_data
                        ]

                        project = Project(
                            id=uuid.UUID(row["id"]),
                            name=row["name"],
                            description=row["description"],
                            created_at=datetime.fromisoformat(row["created_at"]),
                            settings=settings,
                            collaborators=collaborators,
                        )
                        projects.append(project)

                    except Exception as e:
                        logger.warning(
                            f"Failed to deserialize project {row['id']}: {e}"
                        )
                        continue

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
            with self._get_connection() as conn:
                # Check if project exists
                cursor = conn.execute(
                    "SELECT id FROM projects WHERE id = ?", (str(project.id),)
                )
                if not cursor.fetchone():
                    raise StorageError(f"Project {project.id} not found")

                # Update project
                conn.execute(
                    """
                    UPDATE projects 
                    SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP,
                        settings_json = ?, collaborators_json = ?
                    WHERE id = ?
                """,
                    (
                        project.name,
                        project.description,
                        json.dumps(serialize_model(project.settings)),
                        json.dumps(
                            [serialize_model(user) for user in project.collaborators]
                        ),
                        str(project.id),
                    ),
                )

                # Create version record
                self._create_version_record(conn, project.id, "Project updated", None)

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
            with self._get_connection() as conn:
                # Check if project exists
                cursor = conn.execute(
                    "SELECT id FROM projects WHERE id = ?", (str(project_id),)
                )
                if not cursor.fetchone():
                    return False

                # Delete project (cascades to related data)
                conn.execute("DELETE FROM projects WHERE id = ?", (str(project_id),))

            logger.info(f"Deleted project: {project_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete project {project_id}: {e}")
            return False

    def store_flow(
        self, project_id: Union[str, uuid.UUID], flow: HTTPFlow
    ) -> Union[uuid.UUID, bool]:
        """
        Store an HTTP flow in a project.

        Args:
            project_id: Project ID
            flow: HTTP flow to store

        Returns:
            Flow ID if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                # Check if project exists
                cursor = conn.execute(
                    "SELECT id FROM projects WHERE id = ?", (str(project_id),)
                )
                if not cursor.fetchone():
                    raise StorageError(f"Project {project_id} not found")

                # Serialize flow data with proper handling of datetime and bytes
                request_data = serialize_model(flow.request)
                # Handle bytes serialization for request body
                if request_data.get("body") is not None:
                    request_data["body"] = (
                        request_data["body"].hex()
                        if isinstance(request_data["body"], bytes)
                        else request_data["body"]
                    )
                request_json = json.dumps(request_data, default=str)

                response_json = None
                if flow.response:
                    response_data = serialize_model(flow.response)
                    # Handle bytes serialization for response body
                    if response_data.get("body") is not None:
                        response_data["body"] = (
                            response_data["body"].hex()
                            if isinstance(response_data["body"], bytes)
                            else response_data["body"]
                        )
                    response_json = json.dumps(response_data, default=str)

                metadata_json = json.dumps(serialize_model(flow.metadata), default=str)

                # Store flow
                conn.execute(
                    """
                    INSERT INTO http_flows (id, project_id, request_json, response_json, metadata_json)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        str(flow.id),
                        str(project_id),
                        request_json,
                        response_json,
                        metadata_json,
                    ),
                )

            logger.debug(f"Stored flow {flow.id} in project {project_id}")
            return flow.id

        except Exception as e:
            logger.error(f"Failed to store flow {flow.id}: {e}")
            return False

    def delete_flow(
        self, project_id: Union[str, uuid.UUID], flow_id: Union[str, uuid.UUID]
    ) -> bool:
        """
        Delete an HTTP flow from a project.

        Args:
            project_id: Project ID
            flow_id: Flow ID to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                # Check if project exists
                cursor = conn.execute(
                    "SELECT id FROM projects WHERE id = ?", (str(project_id),)
                )
                if not cursor.fetchone():
                    raise StorageError(f"Project {project_id} not found")

                # Delete the flow
                cursor = conn.execute(
                    """
                    DELETE FROM http_flows 
                    WHERE id = ? AND project_id = ?
                """,
                    (str(flow_id), str(project_id)),
                )

                if cursor.rowcount == 0:
                    logger.warning(f"Flow {flow_id} not found in project {project_id}")
                    return False

            logger.debug(f"Deleted flow {flow_id} from project {project_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete flow {flow_id}: {e}")
            return False

    def get_flows(
        self,
        project_id: Union[str, uuid.UUID],
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[HTTPFlow]:
        """
        Get HTTP flows for a project.

        Args:
            project_id: Project ID
            limit: Maximum number of flows to return
            offset: Number of flows to skip

        Returns:
            List of HTTP flows
        """
        flows = []
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT id, request_json, response_json, metadata_json, created_at
                    FROM http_flows 
                    WHERE project_id = ?
                    ORDER BY created_at DESC
                """
                params = [str(project_id)]

                if limit:
                    query += " LIMIT ? OFFSET ?"
                    params.extend([limit, offset])

                cursor = conn.execute(query, params)

                for row in cursor.fetchall():
                    try:
                        # Deserialize flow data
                        request_data = json.loads(row["request_json"])
                        response_data = (
                            json.loads(row["response_json"])
                            if row["response_json"]
                            else None
                        )
                        metadata_data = json.loads(row["metadata_json"])

                        # Handle bytes deserialization for request body
                        if request_data.get("body") and isinstance(
                            request_data["body"], str
                        ):
                            try:
                                request_data["body"] = bytes.fromhex(
                                    request_data["body"]
                                )
                            except ValueError:
                                # If it's not hex, keep as string or set to None
                                request_data["body"] = None

                        # Handle bytes deserialization for response body
                        if (
                            response_data
                            and response_data.get("body")
                            and isinstance(response_data["body"], str)
                        ):
                            try:
                                response_data["body"] = bytes.fromhex(
                                    response_data["body"]
                                )
                            except ValueError:
                                # If it's not hex, keep as string or set to None
                                response_data["body"] = None

                        from ..core.models import (
                            HTTPRequest,
                            HTTPResponse,
                            FlowMetadata,
                        )

                        request = deserialize_model(HTTPRequest, request_data)
                        response = (
                            deserialize_model(HTTPResponse, response_data)
                            if response_data
                            else None
                        )
                        metadata = deserialize_model(FlowMetadata, metadata_data)

                        flow = HTTPFlow(
                            id=uuid.UUID(row["id"]),
                            request=request,
                            response=response,
                            metadata=metadata,
                            created_at=datetime.fromisoformat(row["created_at"]),
                        )
                        flows.append(flow)

                    except Exception as e:
                        logger.warning(f"Failed to deserialize flow {row['id']}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Failed to get flows for project {project_id}: {e}")

        return flows

    def get_flow(
        self, project_id: Union[str, uuid.UUID], flow_id: Union[str, uuid.UUID]
    ) -> Optional[HTTPFlow]:
        """
        Get a single HTTP flow by ID.

        Args:
            project_id: Project ID
            flow_id: Flow ID

        Returns:
            HTTP flow or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT id, request_json, response_json, metadata_json, created_at
                    FROM http_flows 
                    WHERE id = ? AND project_id = ?
                """,
                    (str(flow_id), str(project_id)),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                # Deserialize flow data
                request_data = json.loads(row["request_json"])
                response_data = (
                    json.loads(row["response_json"]) if row["response_json"] else None
                )
                metadata_data = json.loads(row["metadata_json"])

                # Handle bytes deserialization for request body
                if request_data.get("body") and isinstance(request_data["body"], str):
                    try:
                        request_data["body"] = bytes.fromhex(request_data["body"])
                    except ValueError:
                        # If it's not hex, keep as string or set to None
                        request_data["body"] = None

                # Handle bytes deserialization for response body
                if (
                    response_data
                    and response_data.get("body")
                    and isinstance(response_data["body"], str)
                ):
                    try:
                        response_data["body"] = bytes.fromhex(response_data["body"])
                    except ValueError:
                        # If it's not hex, keep as string or set to None
                        response_data["body"] = None

                from ..core.models import HTTPRequest, HTTPResponse, FlowMetadata

                request = deserialize_model(HTTPRequest, request_data)
                response = (
                    deserialize_model(HTTPResponse, response_data)
                    if response_data
                    else None
                )
                metadata = deserialize_model(FlowMetadata, metadata_data)

                return HTTPFlow(
                    id=uuid.UUID(row["id"]),
                    request=request,
                    response=response,
                    metadata=metadata,
                    created_at=datetime.fromisoformat(row["created_at"]),
                )

        except Exception as e:
            logger.error(f"Failed to get flow {flow_id}: {e}")
            return None

    def store_finding(
        self, project_id: Union[str, uuid.UUID], finding: Finding
    ) -> Union[uuid.UUID, bool]:
        """
        Store a security finding in a project.

        Args:
            project_id: Project ID
            finding: Security finding to store

        Returns:
            Finding ID if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                # Check if project exists
                cursor = conn.execute(
                    "SELECT id FROM projects WHERE id = ?", (str(project_id),)
                )
                if not cursor.fetchone():
                    raise StorageError(f"Project {project_id} not found")

                # Store finding
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, project_id, vulnerability_type, severity, confidence,
                        title, description, evidence_json, remediation, references_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        str(finding.id),
                        str(project_id),
                        finding.vulnerability_type.value,
                        finding.severity.value,
                        finding.confidence.value,
                        finding.title,
                        finding.description,
                        json.dumps(serialize_model(finding.evidence), default=str),
                        finding.remediation,
                        json.dumps(finding.references, default=str),
                    ),
                )

            logger.debug(f"Stored finding {finding.id} in project {project_id}")
            return finding.id

        except Exception as e:
            logger.error(f"Failed to store finding {finding.id}: {e}")
            return False

    def get_findings(
        self, project_id: Union[str, uuid.UUID], severity_filter: Optional[str] = None
    ) -> List[Finding]:
        """
        Get security findings for a project.

        Args:
            project_id: Project ID
            severity_filter: Filter by severity level

        Returns:
            List of security findings
        """
        findings = []
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT id, vulnerability_type, severity, confidence, title, description,
                           evidence_json, remediation, references_json, created_at, updated_at
                    FROM findings 
                    WHERE project_id = ?
                """
                params = [str(project_id)]

                if severity_filter:
                    query += " AND severity = ?"
                    params.append(severity_filter)

                query += " ORDER BY created_at DESC"

                cursor = conn.execute(query, params)

                for row in cursor.fetchall():
                    try:
                        # Deserialize finding data
                        evidence_data = json.loads(row["evidence_json"])
                        references = json.loads(row["references_json"])

                        from ..core.models import (
                            Evidence,
                            VulnerabilityType,
                            Severity,
                            Confidence,
                        )

                        evidence = deserialize_model(Evidence, evidence_data)

                        finding = Finding(
                            id=uuid.UUID(row["id"]),
                            vulnerability_type=VulnerabilityType(
                                row["vulnerability_type"]
                            ),
                            severity=Severity(row["severity"]),
                            confidence=Confidence(row["confidence"]),
                            title=row["title"],
                            description=row["description"],
                            evidence=evidence,
                            remediation=row["remediation"],
                            references=references,
                            created_at=datetime.fromisoformat(row["created_at"]),
                            updated_at=datetime.fromisoformat(row["updated_at"]),
                        )
                        findings.append(finding)

                    except Exception as e:
                        logger.warning(
                            f"Failed to deserialize finding {row['id']}: {e}"
                        )
                        continue

        except Exception as e:
            logger.error(f"Failed to get findings for project {project_id}: {e}")

        return findings

    def get_finding(
        self, project_id: Union[str, uuid.UUID], finding_id: Union[str, uuid.UUID]
    ) -> Optional[Finding]:
        """
        Get a single security finding by ID.

        Args:
            project_id: Project ID
            finding_id: Finding ID

        Returns:
            Finding or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT id, vulnerability_type, severity, confidence, title, description,
                           evidence_json, remediation, references_json, created_at, updated_at
                    FROM findings 
                    WHERE id = ? AND project_id = ?
                """,
                    (str(finding_id), str(project_id)),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                # Deserialize finding data
                evidence_data = json.loads(row["evidence_json"])
                references = json.loads(row["references_json"])

                from ..core.models import (
                    Evidence,
                    VulnerabilityType,
                    Severity,
                    Confidence,
                )

                evidence = deserialize_model(Evidence, evidence_data)

                return Finding(
                    id=uuid.UUID(row["id"]),
                    vulnerability_type=VulnerabilityType(row["vulnerability_type"]),
                    severity=Severity(row["severity"]),
                    confidence=Confidence(row["confidence"]),
                    title=row["title"],
                    description=row["description"],
                    evidence=evidence,
                    remediation=row["remediation"],
                    references=references,
                    created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                )

        except Exception as e:
            logger.error(f"Failed to get finding {finding_id}: {e}")
            return None

    def search_flows(
        self, project_id: Union[str, uuid.UUID], query: str, limit: int = 100
    ) -> List[HTTPFlow]:
        """
        Search HTTP flows using full-text search.

        Args:
            project_id: Project ID
            query: Search query
            limit: Maximum number of results

        Returns:
            List of matching HTTP flows
        """
        flows = []
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT hf.id, hf.request_json, hf.response_json, hf.metadata_json, hf.created_at
                    FROM http_flows hf
                    JOIN flows_fts fts ON hf.id = fts.flow_id
                    WHERE hf.project_id = ? AND flows_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                """,
                    (str(project_id), query, limit),
                )

                for row in cursor.fetchall():
                    try:
                        # Deserialize flow data (same as get_flows)
                        request_data = json.loads(row["request_json"])
                        response_data = (
                            json.loads(row["response_json"])
                            if row["response_json"]
                            else None
                        )
                        metadata_data = json.loads(row["metadata_json"])

                        # Handle bytes deserialization for request body
                        if request_data.get("body") and isinstance(
                            request_data["body"], str
                        ):
                            try:
                                request_data["body"] = bytes.fromhex(
                                    request_data["body"]
                                )
                            except ValueError:
                                request_data["body"] = None

                        # Handle bytes deserialization for response body
                        if (
                            response_data
                            and response_data.get("body")
                            and isinstance(response_data["body"], str)
                        ):
                            try:
                                response_data["body"] = bytes.fromhex(
                                    response_data["body"]
                                )
                            except ValueError:
                                response_data["body"] = None

                        from ..core.models import (
                            HTTPRequest,
                            HTTPResponse,
                            FlowMetadata,
                        )

                        request = deserialize_model(HTTPRequest, request_data)
                        response = (
                            deserialize_model(HTTPResponse, response_data)
                            if response_data
                            else None
                        )
                        metadata = deserialize_model(FlowMetadata, metadata_data)

                        flow = HTTPFlow(
                            id=uuid.UUID(row["id"]),
                            request=request,
                            response=response,
                            metadata=metadata,
                            created_at=datetime.fromisoformat(row["created_at"]),
                        )
                        flows.append(flow)

                    except Exception as e:
                        logger.warning(
                            f"Failed to deserialize search result {row['id']}: {e}"
                        )
                        continue

        except Exception as e:
            logger.error(f"Failed to search flows in project {project_id}: {e}")

        return flows

    def _create_version_record(
        self,
        conn: sqlite3.Connection,
        project_id: uuid.UUID,
        changes: str,
        created_by: Optional[str],
    ) -> None:
        """Create a version record for change tracking."""
        try:
            # Get current version number
            cursor = conn.execute(
                """
                SELECT COALESCE(MAX(version_number), 0) + 1 as next_version
                FROM project_versions WHERE project_id = ?
            """,
                (str(project_id),),
            )

            next_version = cursor.fetchone()["next_version"]

            # Create version record
            conn.execute(
                """
                INSERT INTO project_versions (project_id, version_number, changes_json, created_by)
                VALUES (?, ?, ?, ?)
            """,
                (
                    str(project_id),
                    next_version,
                    json.dumps(
                        {"changes": changes, "timestamp": datetime.now().isoformat()}
                    ),
                    created_by,
                ),
            )

        except Exception as e:
            logger.warning(f"Failed to create version record: {e}")

    def get_vault_info(self) -> Dict[str, Any]:
        """
        Get vault information and statistics.

        Returns:
            Dictionary containing vault information
        """
        try:
            with self._get_connection() as conn:
                # Get basic stats
                cursor = conn.execute(
                    """
                    SELECT 
                        COUNT(DISTINCT p.id) as project_count,
                        COUNT(DISTINCT hf.id) as total_flows,
                        COUNT(DISTINCT f.id) as total_findings,
                        MAX(p.created_at) as last_project_created
                    FROM projects p
                    LEFT JOIN http_flows hf ON p.id = hf.project_id
                    LEFT JOIN findings f ON p.id = f.project_id
                """
                )

                stats = cursor.fetchone()

                # Get database size
                cursor = conn.execute(
                    "SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()"
                )
                db_size = cursor.fetchone()["size"]

                # Get schema version
                cursor = conn.execute(
                    "SELECT MAX(version) as version FROM schema_version"
                )
                schema_version = cursor.fetchone()["version"]

                return {
                    "version": "2.0",
                    "schema_version": schema_version,
                    "base_path": str(self.base_path),
                    "database_path": str(self.db_path),
                    "database_size_bytes": db_size,
                    "project_count": stats["project_count"],
                    "total_flows": stats["total_flows"],
                    "total_findings": stats["total_findings"],
                    "last_project_created": stats["last_project_created"],
                }

        except Exception as e:
            logger.error(f"Failed to get vault info: {e}")
            return {}

    def backup_database(self, backup_path: Optional[Path] = None) -> bool:
        """
        Create a backup of the database.

        Args:
            backup_path: Path for backup file (auto-generated if None)

        Returns:
            True if successful, False otherwise
        """
        try:
            if not backup_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = self.base_path / f"vault_backup_{timestamp}.db"

            # Use SQLite backup API for consistent backup
            with self._get_connection() as source:
                with sqlite3.connect(backup_path) as backup:
                    source.backup(backup)

            logger.info(f"Created database backup: {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False
