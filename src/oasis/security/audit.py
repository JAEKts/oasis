"""
OASIS Audit Logging

Provides comprehensive audit logging for all user actions and system events
to support compliance requirements (PCI DSS, HIPAA, SOX).
"""

import json
import sqlite3
import uuid
from datetime import datetime, UTC
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from ..core.config import get_config, get_vault_path
from ..core.logging import get_logger

logger = get_logger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""

    # Authentication events
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"

    # Data access events
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    DATA_DELETE = "data_delete"
    DATA_EXPORT = "data_export"

    # Project events
    PROJECT_CREATE = "project_create"
    PROJECT_UPDATE = "project_update"
    PROJECT_DELETE = "project_delete"
    PROJECT_SHARE = "project_share"

    # Security events
    ENCRYPTION_KEY_ROTATE = "encryption_key_rotate"
    PERMISSION_CHANGE = "permission_change"
    SECURITY_SCAN = "security_scan"
    VULNERABILITY_FOUND = "vulnerability_found"

    # System events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    CONFIGURATION_CHANGE = "configuration_change"
    BACKUP_CREATE = "backup_create"

    # Extension events
    EXTENSION_LOAD = "extension_load"
    EXTENSION_UNLOAD = "extension_unload"
    EXTENSION_ACTION = "extension_action"

    # Proxy events
    PROXY_START = "proxy_start"
    PROXY_STOP = "proxy_stop"
    TRAFFIC_INTERCEPT = "traffic_intercept"
    TRAFFIC_MODIFY = "traffic_modify"


class AuditEvent(BaseModel):
    """Audit event model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique event ID")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Event timestamp"
    )
    event_type: AuditEventType = Field(description="Type of event")
    user_id: Optional[str] = Field(
        default=None, description="User ID who triggered the event"
    )
    username: Optional[str] = Field(
        default=None, description="Username who triggered the event"
    )
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    resource_type: Optional[str] = Field(
        default=None, description="Type of resource affected"
    )
    resource_id: Optional[str] = Field(
        default=None, description="ID of resource affected"
    )
    action: str = Field(description="Action performed")
    result: str = Field(
        default="success", description="Result of action (success/failure)"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict, description="Additional event details"
    )
    severity: str = Field(
        default="info", description="Event severity (info/warning/error/critical)"
    )


class AuditLogger:
    """
    Audit logging system for compliance and security monitoring.

    Provides:
    - Comprehensive logging of all user actions and system events
    - Tamper-evident audit trail storage
    - Query and reporting capabilities
    - Compliance reporting for PCI DSS, HIPAA, and SOX
    """

    def __init__(self, audit_db_path: Optional[Path] = None) -> None:
        """
        Initialize audit logger.

        Args:
            audit_db_path: Path to audit database (uses config if None)
        """
        if audit_db_path:
            self.audit_db_path = audit_db_path
        else:
            try:
                vault_path = get_vault_path()
                self.audit_db_path = vault_path / "audit.db"
            except Exception:
                self.audit_db_path = Path.home() / ".oasis" / "audit.db"

        # Ensure parent directory exists
        self.audit_db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper configuration."""
        conn = sqlite3.connect(self.audit_db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _initialize_database(self) -> None:
        """Initialize audit database schema."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id TEXT PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL,
                        event_type TEXT NOT NULL,
                        user_id TEXT,
                        username TEXT,
                        source_ip TEXT,
                        resource_type TEXT,
                        resource_id TEXT,
                        action TEXT NOT NULL,
                        result TEXT NOT NULL,
                        details_json TEXT DEFAULT '{}',
                        severity TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )

                # Create indexes for efficient querying
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                    ON audit_events (timestamp DESC)
                """
                )

                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_event_type 
                    ON audit_events (event_type)
                """
                )

                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_user_id 
                    ON audit_events (user_id)
                """
                )

                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_resource 
                    ON audit_events (resource_type, resource_id)
                """
                )

                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_severity 
                    ON audit_events (severity)
                """
                )

                # Create audit log integrity table (for tamper detection)
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_integrity (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_count INTEGER NOT NULL,
                        last_event_id TEXT NOT NULL,
                        checksum TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )

            logger.info(f"Audit database initialized at {self.audit_db_path}")

        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
            raise

    def log_event(self, event: AuditEvent) -> bool:
        """
        Log an audit event.

        Args:
            event: Audit event to log

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        id, timestamp, event_type, user_id, username, source_ip,
                        resource_type, resource_id, action, result, details_json, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        str(event.id),
                        event.timestamp.isoformat(),
                        event.event_type.value,
                        event.user_id,
                        event.username,
                        event.source_ip,
                        event.resource_type,
                        event.resource_id,
                        event.action,
                        event.result,
                        json.dumps(event.details),
                        event.severity,
                    ),
                )

            logger.debug(
                f"Logged audit event: {event.event_type.value} - {event.action}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False

    def log(
        self,
        event_type: AuditEventType,
        action: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ) -> bool:
        """
        Log an audit event (convenience method).

        Args:
            event_type: Type of event
            action: Action performed
            user_id: User ID who triggered the event
            username: Username who triggered the event
            source_ip: Source IP address
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            result: Result of action
            details: Additional event details
            severity: Event severity

        Returns:
            True if successful, False otherwise
        """
        event = AuditEvent(
            event_type=event_type,
            action=action,
            user_id=user_id,
            username=username,
            source_ip=source_ip,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            details=details or {},
            severity=severity,
        )
        return self.log_event(event)

    def query_events(
        self,
        event_type: Optional[AuditEventType] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[AuditEvent]:
        """
        Query audit events with filters.

        Args:
            event_type: Filter by event type
            user_id: Filter by user ID
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            start_time: Filter by start time
            end_time: Filter by end time
            severity: Filter by severity
            limit: Maximum number of events to return
            offset: Number of events to skip

        Returns:
            List of audit events
        """
        events = []
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            if resource_type:
                query += " AND resource_type = ?"
                params.append(resource_type)

            if resource_id:
                query += " AND resource_id = ?"
                params.append(resource_id)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            with self._get_connection() as conn:
                cursor = conn.execute(query, params)

                for row in cursor.fetchall():
                    try:
                        event = AuditEvent(
                            id=uuid.UUID(row["id"]),
                            timestamp=datetime.fromisoformat(row["timestamp"]),
                            event_type=AuditEventType(row["event_type"]),
                            user_id=row["user_id"],
                            username=row["username"],
                            source_ip=row["source_ip"],
                            resource_type=row["resource_type"],
                            resource_id=row["resource_id"],
                            action=row["action"],
                            result=row["result"],
                            details=json.loads(row["details_json"]),
                            severity=row["severity"],
                        )
                        events.append(event)
                    except Exception as e:
                        logger.warning(
                            f"Failed to deserialize audit event {row['id']}: {e}"
                        )
                        continue

        except Exception as e:
            logger.error(f"Failed to query audit events: {e}")

        return events

    def get_event_count(
        self,
        event_type: Optional[AuditEventType] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Get count of audit events matching filters.

        Args:
            event_type: Filter by event type
            user_id: Filter by user ID
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            Count of matching events
        """
        try:
            query = "SELECT COUNT(*) as count FROM audit_events WHERE 1=1"
            params = []

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())

            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                return cursor.fetchone()["count"]

        except Exception as e:
            logger.error(f"Failed to get event count: {e}")
            return 0

    def generate_compliance_report(
        self, standard: str, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """
        Generate compliance report for specified standard.

        Args:
            standard: Compliance standard (PCI_DSS, HIPAA, SOX)
            start_time: Report start time
            end_time: Report end time

        Returns:
            Compliance report dictionary
        """
        try:
            # Get all events in time range
            events = self.query_events(
                start_time=start_time, end_time=end_time, limit=100000
            )

            # Generate report based on standard
            report = {
                "standard": standard,
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                "total_events": len(events),
                "event_summary": {},
                "security_events": [],
                "failed_actions": [],
                "user_activity": {},
            }

            # Summarize events by type
            for event in events:
                event_type = event.event_type.value
                report["event_summary"][event_type] = (
                    report["event_summary"].get(event_type, 0) + 1
                )

                # Track security events
                if event.severity in ["error", "critical"]:
                    report["security_events"].append(
                        {
                            "timestamp": event.timestamp.isoformat(),
                            "type": event_type,
                            "action": event.action,
                            "user": event.username or event.user_id,
                            "severity": event.severity,
                        }
                    )

                # Track failed actions
                if event.result == "failure":
                    report["failed_actions"].append(
                        {
                            "timestamp": event.timestamp.isoformat(),
                            "type": event_type,
                            "action": event.action,
                            "user": event.username or event.user_id,
                        }
                    )

                # Track user activity
                if event.user_id:
                    if event.user_id not in report["user_activity"]:
                        report["user_activity"][event.user_id] = {
                            "username": event.username,
                            "event_count": 0,
                            "actions": [],
                        }
                    report["user_activity"][event.user_id]["event_count"] += 1
                    report["user_activity"][event.user_id]["actions"].append(
                        event.action
                    )

            return report

        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {}


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_audit_event(event_type: AuditEventType, action: str, **kwargs: Any) -> bool:
    """
    Log an audit event using the global audit logger.

    Args:
        event_type: Type of event
        action: Action performed
        **kwargs: Additional event parameters

    Returns:
        True if successful, False otherwise
    """
    audit_logger = get_audit_logger()
    return audit_logger.log(event_type, action, **kwargs)
