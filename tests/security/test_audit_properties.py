"""
Property-based tests for OASIS audit logging.

Feature: oasis-pentest-suite, Property 19: Audit Trail Completeness
Validates: Requirements 12.4
"""

import tempfile
import uuid
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from src.oasis.security.audit import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    log_audit_event
)
from src.oasis.security.compliance import ComplianceReporter, ComplianceStandard


# Strategies for generating test data
@st.composite
def audit_event_data(draw):
    """Generate audit event data."""
    event_types = list(AuditEventType)
    return {
        "event_type": draw(st.sampled_from(event_types)),
        "action": draw(st.text(min_size=1, max_size=100)),
        "user_id": draw(st.text(min_size=1, max_size=50)),
        "username": draw(st.text(min_size=1, max_size=50)),
        "source_ip": draw(st.ip_addresses(v=4).map(str)),
        "resource_type": draw(st.text(min_size=1, max_size=50)),
        "resource_id": draw(st.uuids().map(str)),
        "result": draw(st.sampled_from(["success", "failure"])),
        "severity": draw(st.sampled_from(["info", "warning", "error", "critical"]))
    }


# Feature: oasis-pentest-suite, Property 19: Audit Trail Completeness
# Validates: Requirements 12.4
class TestAuditTrailCompleteness:
    """
    Property 19: Audit Trail Completeness
    
    For any user action or system event, it should be logged with sufficient
    detail for security auditing and compliance reporting.
    
    Validates: Requirements 12.4
    """
    
    @given(event_data=audit_event_data())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_all_events_are_logged(self, event_data: Dict[str, Any]):
        """
        Property: For any event, logging it should succeed and the event
        should be retrievable from the audit log.
        
        This validates that all events are captured in the audit trail.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log event
            success = audit_logger.log(
                event_type=event_data["event_type"],
                action=event_data["action"],
                user_id=event_data["user_id"],
                username=event_data["username"],
                source_ip=event_data["source_ip"],
                resource_type=event_data["resource_type"],
                resource_id=event_data["resource_id"],
                result=event_data["result"],
                severity=event_data["severity"]
            )
            
            # Verify logging succeeded
            assert success is True
            
            # Query for the event
            events = audit_logger.query_events(
                event_type=event_data["event_type"],
                user_id=event_data["user_id"]
            )
            
            # Verify event was logged
            assert len(events) > 0
            
            # Verify event details match
            logged_event = events[0]
            assert logged_event.event_type == event_data["event_type"]
            assert logged_event.action == event_data["action"]
            assert logged_event.user_id == event_data["user_id"]
            assert logged_event.username == event_data["username"]
            assert logged_event.result == event_data["result"]
            assert logged_event.severity == event_data["severity"]
    
    @given(
        event_count=st.integers(min_value=1, max_value=50),
        event_type=st.sampled_from(list(AuditEventType))
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_event_count_accuracy(self, event_count: int, event_type: AuditEventType):
        """
        Property: For any number of events logged, the event count query
        should return the exact number of events logged.
        
        This validates that the audit trail accurately tracks event counts.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log multiple events
            for i in range(event_count):
                audit_logger.log(
                    event_type=event_type,
                    action=f"Test action {i}",
                    user_id=f"user_{i}"
                )
            
            # Get event count
            count = audit_logger.get_event_count(event_type=event_type)
            
            # Verify count matches
            assert count == event_count
    
    @given(
        user_id=st.text(min_size=1, max_size=50),
        action_count=st.integers(min_value=1, max_value=20)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_user_activity_tracking(self, user_id: str, action_count: int):
        """
        Property: For any user performing multiple actions, all actions
        should be tracked and retrievable by user ID.
        
        This validates that user activity is completely tracked.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log multiple actions for the user
            event_types = list(AuditEventType)
            for i in range(action_count):
                audit_logger.log(
                    event_type=event_types[i % len(event_types)],
                    action=f"Action {i}",
                    user_id=user_id
                )
            
            # Query user's events
            events = audit_logger.query_events(user_id=user_id, limit=1000)
            
            # Verify all actions were logged
            assert len(events) == action_count
            
            # Verify all events belong to the user
            assert all(e.user_id == user_id for e in events)
    
    @given(
        resource_type=st.text(min_size=1, max_size=50),
        resource_id=st.uuids().map(str)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_resource_access_tracking(self, resource_type: str, resource_id: str):
        """
        Property: For any resource access, the event should be logged with
        complete resource information.
        
        This validates that resource access is tracked with sufficient detail.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log resource access
            audit_logger.log(
                event_type=AuditEventType.DATA_READ,
                action="Read resource",
                resource_type=resource_type,
                resource_id=resource_id
            )
            
            # Query for resource access
            events = audit_logger.query_events(
                resource_type=resource_type,
                resource_id=resource_id
            )
            
            # Verify event was logged
            assert len(events) > 0
            
            # Verify resource details
            event = events[0]
            assert event.resource_type == resource_type
            assert event.resource_id == resource_id
    
    @given(days_back=st.integers(min_value=1, max_value=30))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_time_range_filtering(self, days_back: int):
        """
        Property: For any time range, querying events should return only
        events within that time range.
        
        This validates that temporal filtering works correctly.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Define time range
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=days_back)
            
            # Log event within range
            audit_logger.log(
                event_type=AuditEventType.DATA_READ,
                action="Test action in range"
            )
            
            # Query with time range
            events = audit_logger.query_events(
                start_time=start_time,
                end_time=end_time
            )
            
            # Verify all events are within range
            for event in events:
                assert start_time <= event.timestamp <= end_time
    
    @given(
        severity=st.sampled_from(["info", "warning", "error", "critical"]),
        event_count=st.integers(min_value=1, max_value=20)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_severity_filtering(self, severity: str, event_count: int):
        """
        Property: For any severity level, querying events should return only
        events with that severity.
        
        This validates that severity filtering works correctly.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log events with specified severity
            for i in range(event_count):
                audit_logger.log(
                    event_type=AuditEventType.DATA_READ,
                    action=f"Action {i}",
                    severity=severity
                )
            
            # Query by severity
            events = audit_logger.query_events(severity=severity, limit=1000)
            
            # Verify all events have correct severity
            assert len(events) >= event_count
            assert all(e.severity == severity for e in events)
    
    @given(event_data=audit_event_data())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_event_immutability(self, event_data: Dict[str, Any]):
        """
        Property: For any logged event, it should remain unchanged in the
        audit trail (immutability).
        
        This validates that audit logs are tamper-evident.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log event
            audit_logger.log(
                event_type=event_data["event_type"],
                action=event_data["action"],
                user_id=event_data["user_id"]
            )
            
            # Query event
            events1 = audit_logger.query_events(user_id=event_data["user_id"])
            assert len(events1) > 0
            event1 = events1[0]
            
            # Query again
            events2 = audit_logger.query_events(user_id=event_data["user_id"])
            assert len(events2) > 0
            event2 = events2[0]
            
            # Verify events are identical
            assert event1.id == event2.id
            assert event1.timestamp == event2.timestamp
            assert event1.event_type == event2.event_type
            assert event1.action == event2.action
            assert event1.user_id == event2.user_id


class TestComplianceReporting:
    """Tests for compliance reporting functionality."""
    
    @given(days_back=st.integers(min_value=1, max_value=30))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_compliance_report_generation(self, days_back: int):
        """
        Property: For any time period, compliance reports should be
        generated successfully for all supported standards.
        
        This validates that compliance reporting works for all standards.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log some events
            for i in range(10):
                audit_logger.log(
                    event_type=AuditEventType.DATA_READ,
                    action=f"Test action {i}",
                    user_id=f"user_{i}"
                )
            
            # Create compliance reporter
            reporter = ComplianceReporter(audit_logger)
            
            # Define time range
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=days_back)
            
            # Generate reports for all standards
            for standard in [ComplianceStandard.PCI_DSS, ComplianceStandard.HIPAA, ComplianceStandard.SOX]:
                report = reporter.generate_report(standard, start_time, end_time)
                
                # Verify report is not empty
                assert report is not None
                assert len(report) > 0
    
    def test_pci_dss_report_structure(self):
        """Verify PCI DSS report contains required sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log various event types
            for event_type in [AuditEventType.LOGIN, AuditEventType.DATA_READ, AuditEventType.LOGIN_FAILED]:
                audit_logger.log(
                    event_type=event_type,
                    action="Test action",
                    user_id="test_user"
                )
            
            # Generate PCI DSS report
            reporter = ComplianceReporter(audit_logger)
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=30)
            
            report = reporter.generate_pci_dss_report(start_time, end_time)
            
            # Verify required sections
            assert "standard" in report
            assert "requirements" in report
            assert "compliance_status" in report
            assert report["standard"] == "PCI DSS v4.0"
            
            # Verify specific requirements are checked
            assert "10.2.1" in report["requirements"]
            assert "10.2.4" in report["requirements"]
            assert "10.2.5" in report["requirements"]
    
    def test_hipaa_report_structure(self):
        """Verify HIPAA report contains required sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log events
            audit_logger.log(
                event_type=AuditEventType.LOGIN,
                action="User login",
                user_id="test_user"
            )
            
            # Generate HIPAA report
            reporter = ComplianceReporter(audit_logger)
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=30)
            
            report = reporter.generate_hipaa_report(start_time, end_time)
            
            # Verify required sections
            assert "standard" in report
            assert "requirements" in report
            assert report["standard"] == "HIPAA Security Rule"
            
            # Verify specific requirements
            assert "164.308(a)(1)(ii)(D)" in report["requirements"]
            assert "164.312(b)" in report["requirements"]
    
    def test_sox_report_structure(self):
        """Verify SOX report contains required sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log events
            audit_logger.log(
                event_type=AuditEventType.CONFIGURATION_CHANGE,
                action="Configuration updated",
                user_id="admin_user"
            )
            
            # Generate SOX report
            reporter = ComplianceReporter(audit_logger)
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=30)
            
            report = reporter.generate_sox_report(start_time, end_time)
            
            # Verify required sections
            assert "standard" in report
            assert "requirements" in report
            assert report["standard"] == "Sarbanes-Oxley Act (SOX)"
            
            # Verify ITGC requirements
            assert "ITGC_Access_Controls" in report["requirements"]
            assert "ITGC_Audit_Trails" in report["requirements"]


# Additional unit tests for audit logging
class TestAuditLogging:
    """Unit tests for audit logging functionality."""
    
    def test_audit_database_initialization(self):
        """Verify audit database is initialized correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Verify database file exists
            assert audit_db_path.exists()
            
            # Verify we can log an event
            success = audit_logger.log(
                event_type=AuditEventType.SYSTEM_START,
                action="System initialized"
            )
            assert success is True
    
    def test_event_details_preservation(self):
        """Verify event details are preserved correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log event with details
            details = {
                "key1": "value1",
                "key2": 123,
                "key3": ["item1", "item2"]
            }
            
            audit_logger.log(
                event_type=AuditEventType.DATA_WRITE,
                action="Test action",
                details=details
            )
            
            # Query event
            events = audit_logger.query_events(event_type=AuditEventType.DATA_WRITE)
            
            # Verify details are preserved
            assert len(events) > 0
            assert events[0].details == details
    
    def test_failed_action_tracking(self):
        """Verify failed actions are tracked separately."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_db_path = Path(tmpdir) / "audit.db"
            audit_logger = AuditLogger(audit_db_path)
            
            # Log successful and failed actions
            audit_logger.log(
                event_type=AuditEventType.LOGIN,
                action="Login attempt",
                result="success"
            )
            
            audit_logger.log(
                event_type=AuditEventType.LOGIN_FAILED,
                action="Login attempt",
                result="failure"
            )
            
            # Query failed events
            failed_events = audit_logger.query_events(
                event_type=AuditEventType.LOGIN_FAILED
            )
            
            # Verify failed events are tracked
            assert len(failed_events) > 0
            assert all(e.result == "failure" for e in failed_events)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
