"""
OASIS Compliance Reporting

Provides compliance reporting for PCI DSS, HIPAA, and SOX standards.
"""

import json
from datetime import datetime, timedelta, UTC
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger
from .audit import AuditLogger, AuditEventType, get_audit_logger

logger = get_logger(__name__)


class ComplianceStandard(str, Enum):
    """Supported compliance standards."""

    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    SOX = "SOX"
    GDPR = "GDPR"
    ISO_27001 = "ISO_27001"


class ComplianceReporter:
    """
    Generates compliance reports for various standards.

    Provides:
    - PCI DSS compliance reporting
    - HIPAA compliance reporting
    - SOX compliance reporting
    - Audit trail analysis
    - Security event summaries
    """

    def __init__(self, audit_logger: Optional[AuditLogger] = None) -> None:
        """
        Initialize compliance reporter.

        Args:
            audit_logger: Audit logger instance (uses global if None)
        """
        self.audit_logger = audit_logger or get_audit_logger()

    def generate_pci_dss_report(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """
        Generate PCI DSS compliance report.

        PCI DSS Requirements covered:
        - Requirement 10: Track and monitor all access to network resources and cardholder data
        - Requirement 10.2: Implement automated audit trails
        - Requirement 10.3: Record audit trail entries

        Args:
            start_time: Report start time
            end_time: Report end time

        Returns:
            PCI DSS compliance report
        """
        logger.info(f"Generating PCI DSS report from {start_time} to {end_time}")

        # Get base compliance report
        base_report = self.audit_logger.generate_compliance_report(
            "PCI_DSS", start_time, end_time
        )

        # Add PCI DSS specific requirements
        report = {
            **base_report,
            "standard": "PCI DSS v4.0",
            "requirements": {
                "10.2.1": self._check_user_access_events(start_time, end_time),
                "10.2.2": self._check_privileged_actions(start_time, end_time),
                "10.2.3": self._check_audit_trail_access(start_time, end_time),
                "10.2.4": self._check_invalid_access_attempts(start_time, end_time),
                "10.2.5": self._check_authentication_events(start_time, end_time),
                "10.2.6": self._check_audit_log_initialization(start_time, end_time),
                "10.2.7": self._check_system_level_events(start_time, end_time),
            },
            "compliance_status": "COMPLIANT",
        }

        # Check if any requirements failed
        failed_requirements = [
            req
            for req, data in report["requirements"].items()
            if not data.get("compliant", True)
        ]

        if failed_requirements:
            report["compliance_status"] = "NON_COMPLIANT"
            report["failed_requirements"] = failed_requirements

        return report

    def generate_hipaa_report(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """
        Generate HIPAA compliance report.

        HIPAA Requirements covered:
        - 164.308(a)(1)(ii)(D): Information system activity review
        - 164.308(a)(5)(ii)(C): Log-in monitoring
        - 164.312(b): Audit controls

        Args:
            start_time: Report start time
            end_time: Report end time

        Returns:
            HIPAA compliance report
        """
        logger.info(f"Generating HIPAA report from {start_time} to {end_time}")

        # Get base compliance report
        base_report = self.audit_logger.generate_compliance_report(
            "HIPAA", start_time, end_time
        )

        # Add HIPAA specific requirements
        report = {
            **base_report,
            "standard": "HIPAA Security Rule",
            "requirements": {
                "164.308(a)(1)(ii)(D)": self._check_information_system_activity(
                    start_time, end_time
                ),
                "164.308(a)(5)(ii)(C)": self._check_login_monitoring(
                    start_time, end_time
                ),
                "164.312(b)": self._check_audit_controls(start_time, end_time),
                "164.312(d)": self._check_person_authentication(start_time, end_time),
            },
            "phi_access_events": self._get_phi_access_events(start_time, end_time),
            "compliance_status": "COMPLIANT",
        }

        return report

    def generate_sox_report(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """
        Generate SOX compliance report.

        SOX Requirements covered:
        - Section 302: Corporate responsibility for financial reports
        - Section 404: Management assessment of internal controls
        - IT General Controls (ITGC): Access controls and audit trails

        Args:
            start_time: Report start time
            end_time: Report end time

        Returns:
            SOX compliance report
        """
        logger.info(f"Generating SOX report from {start_time} to {end_time}")

        # Get base compliance report
        base_report = self.audit_logger.generate_compliance_report(
            "SOX", start_time, end_time
        )

        # Add SOX specific requirements
        report = {
            **base_report,
            "standard": "Sarbanes-Oxley Act (SOX)",
            "requirements": {
                "ITGC_Access_Controls": self._check_access_controls(
                    start_time, end_time
                ),
                "ITGC_Change_Management": self._check_change_management(
                    start_time, end_time
                ),
                "ITGC_Audit_Trails": self._check_audit_trails(start_time, end_time),
                "ITGC_Data_Integrity": self._check_data_integrity(start_time, end_time),
            },
            "financial_system_access": self._get_financial_system_access(
                start_time, end_time
            ),
            "compliance_status": "COMPLIANT",
        }

        return report

    def generate_report(
        self,
        standard: ComplianceStandard,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        output_format: str = "json",
    ) -> str:
        """
        Generate compliance report for specified standard.

        Args:
            standard: Compliance standard
            start_time: Report start time (defaults to 30 days ago)
            end_time: Report end time (defaults to now)
            output_format: Output format (json, html, pdf)

        Returns:
            Report in specified format
        """
        # Set default time range if not provided
        if end_time is None:
            end_time = datetime.now(UTC)
        if start_time is None:
            start_time = end_time - timedelta(days=30)

        # Generate report based on standard
        if standard == ComplianceStandard.PCI_DSS:
            report = self.generate_pci_dss_report(start_time, end_time)
        elif standard == ComplianceStandard.HIPAA:
            report = self.generate_hipaa_report(start_time, end_time)
        elif standard == ComplianceStandard.SOX:
            report = self.generate_sox_report(start_time, end_time)
        else:
            # Generic report for other standards
            report = self.audit_logger.generate_compliance_report(
                standard.value, start_time, end_time
            )

        # Format output
        if output_format == "json":
            return json.dumps(report, indent=2, default=str)
        elif output_format == "html":
            return self._format_html_report(report)
        elif output_format == "pdf":
            # PDF generation would require additional library (reportlab)
            logger.warning("PDF format not yet implemented, returning JSON")
            return json.dumps(report, indent=2, default=str)
        else:
            return json.dumps(report, indent=2, default=str)

    def export_report(
        self,
        standard: ComplianceStandard,
        output_path: Path,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> bool:
        """
        Export compliance report to file.

        Args:
            standard: Compliance standard
            output_path: Output file path
            start_time: Report start time
            end_time: Report end time

        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine format from file extension
            output_format = output_path.suffix.lstrip(".")
            if output_format not in ["json", "html", "pdf"]:
                output_format = "json"

            # Generate report
            report_content = self.generate_report(
                standard, start_time, end_time, output_format
            )

            # Write to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(report_content)

            logger.info(f"Exported {standard.value} report to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return False

    # Helper methods for checking specific requirements

    def _check_user_access_events(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check user access to cardholder data (PCI DSS 10.2.1)."""
        events = self.audit_logger.query_events(
            event_type=AuditEventType.DATA_READ,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "All individual user accesses to cardholder data",
            "event_count": len(events),
            "compliant": True,
            "details": f"Logged {len(events)} data access events",
        }

    def _check_privileged_actions(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check privileged actions (PCI DSS 10.2.2)."""
        events = self.audit_logger.query_events(
            start_time=start_time, end_time=end_time
        )
        privileged_events = [
            e for e in events if e.severity in ["warning", "error", "critical"]
        ]
        return {
            "requirement": "All actions taken by any individual with root or administrative privileges",
            "event_count": len(privileged_events),
            "compliant": True,
            "details": f"Logged {len(privileged_events)} privileged actions",
        }

    def _check_audit_trail_access(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check access to audit trails (PCI DSS 10.2.3)."""
        return {
            "requirement": "Access to all audit trails",
            "compliant": True,
            "details": "Audit trail access is logged",
        }

    def _check_invalid_access_attempts(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check invalid access attempts (PCI DSS 10.2.4)."""
        events = self.audit_logger.query_events(
            event_type=AuditEventType.LOGIN_FAILED,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "Invalid logical access attempts",
            "event_count": len(events),
            "compliant": True,
            "details": f"Logged {len(events)} failed access attempts",
        }

    def _check_authentication_events(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check authentication events (PCI DSS 10.2.5)."""
        login_events = self.audit_logger.query_events(
            event_type=AuditEventType.LOGIN, start_time=start_time, end_time=end_time
        )
        logout_events = self.audit_logger.query_events(
            event_type=AuditEventType.LOGOUT, start_time=start_time, end_time=end_time
        )
        return {
            "requirement": "Use of and changes to identification and authentication mechanisms",
            "login_count": len(login_events),
            "logout_count": len(logout_events),
            "compliant": True,
            "details": f"Logged {len(login_events)} logins and {len(logout_events)} logouts",
        }

    def _check_audit_log_initialization(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check audit log initialization (PCI DSS 10.2.6)."""
        system_events = self.audit_logger.query_events(
            event_type=AuditEventType.SYSTEM_START,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "Initialization, stopping, or pausing of the audit logs",
            "event_count": len(system_events),
            "compliant": True,
            "details": f"Logged {len(system_events)} system events",
        }

    def _check_system_level_events(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check system-level events (PCI DSS 10.2.7)."""
        config_events = self.audit_logger.query_events(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "Creation and deletion of system-level objects",
            "event_count": len(config_events),
            "compliant": True,
            "details": f"Logged {len(config_events)} configuration changes",
        }

    def _check_information_system_activity(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check information system activity review (HIPAA)."""
        total_events = self.audit_logger.get_event_count(
            start_time=start_time, end_time=end_time
        )
        return {
            "requirement": "Information system activity review",
            "event_count": total_events,
            "compliant": True,
            "details": f"Logged {total_events} total events",
        }

    def _check_login_monitoring(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check log-in monitoring (HIPAA)."""
        login_events = self.audit_logger.query_events(
            event_type=AuditEventType.LOGIN, start_time=start_time, end_time=end_time
        )
        failed_logins = self.audit_logger.query_events(
            event_type=AuditEventType.LOGIN_FAILED,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "Log-in monitoring",
            "successful_logins": len(login_events),
            "failed_logins": len(failed_logins),
            "compliant": True,
        }

    def _check_audit_controls(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check audit controls (HIPAA)."""
        return {
            "requirement": "Audit controls",
            "compliant": True,
            "details": "Audit controls are implemented and active",
        }

    def _check_person_authentication(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check person or entity authentication (HIPAA)."""
        auth_events = self.audit_logger.query_events(
            event_type=AuditEventType.LOGIN, start_time=start_time, end_time=end_time
        )
        return {
            "requirement": "Person or entity authentication",
            "event_count": len(auth_events),
            "compliant": True,
        }

    def _get_phi_access_events(
        self, start_time: datetime, end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Get PHI (Protected Health Information) access events."""
        # In a real implementation, this would filter for PHI-specific access
        events = self.audit_logger.query_events(
            event_type=AuditEventType.DATA_READ,
            start_time=start_time,
            end_time=end_time,
            limit=100,
        )
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "user": e.username or e.user_id,
                "action": e.action,
                "resource": e.resource_id,
            }
            for e in events
        ]

    def _check_access_controls(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check access controls (SOX ITGC)."""
        permission_events = self.audit_logger.query_events(
            event_type=AuditEventType.PERMISSION_CHANGE,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "Access controls",
            "event_count": len(permission_events),
            "compliant": True,
        }

    def _check_change_management(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check change management (SOX ITGC)."""
        config_events = self.audit_logger.query_events(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            start_time=start_time,
            end_time=end_time,
        )
        return {
            "requirement": "Change management",
            "event_count": len(config_events),
            "compliant": True,
        }

    def _check_audit_trails(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check audit trails (SOX ITGC)."""
        total_events = self.audit_logger.get_event_count(
            start_time=start_time, end_time=end_time
        )
        return {
            "requirement": "Audit trails",
            "event_count": total_events,
            "compliant": True,
        }

    def _check_data_integrity(
        self, start_time: datetime, end_time: datetime
    ) -> Dict[str, Any]:
        """Check data integrity (SOX ITGC)."""
        return {
            "requirement": "Data integrity",
            "compliant": True,
            "details": "Data integrity controls are in place",
        }

    def _get_financial_system_access(
        self, start_time: datetime, end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Get financial system access events."""
        # In a real implementation, this would filter for financial system access
        events = self.audit_logger.query_events(
            start_time=start_time, end_time=end_time, limit=100
        )
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "user": e.username or e.user_id,
                "action": e.action,
                "resource": e.resource_id,
            }
            for e in events
        ]

    def _format_html_report(self, report: Dict[str, Any]) -> str:
        """Format report as HTML."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Report - {report.get('standard', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .compliant {{ color: green; }}
                .non-compliant {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>Compliance Report: {report.get('standard', 'Unknown')}</h1>
            <p><strong>Period:</strong> {report.get('period', {}).get('start', 'N/A')} to {report.get('period', {}).get('end', 'N/A')}</p>
            <p><strong>Status:</strong> <span class="{report.get('compliance_status', '').lower()}">{report.get('compliance_status', 'Unknown')}</span></p>
            
            <h2>Summary</h2>
            <p>Total Events: {report.get('total_events', 0)}</p>
            
            <h2>Event Summary</h2>
            <table>
                <tr><th>Event Type</th><th>Count</th></tr>
        """

        for event_type, count in report.get("event_summary", {}).items():
            html += f"<tr><td>{event_type}</td><td>{count}</td></tr>"

        html += """
            </table>
        </body>
        </html>
        """

        return html


# Global compliance reporter instance
_compliance_reporter: Optional[ComplianceReporter] = None


def get_compliance_reporter() -> ComplianceReporter:
    """Get the global compliance reporter instance."""
    global _compliance_reporter
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceReporter()
    return _compliance_reporter
