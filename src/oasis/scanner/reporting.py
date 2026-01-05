"""
Scan Result Management and Reporting

Provides functionality for managing findings, generating reports, and filtering results.
"""

import uuid
from typing import List, Dict, Optional, Any
from datetime import datetime, UTC
from enum import Enum

from ..core.models import Finding, Severity, Confidence, VulnerabilityType
from .engine import ScanSession


class ReportFormat(str, Enum):
    """Supported report formats."""

    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    XML = "xml"
    CSV = "csv"
    MARKDOWN = "markdown"


class FindingFilter:
    """Filter for findings based on various criteria."""

    def __init__(
        self,
        severities: Optional[List[Severity]] = None,
        confidence_levels: Optional[List[Confidence]] = None,
        vulnerability_types: Optional[List[VulnerabilityType]] = None,
        include_false_positives: bool = False,
    ):
        self.severities = severities or []
        self.confidence_levels = confidence_levels or []
        self.vulnerability_types = vulnerability_types or []
        self.include_false_positives = include_false_positives

    def matches(self, finding: Finding, is_false_positive: bool = False) -> bool:
        """Check if a finding matches the filter criteria."""
        # Check false positive status
        if not self.include_false_positives and is_false_positive:
            return False

        # Check severity
        if self.severities and finding.severity not in self.severities:
            return False

        # Check confidence
        if self.confidence_levels and finding.confidence not in self.confidence_levels:
            return False

        # Check vulnerability type
        if (
            self.vulnerability_types
            and finding.vulnerability_type not in self.vulnerability_types
        ):
            return False

        return True


class FindingManager:
    """
    Manages scan findings including categorization, filtering, and false positive tracking.
    """

    def __init__(self):
        self._findings: Dict[uuid.UUID, Finding] = {}
        self._false_positives: set[uuid.UUID] = set()
        self._finding_notes: Dict[uuid.UUID, str] = {}

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the manager."""
        self._findings[finding.id] = finding

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the manager."""
        for finding in findings:
            self.add_finding(finding)

    def get_finding(self, finding_id: uuid.UUID) -> Optional[Finding]:
        """Get a finding by ID."""
        return self._findings.get(finding_id)

    def mark_false_positive(
        self, finding_id: uuid.UUID, note: Optional[str] = None
    ) -> bool:
        """
        Mark a finding as a false positive.

        Args:
            finding_id: ID of the finding
            note: Optional note explaining why it's a false positive

        Returns:
            True if marked successfully, False if finding not found
        """
        if finding_id not in self._findings:
            return False

        self._false_positives.add(finding_id)
        if note:
            self._finding_notes[finding_id] = note

        return True

    def unmark_false_positive(self, finding_id: uuid.UUID) -> bool:
        """
        Remove false positive marking from a finding.

        Args:
            finding_id: ID of the finding

        Returns:
            True if unmarked successfully, False if finding not found
        """
        if finding_id not in self._findings:
            return False

        self._false_positives.discard(finding_id)
        return True

    def is_false_positive(self, finding_id: uuid.UUID) -> bool:
        """Check if a finding is marked as a false positive."""
        return finding_id in self._false_positives

    def add_note(self, finding_id: uuid.UUID, note: str) -> bool:
        """
        Add a note to a finding.

        Args:
            finding_id: ID of the finding
            note: Note text

        Returns:
            True if added successfully, False if finding not found
        """
        if finding_id not in self._findings:
            return False

        self._finding_notes[finding_id] = note
        return True

    def get_note(self, finding_id: uuid.UUID) -> Optional[str]:
        """Get the note for a finding."""
        return self._finding_notes.get(finding_id)

    def filter_findings(self, filter_criteria: FindingFilter) -> List[Finding]:
        """
        Filter findings based on criteria.

        Args:
            filter_criteria: Filter criteria

        Returns:
            List of findings matching the criteria
        """
        filtered = []

        for finding_id, finding in self._findings.items():
            is_fp = self.is_false_positive(finding_id)
            if filter_criteria.matches(finding, is_fp):
                filtered.append(finding)

        return filtered

    def get_all_findings(self, include_false_positives: bool = False) -> List[Finding]:
        """
        Get all findings.

        Args:
            include_false_positives: Whether to include false positives

        Returns:
            List of all findings
        """
        if include_false_positives:
            return list(self._findings.values())

        return [
            finding
            for finding_id, finding in self._findings.items()
            if finding_id not in self._false_positives
        ]

    def get_findings_by_severity(
        self, severity: Severity, include_false_positives: bool = False
    ) -> List[Finding]:
        """Get findings filtered by severity."""
        filter_criteria = FindingFilter(
            severities=[severity], include_false_positives=include_false_positives
        )
        return self.filter_findings(filter_criteria)

    def get_findings_by_type(
        self, vuln_type: VulnerabilityType, include_false_positives: bool = False
    ) -> List[Finding]:
        """Get findings filtered by vulnerability type."""
        filter_criteria = FindingFilter(
            vulnerability_types=[vuln_type],
            include_false_positives=include_false_positives,
        )
        return self.filter_findings(filter_criteria)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about findings.

        Returns:
            Dictionary with statistics
        """
        total_findings = len(self._findings)
        false_positives = len(self._false_positives)

        # Count by severity
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }

        # Count by vulnerability type
        type_counts: Dict[VulnerabilityType, int] = {}

        # Count by confidence
        confidence_counts = {
            Confidence.CERTAIN: 0,
            Confidence.FIRM: 0,
            Confidence.TENTATIVE: 0,
        }

        for finding_id, finding in self._findings.items():
            if finding_id not in self._false_positives:
                severity_counts[finding.severity] += 1
                confidence_counts[finding.confidence] += 1

                if finding.vulnerability_type not in type_counts:
                    type_counts[finding.vulnerability_type] = 0
                type_counts[finding.vulnerability_type] += 1

        return {
            "total_findings": total_findings,
            "false_positives": false_positives,
            "valid_findings": total_findings - false_positives,
            "by_severity": {k.value: v for k, v in severity_counts.items()},
            "by_type": {k.value: v for k, v in type_counts.items()},
            "by_confidence": {k.value: v for k, v in confidence_counts.items()},
        }


class ReportGenerator:
    """
    Generates vulnerability reports in various formats.
    """

    def __init__(self, finding_manager: FindingManager):
        self.finding_manager = finding_manager

    def generate_report(
        self,
        session: ScanSession,
        format: ReportFormat = ReportFormat.JSON,
        include_false_positives: bool = False,
        filter_criteria: Optional[FindingFilter] = None,
    ) -> str:
        """
        Generate a vulnerability report.

        Args:
            session: Scan session to report on
            format: Report format
            include_false_positives: Whether to include false positives
            filter_criteria: Optional filter criteria

        Returns:
            Report content as string
        """
        if format == ReportFormat.JSON:
            return self._generate_json_report(
                session, include_false_positives, filter_criteria
            )
        elif format == ReportFormat.HTML:
            return self._generate_html_report(
                session, include_false_positives, filter_criteria
            )
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report(
                session, include_false_positives, filter_criteria
            )
        elif format == ReportFormat.CSV:
            return self._generate_csv_report(
                session, include_false_positives, filter_criteria
            )
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _get_filtered_findings(
        self,
        session: ScanSession,
        include_false_positives: bool,
        filter_criteria: Optional[FindingFilter],
    ) -> List[Finding]:
        """Get findings based on filter criteria."""
        if filter_criteria:
            return self.finding_manager.filter_findings(filter_criteria)
        else:
            return self.finding_manager.get_all_findings(include_false_positives)

    def _generate_json_report(
        self,
        session: ScanSession,
        include_false_positives: bool,
        filter_criteria: Optional[FindingFilter],
    ) -> str:
        """Generate JSON report."""
        import json
        from ..core.models import serialize_model

        findings = self._get_filtered_findings(
            session, include_false_positives, filter_criteria
        )

        report = {
            "scan_session": serialize_model(session),
            "findings": [serialize_model(f) for f in findings],
            "statistics": self.finding_manager.get_statistics(),
            "generated_at": datetime.now(UTC).isoformat(),
        }

        return json.dumps(report, indent=2, default=str)

    def _generate_markdown_report(
        self,
        session: ScanSession,
        include_false_positives: bool,
        filter_criteria: Optional[FindingFilter],
    ) -> str:
        """Generate Markdown report."""
        findings = self._get_filtered_findings(
            session, include_false_positives, filter_criteria
        )
        stats = self.finding_manager.get_statistics()

        lines = [
            f"# Vulnerability Scan Report",
            f"",
            f"**Target:** {session.target.base_url}",
            f"**Scan Date:** {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Status:** {session.status.value}",
            f"",
            f"## Summary",
            f"",
            f"- Total Findings: {stats['valid_findings']}",
            f"- Critical: {stats['by_severity']['critical']}",
            f"- High: {stats['by_severity']['high']}",
            f"- Medium: {stats['by_severity']['medium']}",
            f"- Low: {stats['by_severity']['low']}",
            f"- Info: {stats['by_severity']['info']}",
            f"",
            f"## Findings",
            f"",
        ]

        # Group findings by severity
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            severity_findings = [f for f in findings if f.severity == severity]

            if severity_findings:
                lines.append(f"### {severity.value.upper()} Severity")
                lines.append("")

                for finding in severity_findings:
                    lines.append(f"#### {finding.title}")
                    lines.append(f"")
                    lines.append(f"**Type:** {finding.vulnerability_type.value}")
                    lines.append(f"**Confidence:** {finding.confidence.value}")
                    lines.append(f"")
                    lines.append(f"**Description:**")
                    lines.append(f"{finding.description}")
                    lines.append(f"")
                    lines.append(f"**Remediation:**")
                    lines.append(f"{finding.remediation}")
                    lines.append(f"")

                    if finding.evidence.proof_of_concept:
                        lines.append(f"**Proof of Concept:**")
                        lines.append(f"```")
                        lines.append(f"{finding.evidence.proof_of_concept}")
                        lines.append(f"```")
                        lines.append(f"")

                    lines.append("---")
                    lines.append("")

        return "\n".join(lines)

    def _generate_html_report(
        self,
        session: ScanSession,
        include_false_positives: bool,
        filter_criteria: Optional[FindingFilter],
    ) -> str:
        """Generate HTML report."""
        # Simplified HTML report
        markdown_report = self._generate_markdown_report(
            session, include_false_positives, filter_criteria
        )

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>OASIS Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        h3 {{ color: #888; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .info {{ color: #1976d2; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 4px; }}
    </style>
</head>
<body>
    <pre>{markdown_report}</pre>
</body>
</html>
"""
        return html

    def _generate_csv_report(
        self,
        session: ScanSession,
        include_false_positives: bool,
        filter_criteria: Optional[FindingFilter],
    ) -> str:
        """Generate CSV report."""
        import csv
        import io

        findings = self._get_filtered_findings(
            session, include_false_positives, filter_criteria
        )

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "ID",
                "Title",
                "Severity",
                "Confidence",
                "Type",
                "Description",
                "URL",
                "Remediation",
            ]
        )

        # Write findings
        for finding in findings:
            writer.writerow(
                [
                    str(finding.id),
                    finding.title,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.vulnerability_type.value,
                    finding.description,
                    finding.evidence.request.url if finding.evidence.request else "",
                    finding.remediation,
                ]
            )

        return output.getvalue()
