"""
Security Update and Vulnerability Disclosure

Handles vulnerability disclosure process and security update pipeline.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4

import aiohttp

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DisclosureStatus(Enum):
    """Vulnerability disclosure status"""

    REPORTED = "reported"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    FIXED = "fixed"
    DISCLOSED = "disclosed"
    REJECTED = "rejected"


@dataclass
class VulnerabilityReport:
    """Vulnerability report information"""

    id: UUID
    title: str
    description: str
    severity: VulnerabilitySeverity
    reporter: str
    reporter_email: str
    affected_versions: List[str]
    reported_date: datetime
    status: DisclosureStatus
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    fixed_version: Optional[str] = None
    disclosure_date: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["id"] = str(self.id)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        data["reported_date"] = self.reported_date.isoformat()
        if self.disclosure_date:
            data["disclosure_date"] = self.disclosure_date.isoformat()
        return data


@dataclass
class SecurityUpdate:
    """Security update information"""

    id: UUID
    version: str
    release_date: datetime
    vulnerabilities_fixed: List[UUID]
    description: str
    critical: bool
    download_url: str
    signature_url: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "version": self.version,
            "release_date": self.release_date.isoformat(),
            "vulnerabilities_fixed": [str(v) for v in self.vulnerabilities_fixed],
            "description": self.description,
            "critical": self.critical,
            "download_url": self.download_url,
            "signature_url": self.signature_url,
        }


class VulnerabilityDisclosure:
    """Manages vulnerability disclosure process"""

    def __init__(
        self,
        disclosure_email: str,
        disclosure_url: str,
        storage_path: Optional[Path] = None,
    ):
        """
        Initialize vulnerability disclosure manager

        Args:
            disclosure_email: Email for vulnerability reports
            disclosure_url: URL for vulnerability disclosure page
            storage_path: Path to store vulnerability reports
        """
        self.disclosure_email = disclosure_email
        self.disclosure_url = disclosure_url
        self.storage_path = storage_path or Path.home() / ".oasis" / "vulnerabilities"
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.reports: Dict[UUID, VulnerabilityReport] = {}
        self._load_reports()

    def _load_reports(self) -> None:
        """Load existing vulnerability reports"""
        reports_file = self.storage_path / "reports.json"
        if reports_file.exists():
            try:
                with open(reports_file, "r") as f:
                    data = json.load(f)
                    for report_data in data:
                        report = VulnerabilityReport(
                            id=UUID(report_data["id"]),
                            title=report_data["title"],
                            description=report_data["description"],
                            severity=VulnerabilitySeverity(report_data["severity"]),
                            reporter=report_data["reporter"],
                            reporter_email=report_data["reporter_email"],
                            affected_versions=report_data["affected_versions"],
                            reported_date=datetime.fromisoformat(
                                report_data["reported_date"]
                            ),
                            status=DisclosureStatus(report_data["status"]),
                            cve_id=report_data.get("cve_id"),
                            cvss_score=report_data.get("cvss_score"),
                            proof_of_concept=report_data.get("proof_of_concept"),
                            remediation=report_data.get("remediation"),
                            fixed_version=report_data.get("fixed_version"),
                            disclosure_date=(
                                datetime.fromisoformat(report_data["disclosure_date"])
                                if report_data.get("disclosure_date")
                                else None
                            ),
                        )
                        self.reports[report.id] = report
                logger.info(f"Loaded {len(self.reports)} vulnerability reports")
            except Exception as e:
                logger.error(f"Failed to load vulnerability reports: {e}")

    def _save_reports(self) -> None:
        """Save vulnerability reports to disk"""
        reports_file = self.storage_path / "reports.json"
        try:
            with open(reports_file, "w") as f:
                data = [report.to_dict() for report in self.reports.values()]
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save vulnerability reports: {e}")

    def submit_report(
        self,
        title: str,
        description: str,
        severity: VulnerabilitySeverity,
        reporter: str,
        reporter_email: str,
        affected_versions: List[str],
        proof_of_concept: Optional[str] = None,
    ) -> VulnerabilityReport:
        """
        Submit a new vulnerability report

        Args:
            title: Vulnerability title
            description: Detailed description
            severity: Severity level
            reporter: Reporter name
            reporter_email: Reporter email
            affected_versions: List of affected versions
            proof_of_concept: Optional PoC code/steps

        Returns:
            Created vulnerability report
        """
        report = VulnerabilityReport(
            id=uuid4(),
            title=title,
            description=description,
            severity=severity,
            reporter=reporter,
            reporter_email=reporter_email,
            affected_versions=affected_versions,
            reported_date=datetime.now(),
            status=DisclosureStatus.REPORTED,
            proof_of_concept=proof_of_concept,
        )

        self.reports[report.id] = report
        self._save_reports()

        logger.info(f"Vulnerability report submitted: {report.id} - {title}")
        return report

    def update_status(
        self,
        report_id: UUID,
        status: DisclosureStatus,
        remediation: Optional[str] = None,
        fixed_version: Optional[str] = None,
    ) -> Optional[VulnerabilityReport]:
        """
        Update vulnerability report status

        Args:
            report_id: Report ID
            status: New status
            remediation: Remediation information
            fixed_version: Version where vulnerability is fixed

        Returns:
            Updated report, or None if not found
        """
        report = self.reports.get(report_id)
        if not report:
            logger.error(f"Vulnerability report not found: {report_id}")
            return None

        report.status = status
        if remediation:
            report.remediation = remediation
        if fixed_version:
            report.fixed_version = fixed_version

        self._save_reports()
        logger.info(
            f"Updated vulnerability report {report_id} to status {status.value}"
        )
        return report

    def schedule_disclosure(
        self, report_id: UUID, disclosure_date: Optional[datetime] = None
    ) -> Optional[VulnerabilityReport]:
        """
        Schedule public disclosure of vulnerability

        Args:
            report_id: Report ID
            disclosure_date: Date to disclose (default: 90 days from report)

        Returns:
            Updated report, or None if not found
        """
        report = self.reports.get(report_id)
        if not report:
            logger.error(f"Vulnerability report not found: {report_id}")
            return None

        if not disclosure_date:
            # Default: 90 days from report date
            disclosure_date = report.reported_date + timedelta(days=90)

        report.disclosure_date = disclosure_date
        self._save_reports()

        logger.info(f"Scheduled disclosure for {report_id} on {disclosure_date}")
        return report

    def get_pending_disclosures(self) -> List[VulnerabilityReport]:
        """
        Get vulnerabilities pending disclosure

        Returns:
            List of reports ready for disclosure
        """
        now = datetime.now()
        return [
            report
            for report in self.reports.values()
            if report.disclosure_date
            and report.disclosure_date <= now
            and report.status != DisclosureStatus.DISCLOSED
        ]

    def get_critical_vulnerabilities(self) -> List[VulnerabilityReport]:
        """
        Get critical vulnerabilities

        Returns:
            List of critical vulnerability reports
        """
        return [
            report
            for report in self.reports.values()
            if report.severity == VulnerabilitySeverity.CRITICAL
            and report.status
            not in [DisclosureStatus.FIXED, DisclosureStatus.DISCLOSED]
        ]


class SecurityUpdatePipeline:
    """Manages security update pipeline"""

    def __init__(
        self,
        disclosure_manager: VulnerabilityDisclosure,
        build_server_url: str,
        storage_path: Optional[Path] = None,
    ):
        """
        Initialize security update pipeline

        Args:
            disclosure_manager: Vulnerability disclosure manager
            build_server_url: URL of build server
            storage_path: Path to store security updates
        """
        self.disclosure_manager = disclosure_manager
        self.build_server_url = build_server_url
        self.storage_path = storage_path or Path.home() / ".oasis" / "security_updates"
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.updates: Dict[UUID, SecurityUpdate] = {}
        self._load_updates()

    def _load_updates(self) -> None:
        """Load existing security updates"""
        updates_file = self.storage_path / "updates.json"
        if updates_file.exists():
            try:
                with open(updates_file, "r") as f:
                    data = json.load(f)
                    for update_data in data:
                        update = SecurityUpdate(
                            id=UUID(update_data["id"]),
                            version=update_data["version"],
                            release_date=datetime.fromisoformat(
                                update_data["release_date"]
                            ),
                            vulnerabilities_fixed=[
                                UUID(v) for v in update_data["vulnerabilities_fixed"]
                            ],
                            description=update_data["description"],
                            critical=update_data["critical"],
                            download_url=update_data["download_url"],
                            signature_url=update_data["signature_url"],
                        )
                        self.updates[update.id] = update
                logger.info(f"Loaded {len(self.updates)} security updates")
            except Exception as e:
                logger.error(f"Failed to load security updates: {e}")

    def _save_updates(self) -> None:
        """Save security updates to disk"""
        updates_file = self.storage_path / "updates.json"
        try:
            with open(updates_file, "w") as f:
                data = [update.to_dict() for update in self.updates.values()]
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save security updates: {e}")

    async def create_security_update(
        self, version: str, vulnerability_ids: List[UUID], description: str
    ) -> Optional[SecurityUpdate]:
        """
        Create a security update

        Args:
            version: Version number for update
            vulnerability_ids: List of vulnerability IDs being fixed
            description: Update description

        Returns:
            Created security update, or None on failure
        """
        try:
            # Check if all vulnerabilities exist
            for vuln_id in vulnerability_ids:
                if vuln_id not in self.disclosure_manager.reports:
                    logger.error(f"Vulnerability not found: {vuln_id}")
                    return None

            # Determine if update is critical
            critical = any(
                self.disclosure_manager.reports[vuln_id].severity
                == VulnerabilitySeverity.CRITICAL
                for vuln_id in vulnerability_ids
            )

            # Trigger build process
            build_result = await self._trigger_build(version, vulnerability_ids)
            if not build_result:
                logger.error("Build process failed")
                return None

            # Create security update
            update = SecurityUpdate(
                id=uuid4(),
                version=version,
                release_date=datetime.now(),
                vulnerabilities_fixed=vulnerability_ids,
                description=description,
                critical=critical,
                download_url=build_result["download_url"],
                signature_url=build_result["signature_url"],
            )

            self.updates[update.id] = update
            self._save_updates()

            # Update vulnerability statuses
            for vuln_id in vulnerability_ids:
                self.disclosure_manager.update_status(
                    vuln_id, DisclosureStatus.FIXED, fixed_version=version
                )

            logger.info(
                f"Created security update {version} fixing {len(vulnerability_ids)} vulnerabilities"
            )
            return update

        except Exception as e:
            logger.error(f"Failed to create security update: {e}")
            return None

    async def _trigger_build(
        self, version: str, vulnerability_ids: List[UUID]
    ) -> Optional[Dict[str, str]]:
        """
        Trigger build process on build server

        Args:
            version: Version to build
            vulnerability_ids: Vulnerabilities being fixed

        Returns:
            Build result with download URLs, or None on failure
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.build_server_url}/api/build",
                    json={
                        "version": version,
                        "vulnerabilities": [str(v) for v in vulnerability_ids],
                        "security_update": True,
                    },
                ) as response:
                    if response.status != 200:
                        logger.error(f"Build trigger failed: HTTP {response.status}")
                        return None

                    result = await response.json()
                    return {
                        "download_url": result["download_url"],
                        "signature_url": result["signature_url"],
                    }

        except Exception as e:
            logger.error(f"Build trigger failed: {e}")
            return None

    def get_updates_for_version(self, current_version: str) -> List[SecurityUpdate]:
        """
        Get security updates applicable to a version

        Args:
            current_version: Current software version

        Returns:
            List of applicable security updates
        """
        # Simple version comparison (should use packaging.version in production)
        current_parts = [int(x) for x in current_version.split(".")]

        applicable_updates = []
        for update in self.updates.values():
            update_parts = [int(x) for x in update.version.split(".")]
            if update_parts > current_parts:
                applicable_updates.append(update)

        return sorted(applicable_updates, key=lambda u: u.release_date)
