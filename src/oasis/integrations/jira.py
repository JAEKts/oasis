"""
Jira Integration

Integrates OASIS with Jira for issue tracking.
"""

import logging
from typing import Optional, Dict, Any
from uuid import UUID

from ..core.models import Finding, Severity


logger = logging.getLogger(__name__)


class JiraIntegration:
    """
    Integration with Jira for creating and managing security issues.
    """

    def __init__(self, jira_url: str, username: str, api_token: str, project_key: str):
        """
        Initialize Jira integration.

        Args:
            jira_url: Jira instance URL (e.g., https://company.atlassian.net)
            username: Jira username/email
            api_token: Jira API token
            project_key: Jira project key (e.g., SEC)
        """
        self.jira_url = jira_url.rstrip("/")
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
        self._session = None

    def create_issue_from_finding(self, finding: Finding) -> Optional[str]:
        """
        Create a Jira issue from an OASIS finding.

        Args:
            finding: OASIS vulnerability finding

        Returns:
            Jira issue key if successful, None otherwise
        """
        try:
            # Map OASIS severity to Jira priority
            priority_map = {
                Severity.CRITICAL: "Highest",
                Severity.HIGH: "High",
                Severity.MEDIUM: "Medium",
                Severity.LOW: "Low",
                Severity.INFO: "Lowest",
            }

            # Create issue payload
            issue_data = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": finding.title,
                    "description": self._format_description(finding),
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": priority_map.get(finding.severity, "Medium")},
                    "labels": ["security", "oasis", finding.vulnerability_type.value],
                }
            }

            # In a real implementation, this would make an HTTP request to Jira API
            logger.info(f"Would create Jira issue: {finding.title}")

            # Return mock issue key
            return f"{self.project_key}-123"

        except Exception as e:
            logger.error(f"Failed to create Jira issue: {e}")
            return None

    def _format_description(self, finding: Finding) -> str:
        """Format finding as Jira description."""
        description = f"h2. Description\n{finding.description}\n\n"

        if finding.evidence.payload:
            description += f"h2. Proof of Concept\n{{code}}\n{finding.evidence.payload}\n{{code}}\n\n"

        if finding.evidence.location:
            description += f"h2. Location\n{finding.evidence.location}\n\n"

        description += f"h2. Remediation\n{finding.remediation}\n\n"

        if finding.references:
            description += "h2. References\n"
            for ref in finding.references:
                description += f"* {ref}\n"

        description += f"\n_Discovered by OASIS - Finding ID: {finding.id}_"

        return description

    def update_issue_status(self, issue_key: str, status: str) -> bool:
        """
        Update Jira issue status.

        Args:
            issue_key: Jira issue key (e.g., SEC-123)
            status: New status (e.g., "In Progress", "Resolved")

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Would update Jira issue {issue_key} to status: {status}")
            return True
        except Exception as e:
            logger.error(f"Failed to update Jira issue: {e}")
            return False

    def add_comment(self, issue_key: str, comment: str) -> bool:
        """
        Add comment to Jira issue.

        Args:
            issue_key: Jira issue key
            comment: Comment text

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Would add comment to Jira issue {issue_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            return False
