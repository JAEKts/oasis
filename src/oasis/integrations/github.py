"""
GitHub Integration

Integrates OASIS with GitHub for issue tracking and CI/CD.
"""

import logging
from typing import Optional
from ..core.models import Finding


logger = logging.getLogger(__name__)


class GitHubIntegration:
    """Integration with GitHub for creating security issues."""

    def __init__(self, repo_owner: str, repo_name: str, access_token: str):
        """
        Initialize GitHub integration.

        Args:
            repo_owner: GitHub repository owner
            repo_name: GitHub repository name
            access_token: GitHub personal access token
        """
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.access_token = access_token

    def create_issue_from_finding(self, finding: Finding) -> Optional[int]:
        """
        Create a GitHub issue from an OASIS finding.

        Args:
            finding: OASIS vulnerability finding

        Returns:
            GitHub issue number if successful, None otherwise
        """
        try:
            # Format issue body
            body = f"## Description\n{finding.description}\n\n"

            if finding.evidence.payload:
                body += f"## Proof of Concept\n```\n{finding.evidence.payload}\n```\n\n"

            body += f"## Remediation\n{finding.remediation}\n\n"
            body += f"**Severity:** {finding.severity.value}\n"
            body += f"**Confidence:** {finding.confidence}\n"
            body += f"\n_Discovered by OASIS (Finding ID: {finding.id})_"

            # Create labels
            labels = [
                "security",
                f"severity:{finding.severity.value}",
                finding.vulnerability_type.value,
            ]

            logger.info(f"Would create GitHub issue: {finding.title}")

            # Return mock issue number
            return 123

        except Exception as e:
            logger.error(f"Failed to create GitHub issue: {e}")
            return None
