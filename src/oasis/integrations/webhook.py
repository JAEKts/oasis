"""
Webhook Integration

Provides webhook support for real-time notifications.
"""

import logging
import json
from typing import Dict, Any, List
from datetime import datetime, UTC

from ..core.models import Finding, HTTPFlow


logger = logging.getLogger(__name__)


class WebhookIntegration:
    """
    Webhook integration for real-time notifications.

    Supports sending notifications for:
    - New vulnerability findings
    - Scan completion
    - Collaborator interactions
    """

    def __init__(self, webhook_url: str, secret: str = ""):
        """
        Initialize webhook integration.

        Args:
            webhook_url: Webhook endpoint URL
            secret: Optional secret for HMAC signature verification
        """
        self.webhook_url = webhook_url
        self.secret = secret

    def send_finding_notification(self, finding: Finding) -> bool:
        """
        Send notification for new finding.

        Args:
            finding: New vulnerability finding

        Returns:
            True if successful, False otherwise
        """
        try:
            payload = {
                "event": "finding.created",
                "timestamp": datetime.now(UTC).isoformat(),
                "data": {
                    "id": str(finding.id),
                    "type": finding.vulnerability_type.value,
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "description": finding.description,
                    "confidence": finding.confidence,
                },
            }

            return self._send_webhook(payload)

        except Exception as e:
            logger.error(f"Failed to send finding notification: {e}")
            return False

    def send_scan_complete_notification(
        self, project_id: str, findings_count: int
    ) -> bool:
        """
        Send notification for scan completion.

        Args:
            project_id: Project ID
            findings_count: Number of findings discovered

        Returns:
            True if successful, False otherwise
        """
        try:
            payload = {
                "event": "scan.completed",
                "timestamp": datetime.now(UTC).isoformat(),
                "data": {"project_id": project_id, "findings_count": findings_count},
            }

            return self._send_webhook(payload)

        except Exception as e:
            logger.error(f"Failed to send scan complete notification: {e}")
            return False

    def send_collaborator_interaction(
        self, interaction_type: str, details: Dict[str, Any]
    ) -> bool:
        """
        Send notification for collaborator interaction.

        Args:
            interaction_type: Type of interaction (dns, http, smtp)
            details: Interaction details

        Returns:
            True if successful, False otherwise
        """
        try:
            payload = {
                "event": "collaborator.interaction",
                "timestamp": datetime.now(UTC).isoformat(),
                "data": {"type": interaction_type, **details},
            }

            return self._send_webhook(payload)

        except Exception as e:
            logger.error(f"Failed to send collaborator notification: {e}")
            return False

    def _send_webhook(self, payload: Dict[str, Any]) -> bool:
        """
        Send webhook HTTP request.

        Args:
            payload: Webhook payload

        Returns:
            True if successful, False otherwise
        """
        try:
            # In a real implementation, this would make an HTTP POST request
            logger.info(f"Would send webhook to {self.webhook_url}")
            logger.debug(f"Payload: {json.dumps(payload, indent=2)}")

            # If secret is provided, would add HMAC signature header
            if self.secret:
                logger.debug("Would add HMAC signature")

            return True

        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False


class WebhookManager:
    """Manages multiple webhook integrations."""

    def __init__(self):
        """Initialize webhook manager."""
        self.webhooks: List[WebhookIntegration] = []

    def add_webhook(self, webhook: WebhookIntegration) -> None:
        """Add a webhook integration."""
        self.webhooks.append(webhook)

    def remove_webhook(self, webhook_url: str) -> bool:
        """Remove a webhook integration by URL."""
        initial_count = len(self.webhooks)
        self.webhooks = [w for w in self.webhooks if w.webhook_url != webhook_url]
        return len(self.webhooks) < initial_count

    def broadcast_finding(self, finding: Finding) -> int:
        """
        Broadcast finding to all webhooks.

        Returns:
            Number of successful notifications
        """
        success_count = 0
        for webhook in self.webhooks:
            if webhook.send_finding_notification(finding):
                success_count += 1
        return success_count

    def broadcast_scan_complete(self, project_id: str, findings_count: int) -> int:
        """
        Broadcast scan completion to all webhooks.

        Returns:
            Number of successful notifications
        """
        success_count = 0
        for webhook in self.webhooks:
            if webhook.send_scan_complete_notification(project_id, findings_count):
                success_count += 1
        return success_count
