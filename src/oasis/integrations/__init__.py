"""
OASIS External Tool Integrations

Provides integrations with issue trackers, CI/CD pipelines, and other tools.
"""

from .jira import JiraIntegration
from .github import GitHubIntegration
from .webhook import WebhookIntegration

__all__ = ["JiraIntegration", "GitHubIntegration", "WebhookIntegration"]
