"""
Forensic Analysis for Collaborator Interactions

Provides detailed analysis and reporting of out-of-band interactions.
"""

from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional, Set
from collections import defaultdict
import uuid

from .models import Interaction, Protocol, CollaboratorPayload


class ForensicAnalyzer:
    """
    Analyzes interactions for forensic information and patterns.
    """

    def __init__(self):
        """Initialize the forensic analyzer."""
        pass

    def analyze_interaction(self, interaction: Interaction) -> Dict:
        """
        Perform detailed forensic analysis on an interaction.

        Args:
            interaction: Interaction to analyze

        Returns:
            Dictionary containing forensic analysis results
        """
        analysis = {
            "interaction_id": str(interaction.id),
            "payload_id": str(interaction.payload_id),
            "protocol": interaction.protocol.value,
            "timestamp": interaction.timestamp.isoformat(),
            "source_ip": interaction.source_ip,
            "forensic_details": {},
        }

        # Protocol-specific analysis
        if interaction.protocol == Protocol.DNS:
            analysis["forensic_details"] = self._analyze_dns(interaction)
        elif interaction.protocol in [Protocol.HTTP, Protocol.HTTPS]:
            analysis["forensic_details"] = self._analyze_http(interaction)
        elif interaction.protocol == Protocol.SMTP:
            analysis["forensic_details"] = self._analyze_smtp(interaction)

        return analysis

    def _analyze_dns(self, interaction: Interaction) -> Dict:
        """Analyze DNS interaction."""
        if not interaction.dns_query:
            return {}

        return {
            "query_name": interaction.dns_query.query_name,
            "query_type": interaction.dns_query.query_type,
            "source_ip": interaction.dns_query.source_ip,
            "timestamp": interaction.dns_query.timestamp.isoformat(),
            "analysis": {
                "is_recursive": "." in interaction.dns_query.query_name,
                "subdomain_depth": interaction.dns_query.query_name.count("."),
            },
        }

    def _analyze_http(self, interaction: Interaction) -> Dict:
        """Analyze HTTP interaction."""
        if not interaction.http_request:
            return {}

        analysis = {
            "method": interaction.http_request.get("method"),
            "path": interaction.http_request.get("path"),
            "host": interaction.http_request.get("host"),
            "user_agent": interaction.user_agent,
            "headers": interaction.headers,
        }

        # Analyze user agent
        if interaction.user_agent:
            analysis["user_agent_analysis"] = self._analyze_user_agent(
                interaction.user_agent
            )

        # Analyze headers for interesting patterns
        analysis["header_analysis"] = self._analyze_headers(interaction.headers)

        return analysis

    def _analyze_smtp(self, interaction: Interaction) -> Dict:
        """Analyze SMTP interaction."""
        if not interaction.smtp_message:
            return {}

        return {
            "from_address": interaction.smtp_message.from_address,
            "to_address": interaction.smtp_message.to_address,
            "subject": interaction.smtp_message.subject,
            "timestamp": interaction.smtp_message.timestamp.isoformat(),
            "analysis": {
                "from_domain": (
                    interaction.smtp_message.from_address.split("@")[1]
                    if "@" in interaction.smtp_message.from_address
                    else None
                ),
                "to_domain": (
                    interaction.smtp_message.to_address.split("@")[1]
                    if "@" in interaction.smtp_message.to_address
                    else None
                ),
            },
        }

    def _analyze_user_agent(self, user_agent: str) -> Dict:
        """Analyze user agent string."""
        analysis = {
            "raw": user_agent,
            "is_browser": any(
                browser in user_agent.lower()
                for browser in ["mozilla", "chrome", "safari", "firefox", "edge"]
            ),
            "is_bot": any(
                bot in user_agent.lower()
                for bot in ["bot", "crawler", "spider", "scraper"]
            ),
            "is_curl": "curl" in user_agent.lower(),
            "is_python": "python" in user_agent.lower(),
        }
        return analysis

    def _analyze_headers(self, headers: Dict[str, str]) -> Dict:
        """Analyze HTTP headers."""
        analysis = {
            "has_referer": "Referer" in headers or "referer" in headers,
            "has_origin": "Origin" in headers or "origin" in headers,
            "has_authorization": "Authorization" in headers
            or "authorization" in headers,
            "header_count": len(headers),
        }
        return analysis

    def analyze_interaction_timeline(self, interactions: List[Interaction]) -> Dict:
        """
        Analyze timeline of interactions.

        Args:
            interactions: List of interactions to analyze

        Returns:
            Timeline analysis results
        """
        if not interactions:
            return {"error": "No interactions to analyze"}

        # Sort by timestamp
        sorted_interactions = sorted(interactions, key=lambda x: x.timestamp)

        first = sorted_interactions[0]
        last = sorted_interactions[-1]

        # Calculate time span
        time_span = last.timestamp - first.timestamp

        # Group by protocol
        by_protocol = defaultdict(int)
        for interaction in interactions:
            by_protocol[interaction.protocol.value] += 1

        # Group by source IP
        by_source = defaultdict(int)
        for interaction in interactions:
            by_source[interaction.source_ip] += 1

        return {
            "total_interactions": len(interactions),
            "first_interaction": first.timestamp.isoformat(),
            "last_interaction": last.timestamp.isoformat(),
            "time_span_seconds": time_span.total_seconds(),
            "by_protocol": dict(by_protocol),
            "by_source_ip": dict(by_source),
            "unique_sources": len(by_source),
        }

    def detect_patterns(self, interactions: List[Interaction]) -> List[Dict]:
        """
        Detect patterns in interactions that may indicate specific vulnerabilities.

        Args:
            interactions: List of interactions to analyze

        Returns:
            List of detected patterns
        """
        patterns = []

        # Check for rapid repeated interactions (possible SSRF)
        if len(interactions) > 1:
            sorted_interactions = sorted(interactions, key=lambda x: x.timestamp)
            for i in range(len(sorted_interactions) - 1):
                time_diff = (
                    sorted_interactions[i + 1].timestamp
                    - sorted_interactions[i].timestamp
                ).total_seconds()
                if time_diff < 1.0:  # Less than 1 second apart
                    patterns.append(
                        {
                            "type": "rapid_repeated_interaction",
                            "description": "Multiple interactions within 1 second",
                            "possible_vulnerability": "SSRF or automated scanning",
                            "time_difference_seconds": time_diff,
                        }
                    )
                    break

        # Check for DNS exfiltration patterns
        dns_interactions = [i for i in interactions if i.protocol == Protocol.DNS]
        if len(dns_interactions) > 5:
            patterns.append(
                {
                    "type": "multiple_dns_queries",
                    "description": f"{len(dns_interactions)} DNS queries detected",
                    "possible_vulnerability": "DNS exfiltration or XXE",
                    "query_count": len(dns_interactions),
                }
            )

        # Check for HTTP interactions with interesting paths
        http_interactions = [
            i for i in interactions if i.protocol in [Protocol.HTTP, Protocol.HTTPS]
        ]
        for interaction in http_interactions:
            if interaction.http_request:
                path = interaction.http_request.get("path", "")
                if any(
                    keyword in path.lower()
                    for keyword in ["admin", "config", "secret", "key"]
                ):
                    patterns.append(
                        {
                            "type": "sensitive_path_access",
                            "description": f"Access to potentially sensitive path: {path}",
                            "possible_vulnerability": "SSRF or path traversal",
                            "path": path,
                        }
                    )

        return patterns

    def generate_forensic_report(
        self, payload: CollaboratorPayload, interactions: List[Interaction]
    ) -> Dict:
        """
        Generate a comprehensive forensic report.

        Args:
            payload: Payload that generated the interactions
            interactions: List of interactions to report on

        Returns:
            Comprehensive forensic report
        """
        report = {
            "payload_id": str(payload.id),
            "payload_type": payload.payload_type.value,
            "subdomain": payload.subdomain,
            "full_domain": payload.full_domain,
            "created_at": payload.created_at.isoformat(),
            "interaction_count": len(interactions),
        }

        if interactions:
            # Add timeline analysis
            report["timeline"] = self.analyze_interaction_timeline(interactions)

            # Add pattern detection
            report["detected_patterns"] = self.detect_patterns(interactions)

            # Add detailed interaction analysis
            report["interactions"] = [
                self.analyze_interaction(interaction) for interaction in interactions
            ]
        else:
            report["status"] = "No interactions captured"

        return report
