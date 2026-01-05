"""
Server-Side Request Forgery (SSRF) Detector

Detects SSRF vulnerabilities where user input controls server-side requests.
"""

from typing import List
import re
from urllib.parse import urlparse, parse_qs

from ...core.models import Finding, Severity, Confidence, VulnerabilityType, Evidence
from ..detector import VulnerabilityDetector, ScanContext


class SSRFDetector(VulnerabilityDetector):
    """
    Detects Server-Side Request Forgery (SSRF) vulnerabilities by identifying:
    - URL parameters that might trigger server-side requests
    - Potential SSRF indicators in responses
    """

    def __init__(self):
        super().__init__(
            name="ssrf",
            description="Detects Server-Side Request Forgery vulnerabilities",
        )

        # Parameter names that commonly indicate URL/resource fetching
        self.url_param_indicators = [
            "url",
            "uri",
            "path",
            "dest",
            "destination",
            "redirect",
            "link",
            "file",
            "document",
            "resource",
            "src",
            "source",
            "target",
            "callback",
            "return",
            "returnto",
            "next",
            "continue",
            "view",
            "data",
            "reference",
            "site",
            "html",
            "feed",
            "host",
            "port",
            "to",
            "out",
            "page",
            "load",
            "fetch",
            "get",
            "download",
            "proxy",
        ]

        # SSRF test payloads (for active testing)
        self.ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",  # GCP metadata
            "http://[::1]",  # IPv6 localhost
            "file:///etc/passwd",
            "dict://localhost:11211",
            "gopher://localhost:25",
        ]

    async def detect(self, context: ScanContext) -> List[Finding]:
        """Detect SSRF vulnerabilities."""
        findings = []

        # Check for URL parameters that might be vulnerable
        param_findings = await self._check_url_parameters(context)
        findings.extend(param_findings)

        # Check response for SSRF indicators
        response_findings = await self._check_response_indicators(context)
        findings.extend(response_findings)

        return findings

    async def _check_url_parameters(self, context: ScanContext) -> List[Finding]:
        """Check for parameters that might be vulnerable to SSRF."""
        findings = []

        parsed = urlparse(context.flow.request.url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            # Check if parameter name suggests URL handling
            if any(
                indicator in param_name.lower()
                for indicator in self.url_param_indicators
            ):
                # Check if parameter value looks like a URL
                for param_value in param_values:
                    if self._looks_like_url(param_value):
                        findings.append(
                            Finding(
                                vulnerability_type=VulnerabilityType.SSRF,
                                severity=Severity.HIGH,
                                confidence=Confidence.TENTATIVE,
                                title=f"Potential SSRF in parameter '{param_name}'",
                                description=f"The parameter '{param_name}' appears to accept URL values and may be used "
                                f"for server-side requests. This could potentially be exploited for SSRF attacks "
                                f"to access internal resources or perform port scanning.",
                                evidence=Evidence(
                                    request=context.flow.request,
                                    response=context.flow.response,
                                    location=f"query_parameter:{param_name}",
                                    additional_data={
                                        "parameter": param_name,
                                        "value": param_value,
                                    },
                                    proof_of_concept=f"Test with internal URLs like: {self.ssrf_payloads[0]}",
                                ),
                                remediation="Implement strict URL validation and whitelist allowed domains/protocols. "
                                "Disable unnecessary protocols (file://, gopher://, etc.). "
                                "Use a whitelist of allowed IP addresses and block access to internal networks. "
                                "Consider using a proxy service for external requests.",
                                references=[
                                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )

        # Check POST body for URL parameters
        if context.flow.request.method == "POST" and context.flow.request.body:
            body_findings = await self._check_post_body_urls(context)
            findings.extend(body_findings)

        return findings

    async def _check_post_body_urls(self, context: ScanContext) -> List[Finding]:
        """Check POST body for URL parameters."""
        findings = []

        try:
            body = context.flow.request.body.decode("utf-8", errors="ignore")

            # Simple check for URL-like patterns in body
            for indicator in self.url_param_indicators:
                pattern = rf'{indicator}["\']?\s*[:=]\s*["\']?(https?://[^\s"\'&]+)'
                matches = re.findall(pattern, body, re.IGNORECASE)

                if matches:
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.SSRF,
                            severity=Severity.HIGH,
                            confidence=Confidence.TENTATIVE,
                            title=f"Potential SSRF in POST body parameter",
                            description=f"The POST body contains a parameter that appears to accept URL values. "
                            f"This could potentially be exploited for SSRF attacks.",
                            evidence=Evidence(
                                request=context.flow.request,
                                response=context.flow.response,
                                location="post_body",
                                proof_of_concept=f"Test with internal URLs",
                            ),
                            remediation="Implement strict URL validation and whitelist allowed domains/protocols.",
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            ],
                        )
                    )
                    break  # Only report once per request
        except Exception:
            pass

        return findings

    async def _check_response_indicators(self, context: ScanContext) -> List[Finding]:
        """Check response for SSRF indicators."""
        findings = []

        if not context.flow.response or not context.flow.response.body:
            return findings

        try:
            body = context.flow.response.body.decode("utf-8", errors="ignore")

            # Check for internal IP addresses in response
            internal_ip_patterns = [
                r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b",
                r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
                r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            ]

            for pattern in internal_ip_patterns:
                if re.search(pattern, body):
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.SSRF,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.TENTATIVE,
                            title="Internal IP Address Disclosed",
                            description="The response contains internal IP addresses, which might indicate "
                            "that the application is making requests to internal resources. "
                            "This could be a sign of SSRF vulnerability.",
                            evidence=Evidence(
                                request=context.flow.request,
                                response=context.flow.response,
                                location="response_body",
                            ),
                            remediation="Ensure that internal IP addresses are not disclosed in responses. "
                            "Implement proper SSRF protections.",
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            ],
                        )
                    )
                    break  # Only report once
        except Exception:
            pass

        return findings

    def _looks_like_url(self, value: str) -> bool:
        """Check if a value looks like a URL."""
        if not value:
            return False

        # Check for URL schemes
        url_schemes = [
            "http://",
            "https://",
            "ftp://",
            "file://",
            "gopher://",
            "dict://",
        ]
        if any(value.lower().startswith(scheme) for scheme in url_schemes):
            return True

        # Check for domain-like patterns
        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}", value):
            return True

        return False
