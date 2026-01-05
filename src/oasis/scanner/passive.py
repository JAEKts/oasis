"""
Passive Scanner

Analyzes intercepted HTTP traffic without sending additional requests.
"""

from typing import List
import re

from ..core.models import Finding, Severity, Confidence, VulnerabilityType, Evidence
from .detector import ScanContext


class PassiveScanner:
    """
    Passive vulnerability scanner that analyzes HTTP traffic without active probing.

    Detects issues like:
    - Sensitive data exposure in responses
    - Security misconfigurations
    - Missing security headers
    - Information disclosure
    """

    def __init__(self):
        self.detectors = [
            self._detect_sensitive_data_exposure,
            self._detect_security_headers,
            self._detect_information_disclosure,
            self._detect_insecure_cookies,
        ]

    async def analyze_flow(self, context: ScanContext) -> List[Finding]:
        """
        Analyze an HTTP flow for passive vulnerabilities.

        Args:
            context: Scan context containing the flow

        Returns:
            List of findings discovered
        """
        findings = []

        for detector in self.detectors:
            try:
                result = await detector(context)
                if result:
                    findings.extend(result if isinstance(result, list) else [result])
            except Exception:
                # Continue with other detectors even if one fails
                pass

        return findings

    async def _detect_sensitive_data_exposure(
        self, context: ScanContext
    ) -> List[Finding]:
        """Detect sensitive data in responses."""
        findings = []

        if not context.flow.response or not context.flow.response.body:
            return findings

        try:
            body = context.flow.response.body.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        # Check for common sensitive patterns
        patterns = {
            "api_key": r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
            "password": r'password["\']?\s*[:=]\s*["\']([^"\']{8,})',
            "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        }

        for pattern_name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(
                    Finding(
                        vulnerability_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        title=f"Sensitive Data Exposure: {pattern_name}",
                        description=f"The response contains what appears to be sensitive {pattern_name} data.",
                        evidence=Evidence(
                            request=context.flow.request,
                            response=context.flow.response,
                            location="response_body",
                            proof_of_concept=f"Pattern matched: {pattern_name}",
                        ),
                        remediation="Remove sensitive data from responses or implement proper access controls.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                        ],
                    )
                )

        return findings

    async def _detect_security_headers(self, context: ScanContext) -> List[Finding]:
        """Detect missing security headers."""
        findings = []

        if not context.flow.response:
            return findings

        headers = {k.lower(): v for k, v in context.flow.response.headers.items()}

        # Check for missing security headers
        security_headers = {
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME type sniffing protection",
            "strict-transport-security": "HTTPS enforcement",
            "content-security-policy": "XSS and injection protection",
            "x-xss-protection": "XSS filter",
        }

        for header, description in security_headers.items():
            if header not in headers:
                findings.append(
                    Finding(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        title=f"Missing Security Header: {header}",
                        description=f"The response is missing the {header} header, which provides {description}.",
                        evidence=Evidence(
                            request=context.flow.request,
                            response=context.flow.response,
                            location="response_headers",
                        ),
                        remediation=f"Add the {header} header to all responses.",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )

        return findings

    async def _detect_information_disclosure(
        self, context: ScanContext
    ) -> List[Finding]:
        """Detect information disclosure in responses."""
        findings = []

        if not context.flow.response:
            return findings

        headers = {k.lower(): v for k, v in context.flow.response.headers.items()}

        # Check for server version disclosure
        if "server" in headers:
            server_value = headers["server"]
            # Check if version information is present
            if re.search(r"\d+\.\d+", server_value):
                findings.append(
                    Finding(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        severity=Severity.INFO,
                        confidence=Confidence.CERTAIN,
                        title="Server Version Disclosure",
                        description=f"The server header reveals version information: {server_value}",
                        evidence=Evidence(
                            request=context.flow.request,
                            response=context.flow.response,
                            location="response_headers",
                            additional_data={"server_header": server_value},
                        ),
                        remediation="Configure the server to not disclose version information.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                        ],
                    )
                )

        # Check for X-Powered-By header
        if "x-powered-by" in headers:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    title="Technology Stack Disclosure",
                    description=f"The X-Powered-By header reveals technology information: {headers['x-powered-by']}",
                    evidence=Evidence(
                        request=context.flow.request,
                        response=context.flow.response,
                        location="response_headers",
                    ),
                    remediation="Remove the X-Powered-By header from responses.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                )
            )

        return findings

    async def _detect_insecure_cookies(self, context: ScanContext) -> List[Finding]:
        """Detect insecure cookie configurations."""
        findings = []

        if not context.flow.response:
            return findings

        # Check Set-Cookie headers
        for key, value in context.flow.response.headers.items():
            if key.lower() == "set-cookie":
                # Check for missing Secure flag
                if "secure" not in value.lower():
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CERTAIN,
                            title="Cookie Without Secure Flag",
                            description="A cookie is set without the Secure flag, allowing transmission over unencrypted connections.",
                            evidence=Evidence(
                                request=context.flow.request,
                                response=context.flow.response,
                                location="response_headers",
                                additional_data={"cookie": value},
                            ),
                            remediation="Add the Secure flag to all cookies containing sensitive data.",
                            references=[
                                "https://owasp.org/www-community/controls/SecureCookieAttribute"
                            ],
                        )
                    )

                # Check for missing HttpOnly flag
                if "httponly" not in value.lower():
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CERTAIN,
                            title="Cookie Without HttpOnly Flag",
                            description="A cookie is set without the HttpOnly flag, making it accessible to JavaScript.",
                            evidence=Evidence(
                                request=context.flow.request,
                                response=context.flow.response,
                                location="response_headers",
                                additional_data={"cookie": value},
                            ),
                            remediation="Add the HttpOnly flag to cookies to prevent XSS attacks from stealing session data.",
                            references=["https://owasp.org/www-community/HttpOnly"],
                        )
                    )

        return findings
