"""
Cross-Site Scripting (XSS) Detector

Detects XSS vulnerabilities including reflected, stored, and DOM-based variants.
"""

from typing import List
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ...core.models import Finding, Severity, Confidence, VulnerabilityType, Evidence
from ..detector import VulnerabilityDetector, ScanContext


class XSSDetector(VulnerabilityDetector):
    """
    Detects Cross-Site Scripting (XSS) vulnerabilities:
    - Reflected XSS
    - Stored XSS
    - DOM-based XSS
    """

    def __init__(self):
        super().__init__(
            name="xss", description="Detects Cross-Site Scripting vulnerabilities"
        )

        # XSS test payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"-alert('XSS')-\"",
            "</script><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        ]

        # Patterns to detect XSS in responses
        self.xss_patterns = [
            r"<script[^>]*>.*?alert\(['\"]XSS['\"]",
            r"<img[^>]*onerror\s*=\s*['\"]?alert\(['\"]XSS",
            r"<svg[^>]*onload\s*=\s*['\"]?alert\(['\"]XSS",
            r"javascript:\s*alert\(['\"]XSS",
            r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
            r"<body[^>]*onload\s*=\s*['\"]?alert\(['\"]XSS",
            r"<input[^>]*onfocus\s*=\s*['\"]?alert\(['\"]XSS",
        ]

        # DOM-based XSS sinks
        self.dom_sinks = [
            r"document\.write\(",
            r"document\.writeln\(",
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"eval\(",
            r"setTimeout\(",
            r"setInterval\(",
            r"Function\(",
            r"\.location\s*=",
            r"\.href\s*=",
        ]

    async def detect(self, context: ScanContext) -> List[Finding]:
        """Detect XSS vulnerabilities."""
        findings = []

        # Reflected XSS detection
        reflected_findings = await self._detect_reflected_xss(context)
        findings.extend(reflected_findings)

        # DOM-based XSS detection
        dom_findings = await self._detect_dom_xss(context)
        findings.extend(dom_findings)

        # Stored XSS would require tracking inputs across multiple requests
        # Placeholder for future implementation

        return findings

    async def _detect_reflected_xss(self, context: ScanContext) -> List[Finding]:
        """Detect reflected XSS vulnerabilities."""
        findings = []

        if not context.flow.response or not context.flow.response.body:
            return findings

        try:
            response_body = context.flow.response.body.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        # Check if any query parameters are reflected in the response
        parsed = urlparse(context.flow.request.url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for param_value in param_values:
                # Check if parameter value is reflected in response
                if param_value and param_value in response_body:
                    # Check if it's in a dangerous context
                    if self._is_dangerous_context(response_body, param_value):
                        findings.append(
                            Finding(
                                vulnerability_type=VulnerabilityType.XSS_REFLECTED,
                                severity=Severity.HIGH,
                                confidence=Confidence.FIRM,
                                title=f"Reflected XSS in parameter '{param_name}'",
                                description=f"The parameter '{param_name}' is reflected in the response without proper encoding. "
                                f"This could allow an attacker to inject malicious JavaScript code.",
                                evidence=Evidence(
                                    request=context.flow.request,
                                    response=context.flow.response,
                                    location=f"query_parameter:{param_name}",
                                    proof_of_concept=f"Test with payload: {self.xss_payloads[0]}",
                                    additional_data={
                                        "reflected_value": param_value,
                                        "parameter": param_name,
                                    },
                                ),
                                remediation="Encode all user input before including it in HTML output. "
                                "Use context-appropriate encoding (HTML entity encoding, JavaScript encoding, etc.). "
                                "Implement Content Security Policy (CSP) headers.",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )

        return findings

    def _is_dangerous_context(self, response_body: str, value: str) -> bool:
        """Check if a reflected value is in a dangerous context."""
        # Find the position of the value in the response
        index = response_body.find(value)
        if index == -1:
            return False

        # Get context around the value (100 chars before and after)
        start = max(0, index - 100)
        end = min(len(response_body), index + len(value) + 100)
        context = response_body[start:end]

        # Check for dangerous contexts
        dangerous_patterns = [
            r"<script[^>]*>.*?" + re.escape(value),  # Inside script tag
            r'<[^>]*\s+on\w+\s*=\s*["\']?[^"\']*'
            + re.escape(value),  # In event handler
            r'<[^>]*\s+href\s*=\s*["\']?javascript:[^"\']*'
            + re.escape(value),  # In javascript: URL
            r'<[^>]*\s+src\s*=\s*["\']?[^"\']*' + re.escape(value),  # In src attribute
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        # Check if value is not properly encoded
        if "<" in value or ">" in value or '"' in value or "'" in value:
            # If special chars are present and not encoded, it's dangerous
            if value in context and "&lt;" not in context and "&gt;" not in context:
                return True

        return False

    async def _detect_dom_xss(self, context: ScanContext) -> List[Finding]:
        """Detect DOM-based XSS vulnerabilities."""
        findings = []

        if not context.flow.response or not context.flow.response.body:
            return findings

        try:
            response_body = context.flow.response.body.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        # Check for dangerous DOM sinks with user-controllable sources
        sources = [
            r"location\.hash",
            r"location\.search",
            r"location\.href",
            r"document\.URL",
            r"document\.documentURI",
            r"document\.referrer",
            r"window\.name",
        ]

        for source in sources:
            if re.search(source, response_body):
                # Check if this source flows to a dangerous sink
                for sink in self.dom_sinks:
                    if re.search(sink, response_body):
                        findings.append(
                            Finding(
                                vulnerability_type=VulnerabilityType.XSS_DOM,
                                severity=Severity.HIGH,
                                confidence=Confidence.TENTATIVE,
                                title="Potential DOM-based XSS",
                                description=f"The page uses a user-controllable source ({source}) "
                                f"and contains a dangerous sink ({sink}). "
                                f"This may allow DOM-based XSS if the data flows from source to sink.",
                                evidence=Evidence(
                                    request=context.flow.request,
                                    response=context.flow.response,
                                    location="response_body",
                                    additional_data={
                                        "source": source,
                                        "sink": sink,
                                    },
                                ),
                                remediation="Avoid using dangerous sinks with user-controllable data. "
                                "If necessary, sanitize and validate all data before using it in sinks. "
                                "Use safe APIs like textContent instead of innerHTML.",
                                references=[
                                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )
                        break  # Only report once per source

        return findings
