"""
XML External Entity (XXE) Detector

Detects XXE vulnerabilities in XML processing.
"""

from typing import List
import re

from ...core.models import Finding, Severity, Confidence, VulnerabilityType, Evidence
from ..detector import VulnerabilityDetector, ScanContext


class XXEDetector(VulnerabilityDetector):
    """
    Detects XML External Entity (XXE) vulnerabilities by identifying:
    - XML content in requests
    - Potential XXE indicators in responses
    - Unsafe XML parsing configurations
    """

    def __init__(self):
        super().__init__(
            name="xxe", description="Detects XML External Entity vulnerabilities"
        )

        # XXE test payloads
        self.xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/secret">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
        ]

        # Patterns indicating XXE vulnerability
        self.xxe_indicators = [
            r"root:.*:0:0:",  # /etc/passwd content
            r"<!ENTITY",  # Entity declaration in response
            r'SYSTEM\s+["\']file://',  # File protocol usage
        ]

    async def detect(self, context: ScanContext) -> List[Finding]:
        """Detect XXE vulnerabilities."""
        findings = []

        # Check if request contains XML
        if self._is_xml_request(context):
            xml_findings = await self._check_xml_processing(context)
            findings.extend(xml_findings)

        return findings

    def _is_xml_request(self, context: ScanContext) -> bool:
        """Check if the request contains XML content."""
        # Check Content-Type header
        content_type = context.flow.request.headers.get("Content-Type", "").lower()
        if "xml" in content_type:
            return True

        # Check if body looks like XML
        if context.flow.request.body:
            try:
                body = context.flow.request.body.decode("utf-8", errors="ignore")
                if body.strip().startswith("<?xml") or body.strip().startswith("<"):
                    return True
            except Exception:
                pass

        return False

    async def _check_xml_processing(self, context: ScanContext) -> List[Finding]:
        """Check for XXE vulnerabilities in XML processing."""
        findings = []

        # Check if response indicates XXE vulnerability
        if context.flow.response and context.flow.response.body:
            try:
                response_body = context.flow.response.body.decode(
                    "utf-8", errors="ignore"
                )

                # Check for XXE indicators in response
                for indicator in self.xxe_indicators:
                    if re.search(indicator, response_body, re.IGNORECASE):
                        findings.append(
                            Finding(
                                vulnerability_type=VulnerabilityType.XXE,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.FIRM,
                                title="XML External Entity (XXE) Vulnerability",
                                description="The application appears to be vulnerable to XXE attacks. "
                                "The XML parser processes external entities, which could allow "
                                "an attacker to read local files, perform SSRF attacks, or cause DoS.",
                                evidence=Evidence(
                                    request=context.flow.request,
                                    response=context.flow.response,
                                    location="xml_processing",
                                    proof_of_concept=f"Test with XXE payload: {self.xxe_payloads[0][:100]}...",
                                ),
                                remediation="Disable external entity processing in XML parsers. "
                                "Use secure XML parser configurations:\n"
                                "- For Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                                "- For Python: Use defusedxml library\n"
                                "- For .NET: Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
                                "Validate and sanitize all XML input.",
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )
                        break  # Only report once
            except Exception:
                pass

        # Even if no indicators found, report potential XXE if XML is processed
        if not findings:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.XXE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    title="Potential XXE Vulnerability - XML Processing Detected",
                    description="The application processes XML input. If the XML parser is not properly configured, "
                    "it may be vulnerable to XXE attacks. Further testing is recommended.",
                    evidence=Evidence(
                        request=context.flow.request,
                        response=context.flow.response,
                        location="xml_processing",
                    ),
                    remediation="Ensure XML parsers are configured to disable external entity processing. "
                    "Use secure XML parsing libraries and configurations.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                    ],
                )
            )

        return findings
