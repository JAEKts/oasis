"""
Cross-Site Request Forgery (CSRF) Detector

Detects missing or weak CSRF protection.
"""

from typing import List
import re

from ...core.models import Finding, Severity, Confidence, VulnerabilityType, Evidence
from ..detector import VulnerabilityDetector, ScanContext


class CSRFDetector(VulnerabilityDetector):
    """
    Detects Cross-Site Request Forgery (CSRF) vulnerabilities by checking for:
    - Missing CSRF tokens in forms
    - Missing CSRF tokens in state-changing requests
    - Weak CSRF token implementation
    """

    def __init__(self):
        super().__init__(
            name="csrf",
            description="Detects Cross-Site Request Forgery vulnerabilities",
        )

        # Common CSRF token names
        self.csrf_token_names = [
            "csrf_token",
            "csrftoken",
            "csrf",
            "_csrf",
            "token",
            "_token",
            "authenticity_token",
            "__requestverificationtoken",
            "anti-csrf-token",
        ]

        # State-changing methods
        self.state_changing_methods = ["POST", "PUT", "DELETE", "PATCH"]

    async def detect(self, context: ScanContext) -> List[Finding]:
        """Detect CSRF vulnerabilities."""
        findings = []

        # Check state-changing requests for CSRF protection
        if context.flow.request.method in self.state_changing_methods:
            csrf_findings = await self._check_csrf_protection(context)
            findings.extend(csrf_findings)

        # Check forms in responses for CSRF tokens
        if context.flow.response and context.flow.response.body:
            form_findings = await self._check_forms_for_csrf(context)
            findings.extend(form_findings)

        return findings

    async def _check_csrf_protection(self, context: ScanContext) -> List[Finding]:
        """Check if a state-changing request has CSRF protection."""
        findings = []

        # Check for CSRF token in request
        has_csrf_token = False

        # Check headers
        for header_name, header_value in context.flow.request.headers.items():
            if any(
                token_name in header_name.lower()
                for token_name in self.csrf_token_names
            ):
                has_csrf_token = True
                break

        # Check body (if POST)
        if not has_csrf_token and context.flow.request.body:
            try:
                body = context.flow.request.body.decode("utf-8", errors="ignore")
                for token_name in self.csrf_token_names:
                    if token_name in body.lower():
                        has_csrf_token = True
                        break
            except Exception:
                pass

        # Check for SameSite cookie attribute
        has_samesite = False
        if context.flow.response:
            for header_name, header_value in context.flow.response.headers.items():
                if header_name.lower() == "set-cookie":
                    if "samesite" in header_value.lower():
                        has_samesite = True
                        break

        # If no CSRF protection found, report vulnerability
        if not has_csrf_token and not has_samesite:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.CSRF,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    title=f"Missing CSRF Protection on {context.flow.request.method} Request",
                    description=f"The {context.flow.request.method} request to {context.flow.request.url} "
                    f"does not appear to have CSRF protection. No CSRF token was found in the request, "
                    f"and cookies do not use the SameSite attribute.",
                    evidence=Evidence(
                        request=context.flow.request,
                        response=context.flow.response,
                        location="request",
                    ),
                    remediation="Implement CSRF protection using one or more of the following methods:\n"
                    "1. Include a unique CSRF token in all state-changing requests\n"
                    "2. Use the SameSite cookie attribute\n"
                    "3. Verify the Origin or Referer header\n"
                    "4. Require re-authentication for sensitive operations",
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                )
            )

        return findings

    async def _check_forms_for_csrf(self, context: ScanContext) -> List[Finding]:
        """Check HTML forms for CSRF tokens."""
        findings = []

        try:
            body = context.flow.response.body.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        # Find all forms
        form_pattern = r"<form[^>]*>(.*?)</form>"
        forms = re.findall(form_pattern, body, re.IGNORECASE | re.DOTALL)

        for form_content in forms:
            # Check if form uses POST method
            if "method" in form_content.lower() and "post" in form_content.lower():
                # Check for CSRF token
                has_csrf_token = any(
                    token_name in form_content.lower()
                    for token_name in self.csrf_token_names
                )

                if not has_csrf_token:
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.CSRF,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM,
                            title="Form Without CSRF Token",
                            description="An HTML form using the POST method was found without a CSRF token. "
                            "This could allow an attacker to perform actions on behalf of a victim user.",
                            evidence=Evidence(
                                request=context.flow.request,
                                response=context.flow.response,
                                location="response_body",
                                proof_of_concept="Form found without CSRF protection",
                            ),
                            remediation="Add a unique CSRF token to all forms that perform state-changing operations. "
                            "Verify the token on the server side before processing the request.",
                            references=[
                                "https://owasp.org/www-community/attacks/csrf",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                            ],
                        )
                    )

        return findings
