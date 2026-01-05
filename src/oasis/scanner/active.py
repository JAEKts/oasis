"""
Active Scanner

Performs active probing to detect vulnerabilities by sending test payloads.
"""

from typing import List
import asyncio

from ..core.models import Finding
from .detector import ScanContext
from .detectors.sql_injection import SQLInjectionDetector
from .detectors.xss import XSSDetector
from .detectors.csrf import CSRFDetector
from .detectors.ssrf import SSRFDetector
from .detectors.xxe import XXEDetector


class ActiveScanner:
    """
    Active vulnerability scanner that sends test payloads to detect vulnerabilities.

    Includes detectors for:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Cross-Site Request Forgery (CSRF)
    - Server-Side Request Forgery (SSRF)
    - XML External Entity (XXE)
    """

    def __init__(self):
        # Initialize all vulnerability detectors
        self.detectors = [
            SQLInjectionDetector(),
            XSSDetector(),
            CSRFDetector(),
            SSRFDetector(),
            XXEDetector(),
        ]

    async def probe_flow(self, context: ScanContext) -> List[Finding]:
        """
        Actively probe an HTTP flow for vulnerabilities.

        Args:
            context: Scan context containing the flow

        Returns:
            List of findings discovered through active probing
        """
        findings = []

        # Run all active detectors
        for detector in self.detectors:
            try:
                # Use the detector's analyze method which checks if it's enabled
                result = await detector.analyze(context)
                if result:
                    findings.extend(result)
            except Exception:
                # Continue with other detectors even if one fails
                pass

        return findings

    def add_detector(self, detector):
        """Add a detector to the active scanner."""
        self.detectors.append(detector)
