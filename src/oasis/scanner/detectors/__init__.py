"""
Vulnerability Detection Modules

Individual detectors for specific vulnerability types.
"""

from .sql_injection import SQLInjectionDetector
from .xss import XSSDetector
from .csrf import CSRFDetector
from .ssrf import SSRFDetector
from .xxe import XXEDetector

__all__ = [
    "SQLInjectionDetector",
    "XSSDetector",
    "CSRFDetector",
    "SSRFDetector",
    "XXEDetector",
]
