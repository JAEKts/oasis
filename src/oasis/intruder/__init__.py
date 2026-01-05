"""
OASIS Intruder Module

Automated attack engine with customizable payloads for penetration testing.
"""

from .config import (
    AttackType,
    AttackConfig,
    InjectionPoint,
    PayloadSet,
    PayloadProcessor,
    ProcessorType,
)
from .payloads import (
    PayloadGenerator,
    WordlistGenerator,
    NumberGenerator,
    CharsetGenerator,
    CustomGenerator,
)
from .engine import AttackEngine, AttackResults
from .analysis import (
    ResultAnalyzer,
    ReportGenerator,
    FilterRule,
    FilterCriteria,
    SortCriteria,
)

__all__ = [
    # Configuration
    "AttackType",
    "AttackConfig",
    "InjectionPoint",
    "PayloadSet",
    "PayloadProcessor",
    "ProcessorType",
    # Payload Generation
    "PayloadGenerator",
    "WordlistGenerator",
    "NumberGenerator",
    "CharsetGenerator",
    "CustomGenerator",
    # Engine
    "AttackEngine",
    "AttackResults",
    # Analysis
    "ResultAnalyzer",
    "ReportGenerator",
    "FilterRule",
    "FilterCriteria",
    "SortCriteria",
]
