"""
OASIS Proxy Module

HTTP/HTTPS traffic interception and manipulation using mitmproxy.
"""

from .engine import ProxyEngine
from .addon import OASISAddon, TrafficModifier
from .certificates import CertificateManager

__all__ = ["ProxyEngine", "OASISAddon", "TrafficModifier", "CertificateManager"]
