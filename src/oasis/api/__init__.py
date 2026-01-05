"""
OASIS REST API

Provides REST API for external tool integration and automation.
"""

from .app import create_app, app
from .routes import *

__all__ = ["create_app", "app"]
