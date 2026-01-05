#!/usr/bin/env python
"""
Setup script for OASIS - Open Architecture Security Interception Suite

This setup.py allows the package to be installed with pip even though
the project uses Poetry for dependency management.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Core dependencies
install_requires = [
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    "asyncio>=3.4.3",
    "fastapi>=0.104.0",
    "aiohttp>=3.9.0",
    "mitmproxy>=10.1.0",
    "cryptography>=42.0.0",
    "msgpack>=1.0.7",
    "prometheus-client>=0.19.0",
    "PyQt6>=6.6.0",
    "websockets>=12.0",
    "redis>=5.0.0",
    "psycopg2-binary>=2.9.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "requests>=2.31.0",
    "psutil>=5.9.0",
    "argon2-cffi>=23.1.0",
]

# Platform-specific dependencies
import sys
if sys.platform != "win32":
    install_requires.append("uvloop>=0.19.0")

# Development dependencies
dev_requires = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "hypothesis>=6.88.0",
    "black>=23.11.0",
    "flake8>=6.1.0",
    "mypy>=1.7.0",
    "pre-commit>=3.5.0",
    "coverage>=7.3.0",
    "pytest-cov>=4.1.0",
]

setup(
    name="oasis",
    version="0.1.0",
    description="Open Architecture Security Interception Suite - A comprehensive penetration testing platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="OASIS Team",
    author_email="team@oasis-pentest.org",
    url="https://github.com/oasis/oasis",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11,<3.13",
    install_requires=install_requires,
    extras_require={
        "dev": dev_requires,
    },
    entry_points={
        "console_scripts": [
            "oasis=oasis.main:main",
            "oasis-cli=oasis.cli.main:main",
            "oasis-api=oasis.api.app:run_server",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security penetration-testing proxy scanner",
    project_urls={
        "Bug Reports": "https://github.com/oasis/oasis/issues",
        "Source": "https://github.com/oasis/oasis",
    },
)
