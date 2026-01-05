"""
Pytest configuration and shared fixtures for OASIS tests.
"""

import tempfile
import uuid
from pathlib import Path
from typing import Generator

import pytest

from src.oasis.core.config import OASISConfig, SecurityConfig
from src.oasis.core.models import Project, ProjectSettings
from src.oasis.storage.vault import VaultStorage


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def test_config(temp_dir: Path) -> OASISConfig:
    """Provide a test configuration."""
    return OASISConfig(
        environment="test",
        debug=True,
        security=SecurityConfig(secret_key="test-secret-key-for-testing-only"),
        vault={"base_path": str(temp_dir / "test_vault")},
        database={"url": "sqlite:///:memory:"},
        logging={"level": "DEBUG"}
    )


@pytest.fixture
def vault_storage(temp_dir: Path) -> VaultStorage:
    """Provide a test vault storage instance."""
    return VaultStorage(temp_dir / "test_vault")


@pytest.fixture
def sample_project() -> Project:
    """Provide a sample project for testing."""
    return Project(
        name="Test Project",
        description="A test project for unit testing",
        settings=ProjectSettings(
            target_scope=["https://example.com/*"],
            excluded_scope=["https://example.com/admin/*"]
        )
    )