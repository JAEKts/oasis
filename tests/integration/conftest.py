"""
Shared fixtures for integration tests.
"""

import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio

from src.oasis.core.config import OASISConfig, SecurityConfig
from src.oasis.core.models import HTTPRequest, HTTPResponse, Project, ProjectSettings
from src.oasis.storage.vault import VaultStorage
from src.oasis.proxy.engine import ProxyEngine
from src.oasis.scanner.engine import ScanEngine
from src.oasis.repeater.session import RepeaterSession


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def integration_temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for integration tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def integration_config(integration_temp_dir: Path) -> OASISConfig:
    """Provide an integration test configuration."""
    return OASISConfig(
        environment="integration_test",
        debug=True,
        security=SecurityConfig(secret_key="integration-test-secret-key"),
        vault={"base_path": str(integration_temp_dir / "vault")},
        database={"url": f"sqlite:///{integration_temp_dir / 'test.db'}"},
        logging={"level": "INFO"}
    )


@pytest.fixture
def integration_vault(integration_temp_dir: Path) -> VaultStorage:
    """Provide a vault storage instance for integration tests."""
    vault = VaultStorage(integration_temp_dir / "vault")
    return vault


@pytest.fixture
def integration_project(integration_vault: VaultStorage) -> Project:
    """Provide a project for integration testing."""
    project = Project(
        name="Integration Test Project",
        description="Project for end-to-end integration testing",
        settings=ProjectSettings(
            target_scope=["http://testserver.local/*", "https://testserver.local/*"],
            excluded_scope=["http://testserver.local/admin/*"]
        )
    )
    # Create the project in the vault so it exists for tests
    # Use the project object directly which returns the project ID
    project_id = integration_vault.create_project(project)
    # If create_project returned an ID, update the project's ID
    if isinstance(project_id, uuid.UUID):
        project.id = project_id
    return project


@pytest_asyncio.fixture
async def proxy_engine(integration_config: OASISConfig) -> AsyncGenerator[ProxyEngine, None]:
    """Provide a proxy engine instance for integration tests."""
    engine = ProxyEngine(config=integration_config)
    yield engine
    # Cleanup
    if hasattr(engine, 'stop'):
        await engine.stop()


@pytest_asyncio.fixture
async def scan_engine(integration_config: OASISConfig) -> ScanEngine:
    """Provide a scan engine instance for integration tests."""
    return ScanEngine()


@pytest.fixture
def repeater_session(integration_vault: VaultStorage, integration_project: Project) -> RepeaterSession:
    """Provide a repeater session for integration tests."""
    return RepeaterSession(
        project_id=integration_project.id
    )


@pytest.fixture
def sample_http_request() -> HTTPRequest:
    """Provide a sample HTTP request for testing."""
    return HTTPRequest(
        method="GET",
        url="http://testserver.local/api/users",
        headers={
            "Host": "testserver.local",
            "User-Agent": "OASIS-Integration-Test/1.0",
            "Accept": "application/json"
        }
    )


@pytest.fixture
def sample_http_response() -> HTTPResponse:
    """Provide a sample HTTP response for testing."""
    return HTTPResponse(
        status_code=200,
        headers={
            "Content-Type": "application/json",
            "Server": "TestServer/1.0"
        },
        body=b'{"users": [{"id": 1, "name": "Test User"}]}',
        duration_ms=45
    )
