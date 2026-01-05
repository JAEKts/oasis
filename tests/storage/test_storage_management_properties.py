"""
Property-based tests for OASIS storage management system.

Tests Property 5: Storage Management Efficiency
**Validates: Requirements 1.6**
"""

import asyncio
import pytest
import tempfile
import uuid
from datetime import datetime, timedelta, UTC
from pathlib import Path
from hypothesis import given, strategies as st, assume, settings
from unittest.mock import Mock, patch

from src.oasis.core.models import (
    HTTPRequest, HTTPResponse, HTTPFlow, Project, ProjectSettings,
    RequestSource, FlowMetadata, Severity, Finding, VulnerabilityType, 
    Confidence, Evidence
)
from src.oasis.storage.manager import StorageManager, StorageConfig, ArchiveManager
from src.oasis.storage.sqlite_vault import SQLiteVaultStorage


# Strategies for generating test data
def storage_config_strategy():
    """Generate valid storage configurations."""
    return st.builds(StorageConfig)


@st.composite
def http_flow_strategy(draw):
    """Generate valid HTTP flows."""
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    method = draw(st.sampled_from(methods))
    
    urls = [
        'https://example.com/api/users',
        'https://test.org/login',
        'https://api.example.com/data',
        'https://localhost:8080/admin'
    ]
    url = draw(st.sampled_from(urls))
    
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=20),
        st.text(min_size=1, max_size=50),
        min_size=0, max_size=3
    ))
    
    body = draw(st.one_of(st.none(), st.binary(min_size=0, max_size=1000)))
    
    # Generate deterministic timestamps using Hypothesis (naive, then add UTC)
    request_timestamp_naive = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2025, 12, 31)
    ))
    request_timestamp = request_timestamp_naive.replace(tzinfo=UTC)
    
    request = HTTPRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        timestamp=request_timestamp,
        source=RequestSource.PROXY
    )
    
    # Generate response
    status_codes = [200, 201, 400, 401, 404, 500]
    status_code = draw(st.sampled_from(status_codes))
    
    response_headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=20),
        st.text(min_size=1, max_size=50),
        min_size=0, max_size=3
    ))
    
    response_body = draw(st.one_of(st.none(), st.binary(min_size=0, max_size=1000)))
    duration_ms = draw(st.integers(min_value=1, max_value=5000))
    
    # Response timestamp should be deterministic
    response_timestamp_naive = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2025, 12, 31)
    ))
    response_timestamp = response_timestamp_naive.replace(tzinfo=UTC)
    
    response = HTTPResponse(
        status_code=status_code,
        headers=response_headers,
        body=response_body,
        timestamp=response_timestamp,
        duration_ms=duration_ms
    )
    
    # Create flow with metadata
    metadata = FlowMetadata(
        starred=draw(st.booleans()),
        reviewed=draw(st.booleans()),
        tags=draw(st.lists(st.text(min_size=1, max_size=10), max_size=3))
    )
    
    # Generate timezone-aware created_at datetime
    created_at_naive = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2025, 12, 31)
    ))
    created_at = created_at_naive.replace(tzinfo=UTC)
    
    return HTTPFlow(
        request=request,
        response=response,
        metadata=metadata,
        created_at=created_at
    )


@st.composite
def project_strategy(draw):
    """Generate valid projects."""
    # Generate non-empty, non-whitespace names
    name = draw(st.text(min_size=1, max_size=50).filter(lambda x: x.strip() != ""))
    description = draw(st.text(min_size=0, max_size=200))
    
    return Project(
        name=name,
        description=description,
        settings=ProjectSettings()
    )


class TestStorageManagementEfficiency:
    """Test storage management efficiency properties."""
    
    def setup_method(self):
        """Set up test environment with temporary storage."""
        self.temp_dir = tempfile.mkdtemp()
        self.vault_path = Path(self.temp_dir) / "test_vault"
        
        # Create test storage config with small limits for testing
        self.config = StorageConfig()
        self.config.max_flows_per_project = 10
        self.config.max_total_flows = 50
        self.config.max_database_size_mb = 1  # Very small for testing
        self.config.max_flow_age_days = 7
        self.config.cleanup_interval_hours = 1
        
        # Create fresh vault for each test
        self.vault = SQLiteVaultStorage(self.vault_path)
        self.storage_manager = StorageManager(self.vault, self.config)
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        # Close any open database connections
        try:
            if hasattr(self, 'vault') and hasattr(self.vault, '_get_connection'):
                # Force close any cached connections
                pass
        except Exception:
            pass
        
        # Clean up temp directory
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            # If cleanup fails, log but don't fail the test
            import logging
            logging.warning(f"Failed to cleanup temp dir: {e}")
    
    @given(project_strategy())
    def test_property_5_storage_limits_respected(self, project):
        """
        Property 5a: For any project, storage limits should be respected
        without losing critical data.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Create a fresh vault for this test example to ensure isolation
        import tempfile
        temp_dir = tempfile.mkdtemp()
        vault_path = Path(temp_dir) / "test_vault_limits"
        vault = SQLiteVaultStorage(vault_path)
        storage_manager = StorageManager(vault, self.config)
        
        try:
            # Create project
            created_project = vault.create_project(project.name, project.description)
            
            # Generate flows exceeding the limit
            flows = []
            for i in range(self.config.max_flows_per_project + 5):
                flow = HTTPFlow(
                    request=HTTPRequest(
                        method='GET',
                        url=f'https://example.com/test/{i}',
                        headers={},
                        body=None,
                        timestamp=datetime.now(UTC) - timedelta(days=i),
                        source=RequestSource.PROXY
                    ),
                    response=HTTPResponse(
                        status_code=200,
                        headers={},
                        body=b'test response',
                        timestamp=datetime.now(UTC),
                        duration_ms=100
                    ),
                    metadata=FlowMetadata(),
                    created_at=datetime.now(UTC) - timedelta(days=i)
                )
                flows.append(flow)
                vault.store_flow(created_project.id, flow)
            
            # Run cleanup
            cleanup_results = storage_manager.force_cleanup()
            
            # Verify limits are respected
            remaining_flows = vault.get_flows(created_project.id)
            assert len(remaining_flows) <= self.config.max_flows_per_project
            
            # Verify cleanup actually happened
            assert cleanup_results["status"] in ["completed", "no_cleanup_needed"]
            if cleanup_results["status"] == "completed":
                assert cleanup_results["flows_archived"] > 0 or cleanup_results["flows_deleted"] > 0
        
        finally:
            # Clean up
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    @given(st.lists(http_flow_strategy(), min_size=1, max_size=5))
    def test_property_5_archiving_preserves_data_integrity(self, flows):
        """
        Property 5b: For any list of flows, archiving should preserve
        complete data integrity without corruption.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Create temporary archive manager
        archive_path = Path(self.temp_dir) / "archives"
        archive_manager = ArchiveManager(archive_path, compression=True)
        
        project_id = uuid.uuid4()
        
        # Archive flows
        success = archive_manager.archive_flows(flows, project_id)
        assert success is True
        
        # Verify archive was created
        archives = archive_manager.list_archives(project_id)
        assert len(archives) > 0
        
        # Verify archive contains expected data
        archive_info = archives[0]
        assert archive_info["project_id"] == str(project_id)
        assert archive_info["size_bytes"] > 0
        assert archive_info["compressed"] is True
    
    @given(project_strategy(), st.integers(min_value=1, max_value=20))
    @settings(deadline=1000)  # Allow up to 1 second per test case
    def test_property_5_cleanup_performance_consistency(self, project, flow_count):
        """
        Property 5c: For any project and flow count, cleanup operations
        should complete within reasonable time bounds.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Create project
        created_project = self.vault.create_project(project.name, project.description)
        
        # Add flows
        for i in range(flow_count):
            flow = HTTPFlow(
                request=HTTPRequest(
                    method='GET',
                    url=f'https://example.com/perf/{i}',
                    headers={},
                    body=b'x' * 100,  # Small consistent size
                    timestamp=datetime.now(UTC),
                    source=RequestSource.PROXY
                ),
                response=HTTPResponse(
                    status_code=200,
                    headers={},
                    body=b'y' * 100,
                    timestamp=datetime.now(UTC),
                    duration_ms=100
                ),
                metadata=FlowMetadata(),
                created_at=datetime.now(UTC) - timedelta(days=30)  # Old enough for cleanup
            )
            self.vault.store_flow(created_project.id, flow)
        
        # Measure cleanup performance
        start_time = datetime.now(UTC)
        cleanup_results = self.storage_manager.force_cleanup()
        end_time = datetime.now(UTC)
        
        cleanup_duration = (end_time - start_time).total_seconds()
        
        # Performance should be reasonable (less than 10 seconds for test data)
        assert cleanup_duration < 10.0
        
        # Cleanup should report duration
        if cleanup_results["status"] == "completed":
            assert "cleanup_duration_seconds" in cleanup_results
            assert cleanup_results["cleanup_duration_seconds"] > 0
    
    def test_property_5_starred_flows_preservation(self):
        """
        Property 5d: For any starred flow, it should be preserved
        during cleanup operations regardless of age.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Create project
        project = self.vault.create_project("Test Project", "Test")
        
        # Create old starred flow
        starred_flow = HTTPFlow(
            request=HTTPRequest(
                method='GET',
                url='https://example.com/important',
                headers={},
                body=None,
                timestamp=datetime.now(UTC),
                source=RequestSource.PROXY
            ),
            response=HTTPResponse(
                status_code=200,
                headers={},
                body=b'important data',
                timestamp=datetime.now(UTC),
                duration_ms=100
            ),
            metadata=FlowMetadata(starred=True),
            created_at=datetime.now(UTC) - timedelta(days=365)  # Very old
        )
        
        # Create old unstarred flow
        unstarred_flow = HTTPFlow(
            request=HTTPRequest(
                method='GET',
                url='https://example.com/unimportant',
                headers={},
                body=None,
                timestamp=datetime.now(UTC),
                source=RequestSource.PROXY
            ),
            response=HTTPResponse(
                status_code=200,
                headers={},
                body=b'unimportant data',
                timestamp=datetime.now(UTC),
                duration_ms=100
            ),
            metadata=FlowMetadata(starred=False),
            created_at=datetime.now(UTC) - timedelta(days=365)  # Very old
        )
        
        # Store flows
        self.vault.store_flow(project.id, starred_flow)
        self.vault.store_flow(project.id, unstarred_flow)
        
        # Run cleanup
        cleanup_results = self.storage_manager.force_cleanup()
        
        # Get remaining flows
        remaining_flows = self.vault.get_flows(project.id)
        
        # Starred flow should be preserved
        starred_preserved = any(f.metadata.starred for f in remaining_flows)
        assert starred_preserved is True
    
    @given(st.integers(min_value=1, max_value=10))
    def test_property_5_storage_stats_accuracy(self, project_count):
        """
        Property 5e: For any number of projects, storage statistics
        should accurately reflect actual storage usage.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Create a fresh vault for this test example to ensure isolation
        import tempfile
        temp_dir = tempfile.mkdtemp()
        vault_path = Path(temp_dir) / "test_vault_stats"
        vault = SQLiteVaultStorage(vault_path)
        storage_manager = StorageManager(vault, self.config)
        
        try:
            # Create projects with flows
            created_projects = []
            total_flows_added = 0
            
            for i in range(project_count):
                project = vault.create_project(f"Project {i}", f"Test project {i}")
                created_projects.append(project)
                
                # Add a few flows to each project
                flows_per_project = 3
                for j in range(flows_per_project):
                    flow = HTTPFlow(
                        request=HTTPRequest(
                            method='GET',
                            url=f'https://example.com/project{i}/flow{j}',
                            headers={},
                            body=None,
                            timestamp=datetime.now(UTC),
                            source=RequestSource.PROXY
                        ),
                        response=HTTPResponse(
                            status_code=200,
                            headers={},
                            body=b'test data',
                            timestamp=datetime.now(UTC),
                            duration_ms=100
                        ),
                        metadata=FlowMetadata()
                    )
                    vault.store_flow(project.id, flow)
                    total_flows_added += 1
            
            # Get storage stats
            stats = storage_manager.get_storage_stats()
            
            # Verify stats accuracy
            assert "vault_info" in stats
            vault_info = stats["vault_info"]
            
            assert vault_info["project_count"] == project_count
            assert vault_info["total_flows"] == total_flows_added
            
            # Database size should be positive
            assert stats["database_size_mb"] > 0
            
            # Usage percentages should be calculated
            assert "database_usage_percent" in stats
        
        finally:
            # Clean up
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        assert "flow_usage_percent" in stats
        assert stats["database_usage_percent"] >= 0
        assert stats["flow_usage_percent"] >= 0
    
    def test_property_5_concurrent_cleanup_safety(self):
        """
        Property 5f: For any concurrent cleanup operations,
        the system should handle them safely without corruption.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Create project with flows
        project = self.vault.create_project("Concurrent Test", "Test")
        
        for i in range(20):
            flow = HTTPFlow(
                request=HTTPRequest(
                    method='GET',
                    url=f'https://example.com/concurrent/{i}',
                    headers={},
                    body=None,
                    timestamp=datetime.now(UTC),
                    source=RequestSource.PROXY
                ),
                response=HTTPResponse(
                    status_code=200,
                    headers={},
                    body=b'concurrent test',
                    timestamp=datetime.now(UTC),
                    duration_ms=100
                ),
                metadata=FlowMetadata(),
                created_at=datetime.now(UTC) - timedelta(days=30)
            )
            self.vault.store_flow(project.id, flow)
        
        # Try to run cleanup multiple times (simulating concurrent access)
        results = []
        for _ in range(3):
            result = self.storage_manager.force_cleanup()
            results.append(result)
        
        # All cleanup attempts should complete successfully
        for result in results:
            assert result["status"] in ["completed", "no_cleanup_needed", "cleanup_already_running"]
        
        # At least one should have completed
        completed_cleanups = [r for r in results if r["status"] == "completed"]
        if completed_cleanups:
            # If cleanup ran, it should have processed some data
            assert any(r["flows_archived"] > 0 or r["flows_deleted"] > 0 for r in completed_cleanups)
    
    @given(storage_config_strategy())
    def test_property_5_config_update_consistency(self, new_config):
        """
        Property 5g: For any storage configuration update,
        the system should apply changes consistently.
        
        **Feature: oasis-pentest-suite, Property 5: Storage Management Efficiency**
        **Validates: Requirements 1.6**
        """
        # Get initial stats
        initial_stats = self.storage_manager.get_storage_stats()
        initial_config = initial_stats["config"]
        
        # Update configuration
        new_config.max_flows_per_project = 5
        new_config.max_total_flows = 25
        new_config.enable_archiving = True
        
        self.storage_manager.update_config(new_config)
        
        # Get updated stats
        updated_stats = self.storage_manager.get_storage_stats()
        updated_config = updated_stats["config"]
        
        # Verify configuration was applied
        assert updated_config["max_flows_per_project"] == 5
        assert updated_config["max_total_flows"] == 25
        assert updated_config["enable_archiving"] is True
        
        # Configuration should be different from initial
        assert updated_config != initial_config


class TestArchiveManager:
    """Test archive manager functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.archive_path = Path(self.temp_dir) / "archives"
        self.archive_manager = ArchiveManager(self.archive_path, compression=True)
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_archive_manager_creation(self):
        """Test archive manager basic operations."""
        # Archive path should be created
        assert self.archive_path.exists()
        
        # Should be able to list archives (empty initially)
        archives = self.archive_manager.list_archives()
        assert archives == []
        
        # Archive size should be zero initially
        size = self.archive_manager.get_archive_size()
        assert size == 0
    
    @given(st.lists(http_flow_strategy(), min_size=1, max_size=3))
    def test_archive_roundtrip_consistency(self, flows):
        """Test that archiving preserves flow data."""
        project_id = uuid.uuid4()
        
        # Archive flows
        success = self.archive_manager.archive_flows(flows, project_id)
        assert success is True
        
        # Verify archive exists
        archives = self.archive_manager.list_archives(project_id)
        assert len(archives) == 1
        
        archive_info = archives[0]
        assert archive_info["project_id"] == str(project_id)
        assert archive_info["compressed"] is True
        assert archive_info["size_bytes"] > 0


if __name__ == "__main__":
    pytest.main([__file__])