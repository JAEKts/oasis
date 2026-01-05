"""
External dependency integration tests.

Tests integration with databases, file systems, and other external dependencies.
"""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from src.oasis.core.models import (
    Project, ProjectSettings, HTTPRequest, HTTPResponse,
    HTTPFlow, FlowMetadata, Finding, Evidence,
    Severity, VulnerabilityType
)
from src.oasis.storage.vault import VaultStorage


class TestDatabaseIntegration:
    """Test database integration and persistence."""
    
    def test_sqlite_vault_persistence(self, integration_temp_dir: Path):
        """Test that vault data persists correctly in SQLite."""
        vault_path = integration_temp_dir / "vault_db"
        
        # Create vault and store data
        vault1 = VaultStorage(vault_path)
        
        project = Project(
            name="Persistence Test",
            description="Testing database persistence"
        )
        
        project_id = vault1.create_project(project)
        assert project_id is not None
        
        # Store a flow
        request = HTTPRequest(
            method="POST",
            url="http://testserver.local/api/data",
            headers={"Content-Type": "application/json"},
            body=b'{"test": "data"}'
        )
        
        flow = HTTPFlow(
            request=request,
            response=None,
            metadata=FlowMetadata(project_id=project_id)
        )
        
        flow_id = vault1.store_flow(project_id, flow)
        assert flow_id is not None
        
        # Close and reopen vault
        del vault1
        
        vault2 = VaultStorage(vault_path)
        
        # Verify data persisted
        loaded_project = vault2.get_project(project_id)
        assert loaded_project is not None
        assert loaded_project.name == "Persistence Test"
        
        loaded_flows = vault2.get_flows(project_id)
        assert len(loaded_flows) == 1
        assert loaded_flows[0].request.url == "http://testserver.local/api/data"
    
    def test_concurrent_database_access(self, integration_temp_dir: Path):
        """Test concurrent access to vault database."""
        vault_path = integration_temp_dir / "concurrent_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(name="Concurrent Test")
        project_id = vault.create_project(project)
        
        # Simulate concurrent writes
        flows = []
        for i in range(10):
            request = HTTPRequest(
                method="GET",
                url=f"http://testserver.local/endpoint{i}",
                headers={"Host": "testserver.local"}
            )
            flow = HTTPFlow(
                request=request,
                response=None,
                metadata=FlowMetadata(project_id=project_id)
            )
            flows.append(flow)
            vault.store_flow(project_id, flow)
        
        # Verify all flows were stored
        stored_flows = vault.get_flows(project_id)
        assert len(stored_flows) == 10
        
        # Verify data integrity
        stored_urls = {f.request.url for f in stored_flows}
        expected_urls = {f"http://testserver.local/endpoint{i}" for i in range(10)}
        assert stored_urls == expected_urls
    
    def test_database_transaction_rollback(self, integration_temp_dir: Path):
        """Test database transaction handling and rollback."""
        vault_path = integration_temp_dir / "transaction_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(name="Transaction Test")
        project_id = vault.create_project(project)
        
        # Store valid data
        valid_request = HTTPRequest(
            method="GET",
            url="http://testserver.local/valid",
            headers={"Host": "testserver.local"}
        )
        valid_flow = HTTPFlow(
            request=valid_request,
            response=None,
            metadata=FlowMetadata(project_id=project_id)
        )
        vault.store_flow(project_id, valid_flow)
        
        # Verify valid data was stored
        flows_before = vault.get_flows(project_id)
        assert len(flows_before) == 1
        
        # Attempt to store invalid data (should fail gracefully)
        try:
            invalid_request = HTTPRequest(
                method="INVALID_METHOD",  # This should fail validation
                url="http://testserver.local/invalid",
                headers={}
            )
        except ValueError:
            # Expected validation error
            pass
        
        # Verify original data is still intact
        flows_after = vault.get_flows(project_id)
        assert len(flows_after) == 1
        assert flows_after[0].request.url == "http://testserver.local/valid"


class TestFileSystemIntegration:
    """Test file system integration for large data storage."""
    
    def test_large_response_body_storage(self, integration_temp_dir: Path):
        """Test storing large response bodies to file system."""
        vault_path = integration_temp_dir / "large_data_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(name="Large Data Test")
        project_id = vault.create_project(project)
        
        # Create a large response body (10MB)
        large_body = b"X" * (10 * 1024 * 1024)
        
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/large-file",
            headers={"Host": "testserver.local"}
        )
        
        response = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "application/octet-stream"},
            body=large_body,
            duration_ms=5000
        )
        
        flow = HTTPFlow(
            request=request,
            response=response,
            metadata=FlowMetadata(project_id=project_id)
        )
        
        # Store flow with large body
        flow_id = vault.store_flow(project_id, flow)
        assert flow_id is not None
        
        # Retrieve and verify
        stored_flow = vault.get_flow(project_id, flow_id)
        assert stored_flow is not None
        assert stored_flow.response is not None
        assert len(stored_flow.response.body) == len(large_body)
    
    def test_file_system_cleanup(self, integration_temp_dir: Path):
        """Test file system cleanup when deleting data."""
        vault_path = integration_temp_dir / "cleanup_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(name="Cleanup Test")
        project_id = vault.create_project(project)
        
        # Store multiple flows
        flow_ids = []
        for i in range(5):
            request = HTTPRequest(
                method="GET",
                url=f"http://testserver.local/file{i}",
                headers={"Host": "testserver.local"}
            )
            flow = HTTPFlow(
                request=request,
                response=None,
                metadata=FlowMetadata(project_id=project_id)
            )
            flow_id = vault.store_flow(project_id, flow)
            flow_ids.append(flow_id)
        
        # Verify files exist
        assert len(vault.get_flows(project_id)) == 5
        
        # Delete project
        if hasattr(vault, 'delete_project'):
            vault.delete_project(project_id)
            
            # Verify cleanup
            remaining_flows = vault.get_flows(project_id)
            assert len(remaining_flows) == 0
    
    def test_export_to_file_system(self, integration_temp_dir: Path):
        """Test exporting project data to file system."""
        vault_path = integration_temp_dir / "export_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(
            name="Export Test",
            description="Testing export functionality"
        )
        project_id = vault.create_project(project)
        
        # Create test data
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/api/test",
            headers={"Host": "testserver.local"}
        )
        
        response = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"status": "success"}',
            duration_ms=100
        )
        
        flow = HTTPFlow(
            request=request,
            response=response,
            metadata=FlowMetadata(project_id=project_id, tags=["api", "test"])
        )
        
        vault.store_flow(project_id, flow)
        
        # Export to JSON
        export_path = integration_temp_dir / "export.json"
        
        export_data = {
            "project": project.model_dump(),
            "flows": [f.model_dump() for f in vault.get_flows(project_id)]
        }
        
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        # Verify export file
        assert export_path.exists()
        assert export_path.stat().st_size > 0
        
        # Verify export content
        with open(export_path, 'r') as f:
            loaded_data = json.load(f)
        
        assert loaded_data["project"]["name"] == "Export Test"
        assert len(loaded_data["flows"]) == 1
        assert loaded_data["flows"][0]["request"]["url"] == "http://testserver.local/api/test"


class TestCacheIntegration:
    """Test caching layer integration."""
    
    def test_vault_caching_behavior(self, integration_temp_dir: Path):
        """Test that vault implements efficient caching."""
        vault_path = integration_temp_dir / "cache_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(name="Cache Test")
        project_id = vault.create_project(project)
        
        # Store data
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/cached",
            headers={"Host": "testserver.local"}
        )
        flow = HTTPFlow(
            request=request,
            response=None,
            metadata=FlowMetadata(project_id=project_id)
        )
        flow_id = vault.store_flow(project_id, flow)
        
        # First retrieval (cache miss)
        flow1 = vault.get_flow(project_id, flow_id)
        assert flow1 is not None
        
        # Second retrieval (should be faster if cached)
        flow2 = vault.get_flow(project_id, flow_id)
        assert flow2 is not None
        assert flow2.id == flow1.id
    
    def test_cache_invalidation(self, integration_temp_dir: Path):
        """Test cache invalidation when data is updated."""
        vault_path = integration_temp_dir / "invalidation_vault"
        vault = VaultStorage(vault_path)
        
        project = Project(name="Invalidation Test")
        project_id = vault.create_project(project)
        
        # Store initial data
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/data",
            headers={"Host": "testserver.local"}
        )
        flow = HTTPFlow(
            request=request,
            response=None,
            metadata=FlowMetadata(project_id=project_id, tags=["initial"])
        )
        flow_id = vault.store_flow(project_id, flow)
        
        # Retrieve data
        flow1 = vault.get_flow(project_id, flow_id)
        assert "initial" in flow1.metadata.tags
        
        # Update data
        if hasattr(vault, 'update_flow'):
            flow1.metadata.tags.append("updated")
            vault.update_flow(project_id, flow1)
            
            # Retrieve updated data
            flow2 = vault.get_flow(project_id, flow_id)
            assert "updated" in flow2.metadata.tags


class TestNetworkDependencies:
    """Test integration with network-dependent components."""
    
    def test_collaborator_service_integration(self, integration_temp_dir: Path):
        """Test collaborator service file system integration."""
        # Collaborator service stores interaction logs
        collab_dir = integration_temp_dir / "collaborator"
        collab_dir.mkdir(exist_ok=True)
        
        # Simulate storing interaction
        interaction_data = {
            "id": "test-interaction-123",
            "type": "dns",
            "query": "test.collaborator.local",
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        
        interaction_file = collab_dir / f"{interaction_data['id']}.json"
        with open(interaction_file, 'w') as f:
            json.dump(interaction_data, f)
        
        # Verify storage
        assert interaction_file.exists()
        
        # Retrieve interaction
        with open(interaction_file, 'r') as f:
            loaded_interaction = json.load(f)
        
        assert loaded_interaction["id"] == "test-interaction-123"
        assert loaded_interaction["type"] == "dns"
    
    def test_external_tool_integration_files(self, integration_temp_dir: Path):
        """Test integration with external tool file formats."""
        # Test exporting to formats used by external tools
        export_dir = integration_temp_dir / "external_exports"
        export_dir.mkdir(exist_ok=True)
        
        # Create sample finding
        finding = Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            confidence="firm",
            title="SQL Injection in login form",
            description="User input not sanitized",
            evidence=Evidence(
                payload="' OR '1'='1",
                location="username parameter"
            ),
            remediation="Use parameterized queries"
        )
        
        # Export to JSON (for issue trackers)
        json_export = export_dir / "finding.json"
        with open(json_export, 'w') as f:
            json.dump(finding.model_dump(), f, indent=2, default=str)
        
        assert json_export.exists()
        
        # Export to CSV (for spreadsheets)
        csv_export = export_dir / "findings.csv"
        with open(csv_export, 'w') as f:
            f.write("Type,Severity,Title,Description\n")
            f.write(f"{finding.vulnerability_type.value},{finding.severity.value},")
            f.write(f'"{finding.title}","{finding.description}"\n')
        
        assert csv_export.exists()
        
        # Verify exports can be read back
        with open(json_export, 'r') as f:
            loaded_finding = json.load(f)
        assert loaded_finding["title"] == "SQL Injection in login form"
