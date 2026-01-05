"""
Property-based tests for OASIS vault storage operations.

Feature: oasis-pentest-suite, Property 15: Project Data Organization
Validates: Requirements 10.1, 10.4
"""

import tempfile
import uuid
from pathlib import Path
from typing import List

import pytest
from hypothesis import given, strategies as st, settings

from src.oasis.storage.sqlite_vault import SQLiteVaultStorage
from src.oasis.core.models import (
    Project, ProjectSettings, HTTPFlow, HTTPRequest, HTTPResponse, Finding,
    Evidence, User, FlowMetadata, RequestSource, Severity, Confidence, VulnerabilityType
)


# Hypothesis strategies for generating test data
@st.composite
def project_name_strategy(draw):
    """Generate valid project names."""
    return draw(st.text(min_size=1, max_size=100, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Zs'),
        blacklist_characters='\x00\n\r\t'
    )).filter(lambda x: x.strip()))


@st.composite
def project_strategy(draw):
    """Generate valid Project instances."""
    name = draw(project_name_strategy())
    description = draw(st.text(max_size=500, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Po', 'Zs'),
        blacklist_characters='\x00\n\r\t'
    )))
    
    # Simple project settings
    settings = ProjectSettings(
        target_scope=draw(st.lists(st.text(min_size=1, max_size=50), max_size=3)),
        excluded_scope=draw(st.lists(st.text(min_size=1, max_size=50), max_size=3))
    )
    
    return Project(name=name, description=description, settings=settings)


@st.composite
def http_request_strategy(draw):
    """Generate valid HTTPRequest instances."""
    method = draw(st.sampled_from(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']))
    url = draw(st.text(min_size=10, max_size=200).map(lambda x: f"https://example.com/{x.replace(' ', '_')}"))
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-_')),
        st.text(min_size=1, max_size=100),
        max_size=5
    ))
    body = draw(st.one_of(st.none(), st.binary(max_size=500)))
    source = draw(st.sampled_from(list(RequestSource)))
    
    return HTTPRequest(method=method, url=url, headers=headers, body=body, source=source)


@st.composite
def http_response_strategy(draw):
    """Generate valid HTTPResponse instances."""
    status_code = draw(st.integers(min_value=100, max_value=599))
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-_')),
        st.text(min_size=1, max_size=100),
        max_size=5
    ))
    body = draw(st.one_of(st.none(), st.binary(max_size=500)))
    duration_ms = draw(st.integers(min_value=0, max_value=10000))
    
    return HTTPResponse(status_code=status_code, headers=headers, body=body, duration_ms=duration_ms)


@st.composite
def http_flow_strategy(draw):
    """Generate valid HTTPFlow instances."""
    request = draw(http_request_strategy())
    response = draw(st.one_of(st.none(), http_response_strategy()))
    metadata = FlowMetadata(
        tags=draw(st.lists(st.text(min_size=1, max_size=20), max_size=3)),
        notes=draw(st.text(max_size=200))
    )
    
    return HTTPFlow(request=request, response=response, metadata=metadata)


@st.composite
def finding_strategy(draw):
    """Generate valid Finding instances."""
    vulnerability_type = draw(st.sampled_from(list(VulnerabilityType)))
    severity = draw(st.sampled_from(list(Severity)))
    confidence = draw(st.sampled_from(list(Confidence)))
    title = draw(st.text(min_size=1, max_size=100))
    description = draw(st.text(min_size=1, max_size=500))
    evidence = Evidence(payload=draw(st.one_of(st.none(), st.text(max_size=100))))
    remediation = draw(st.text(min_size=1, max_size=200))
    references = draw(st.lists(st.text(min_size=1, max_size=100), max_size=3))
    
    return Finding(
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        references=references
    )


class TestVaultStorageProperties:
    """Property-based tests for vault storage operations."""
    
    @given(project_strategy())
    @settings(max_examples=50)  # Reduce examples for faster testing
    def test_project_storage_organization(self, project: Project):
        """
        Property 15: Project Data Organization
        For any project, storing and retrieving should maintain hierarchical organization with proper metadata.
        **Validates: Requirements 10.1, 10.4**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            vault = SQLiteVaultStorage(Path(temp_dir))
            
            # Store project
            created_project = vault.create_project(project.name, project.description, project.settings)
            
            # Verify project was created with proper organization
            assert created_project.name == project.name
            assert created_project.description == project.description
            assert created_project.settings.target_scope == project.settings.target_scope
            assert created_project.settings.excluded_scope == project.settings.excluded_scope
            assert created_project.id is not None
            assert created_project.created_at is not None
            
            # Retrieve project and verify hierarchical organization
            retrieved_project = vault.get_project(created_project.id)
            assert retrieved_project is not None
            assert retrieved_project.id == created_project.id
            assert retrieved_project.name == created_project.name
            assert retrieved_project.description == created_project.description
            
            # Verify project appears in listing with proper metadata
            projects = vault.list_projects()
            assert len(projects) == 1
            assert projects[0].id == created_project.id
            assert projects[0].name == created_project.name
    
    @given(project_strategy(), st.lists(http_flow_strategy(), min_size=1, max_size=5))
    @settings(max_examples=30)
    def test_flow_storage_organization(self, project: Project, flows: List[HTTPFlow]):
        """
        Property 15: Project Data Organization
        For any project and flows, storing flows should maintain proper hierarchical organization within the project.
        **Validates: Requirements 10.1, 10.4**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            vault = SQLiteVaultStorage(Path(temp_dir))
            
            # Create project
            created_project = vault.create_project(project.name, project.description)
            
            # Store flows in project
            stored_flow_ids = []
            for flow in flows:
                success = vault.store_flow(created_project.id, flow)
                assert success, "Flow storage should succeed"
                stored_flow_ids.append(flow.id)
            
            # Retrieve flows and verify organization
            retrieved_flows = vault.get_flows(created_project.id)
            assert len(retrieved_flows) == len(flows)
            
            # Verify all flows are properly organized under the project
            retrieved_flow_ids = [f.id for f in retrieved_flows]
            for flow_id in stored_flow_ids:
                assert flow_id in retrieved_flow_ids, "All stored flows should be retrievable"
            
            # Verify flows maintain their data integrity
            for retrieved_flow in retrieved_flows:
                original_flow = next(f for f in flows if f.id == retrieved_flow.id)
                assert retrieved_flow.request.method == original_flow.request.method
                assert retrieved_flow.request.url == original_flow.request.url
                assert retrieved_flow.request.headers == original_flow.request.headers
                assert retrieved_flow.request.body == original_flow.request.body
    
    @given(project_strategy(), st.lists(finding_strategy(), min_size=1, max_size=3))
    @settings(max_examples=30)
    def test_finding_storage_organization(self, project: Project, findings: List[Finding]):
        """
        Property 15: Project Data Organization
        For any project and findings, storing findings should maintain proper hierarchical organization.
        **Validates: Requirements 10.1, 10.4**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            vault = SQLiteVaultStorage(Path(temp_dir))
            
            # Create project
            created_project = vault.create_project(project.name, project.description)
            
            # Store findings in project
            stored_finding_ids = []
            for finding in findings:
                success = vault.store_finding(created_project.id, finding)
                assert success, "Finding storage should succeed"
                stored_finding_ids.append(finding.id)
            
            # Retrieve findings and verify organization
            retrieved_findings = vault.get_findings(created_project.id)
            assert len(retrieved_findings) == len(findings)
            
            # Verify all findings are properly organized under the project
            retrieved_finding_ids = [f.id for f in retrieved_findings]
            for finding_id in stored_finding_ids:
                assert finding_id in retrieved_finding_ids, "All stored findings should be retrievable"
            
            # Verify findings maintain their data integrity
            for retrieved_finding in retrieved_findings:
                original_finding = next(f for f in findings if f.id == retrieved_finding.id)
                assert retrieved_finding.vulnerability_type == original_finding.vulnerability_type
                assert retrieved_finding.severity == original_finding.severity
                assert retrieved_finding.confidence == original_finding.confidence
                assert retrieved_finding.title == original_finding.title
                assert retrieved_finding.description == original_finding.description
    
    @given(st.lists(project_strategy(), min_size=2, max_size=5))
    @settings(max_examples=20)
    def test_multi_project_organization(self, projects: List[Project]):
        """
        Property 15: Project Data Organization
        For any collection of projects, the vault should maintain proper hierarchical organization for all projects.
        **Validates: Requirements 10.1, 10.4**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            vault = SQLiteVaultStorage(Path(temp_dir))
            
            # Create all projects
            created_projects = []
            for project in projects:
                created_project = vault.create_project(project.name, project.description, project.settings)
                created_projects.append(created_project)
            
            # Verify all projects are properly organized
            all_projects = vault.list_projects()
            assert len(all_projects) == len(projects)
            
            # Verify each project maintains its identity and organization
            created_project_ids = {p.id for p in created_projects}
            retrieved_project_ids = {p.id for p in all_projects}
            assert created_project_ids == retrieved_project_ids, "All projects should be retrievable"
            
            # Verify individual project retrieval maintains organization
            for created_project in created_projects:
                retrieved_project = vault.get_project(created_project.id)
                assert retrieved_project is not None
                assert retrieved_project.id == created_project.id
                assert retrieved_project.name == created_project.name
                assert retrieved_project.description == created_project.description
    
    @given(project_strategy())
    @settings(max_examples=30)
    def test_project_version_control(self, project: Project):
        """
        Property 15: Project Data Organization
        For any project, version control should maintain proper change tracking.
        **Validates: Requirements 10.4**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            vault = SQLiteVaultStorage(Path(temp_dir))
            
            # Create project
            created_project = vault.create_project(project.name, project.description)
            original_name = created_project.name
            
            # Update project
            created_project.name = f"Updated {original_name}"
            created_project.description = f"Updated {created_project.description}"
            
            success = vault.update_project(created_project)
            assert success, "Project update should succeed"
            
            # Verify updated project maintains organization
            retrieved_project = vault.get_project(created_project.id)
            assert retrieved_project is not None
            assert retrieved_project.id == created_project.id
            assert retrieved_project.name == created_project.name
            assert retrieved_project.description == created_project.description
            
            # Verify project still appears correctly in listings
            projects = vault.list_projects()
            assert len(projects) == 1
            assert projects[0].id == created_project.id
            assert projects[0].name == created_project.name
    
    @given(project_strategy())
    @settings(max_examples=30)
    def test_vault_info_consistency(self, project: Project):
        """
        Property 15: Project Data Organization
        For any vault state, vault info should accurately reflect the hierarchical organization.
        **Validates: Requirements 10.1**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            vault = SQLiteVaultStorage(Path(temp_dir))
            
            # Get initial vault info
            initial_info = vault.get_vault_info()
            assert initial_info["project_count"] == 0
            assert initial_info["total_flows"] == 0
            assert initial_info["total_findings"] == 0
            
            # Create project
            created_project = vault.create_project(project.name, project.description)
            
            # Verify vault info reflects the new organization
            updated_info = vault.get_vault_info()
            assert updated_info["project_count"] == 1
            assert updated_info["total_flows"] == 0  # No flows added yet
            assert updated_info["total_findings"] == 0  # No findings added yet
            assert updated_info["base_path"] == str(temp_dir)
            assert "database_size_bytes" in updated_info
            assert updated_info["database_size_bytes"] > 0