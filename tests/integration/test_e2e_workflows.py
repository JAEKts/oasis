"""
End-to-end workflow integration tests.

Tests the complete workflow from proxy interception through scanner analysis
and repeater manipulation.
"""

import asyncio
import pytest

from src.oasis.core.models import (
    HTTPRequest, HTTPResponse, HTTPFlow, FlowMetadata,
    RequestSource, Severity, VulnerabilityType
)
from src.oasis.storage.vault import VaultStorage
from src.oasis.scanner.engine import ScanEngine
from src.oasis.scanner.policy import ScanPolicy, ScanIntensity
from src.oasis.repeater.session import RepeaterSession
from src.oasis.proxy.filtering import FilterEngine


class TestProxyToScannerWorkflow:
    """Test workflow from proxy capture to scanner analysis."""
    
    @pytest.mark.asyncio
    async def test_proxy_capture_to_scanner_analysis(
        self,
        integration_vault: VaultStorage,
        integration_project,
        sample_http_request,
        sample_http_response
    ):
        """Test that traffic captured by proxy can be analyzed by scanner."""
        # Use the project ID from the fixture
        project_id = integration_project.id
        
        # Step 1: Simulate proxy capturing traffic
        flow = HTTPFlow(
            request=sample_http_request,
            response=sample_http_response,
            metadata=FlowMetadata(project_id=project_id)
        )
        
        # Store the flow in vault
        flow_id = integration_vault.store_flow(project_id, flow)
        assert flow_id is not None
        
        # Step 2: Retrieve flows for scanning
        stored_flows = integration_vault.get_flows(project_id)
        assert len(stored_flows) > 0
        assert stored_flows[0].id == flow.id
        
        # Step 3: Scanner analyzes the captured traffic
        scan_engine = ScanEngine()
        policy = ScanPolicy(
            name="Basic Security Scan",
            enabled_checks=["sql_injection", "xss"],
            scan_intensity=ScanIntensity.NORMAL
        )
        
        # Passive scan of captured traffic
        findings = await scan_engine.passive_scan([flow], policy)
        
        # Verify findings can be stored
        for finding in findings:
            finding_id = integration_vault.store_finding(project_id, finding)
            assert finding_id is not None
    
    @pytest.mark.asyncio
    async def test_proxy_to_scanner_async_workflow(
        self,
        integration_vault: VaultStorage,
        integration_project,
        scan_engine: ScanEngine
    ):
        """Test async workflow from proxy to scanner."""
        # Use the project ID from the fixture
        project_id = integration_project.id
        
        # Create multiple flows
        flows = []
        for i in range(5):
            request = HTTPRequest(
                method="GET",
                url=f"http://testserver.local/api/endpoint{i}",
                headers={"Host": "testserver.local"}
            )
            response = HTTPResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><body>Test</body></html>",
                duration_ms=50 + i * 10
            )
            flow = HTTPFlow(
                request=request,
                response=response,
                metadata=FlowMetadata(project_id=project_id)
            )
            flows.append(flow)
            integration_vault.store_flow(project_id, flow)
        
        # Scan all flows
        policy = ScanPolicy(
            name="Async Scan Policy",
            enabled_checks=["xss", "csrf"],
            scan_intensity=ScanIntensity.LIGHT
        )
        
        findings = await scan_engine.passive_scan(flows, policy)
        
        # Store findings
        for finding in findings:
            integration_vault.store_finding(project_id, finding)
        
        # Verify we can retrieve findings
        stored_findings = integration_vault.get_findings(project_id)
        assert len(stored_findings) == len(findings)


class TestProxyToRepeaterWorkflow:
    """Test workflow from proxy capture to repeater manipulation."""
    
    def test_proxy_to_repeater_send(
        self,
        integration_vault: VaultStorage,
        integration_project,
        repeater_session: RepeaterSession,
        sample_http_request
    ):
        """Test sending captured traffic through repeater."""
        # Step 1: Capture traffic in proxy
        flow = HTTPFlow(
            request=sample_http_request,
            response=None,
            metadata=FlowMetadata(project_id=integration_project.id)
        )
        
        flow_id = integration_vault.store_flow(integration_project.id, flow)
        
        # Step 2: Load flow into repeater
        stored_flow = integration_vault.get_flow(integration_project.id, flow_id)
        assert stored_flow is not None
        
        # Step 3: Modify request in repeater
        modified_request = HTTPRequest(
            method=stored_flow.request.method,
            url=stored_flow.request.url,
            headers={**stored_flow.request.headers, "X-Custom-Header": "test"},
            body=stored_flow.request.body,
            source=RequestSource.REPEATER
        )
        
        # Create a tab with the modified request
        tab = repeater_session.create_tab("Modified Request", modified_request)
        
        # Verify tab was created
        assert tab is not None
        assert tab.request.headers.get("X-Custom-Header") == "test"
    
    def test_repeater_undo_redo_workflow(
        self,
        repeater_session: RepeaterSession,
        sample_http_request
    ):
        """Test undo/redo functionality in repeater workflow."""
        # Create a tab with initial request
        tab = repeater_session.create_tab("Test Request", sample_http_request)
        
        # Modify request multiple times
        for i in range(3):
            modified = HTTPRequest(
                method=sample_http_request.method,
                url=sample_http_request.url,
                headers={**sample_http_request.headers, f"X-Iteration": str(i)},
                body=sample_http_request.body,
                source=RequestSource.REPEATER
            )
            tab.update_request(modified)
        
        # Verify history
        assert tab.history.can_undo()
        
        # Test undo
        success = tab.undo()
        assert success
        assert tab.request.headers.get("X-Iteration") == "1"  # Should be back to iteration 1
        
        # Test redo
        success = tab.redo()
        assert success
        assert tab.request.headers.get("X-Iteration") == "2"  # Should be forward to iteration 2


class TestScannerToRepeaterWorkflow:
    """Test workflow from scanner findings to repeater verification."""
    
    def test_scanner_finding_to_repeater_verification(
        self,
        integration_vault: VaultStorage,
        integration_project,
        repeater_session: RepeaterSession
    ):
        """Test verifying scanner findings using repeater."""
        # Step 1: Create a finding from scanner
        from src.oasis.core.models import Finding, Evidence
        
        vulnerable_request = HTTPRequest(
            method="GET",
            url="http://testserver.local/search?q=<script>alert(1)</script>",
            headers={"Host": "testserver.local"}
        )
        
        vulnerable_response = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"<html><body><script>alert(1)</script></body></html>",
            duration_ms=100
        )
        
        finding = Finding(
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            severity=Severity.HIGH,
            confidence="firm",
            title="Reflected XSS in search parameter",
            description="User input is reflected without sanitization",
            evidence=Evidence(
                request=vulnerable_request,
                response=vulnerable_response,
                payload="<script>alert(1)</script>",
                location="query parameter 'q'"
            ),
            remediation="Sanitize user input before rendering"
        )
        
        # Store finding
        finding_id = integration_vault.store_finding(integration_project.id, finding)
        assert finding_id is not None
        
        # Step 2: Load finding into repeater for manual verification
        stored_finding = integration_vault.get_finding(integration_project.id, finding_id)
        assert stored_finding is not None
        
        # Step 3: Use repeater to test variations
        test_payloads = [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)"
        ]
        
        # Create tabs for each test payload
        for i, payload in enumerate(test_payloads):
            test_request = HTTPRequest(
                method="GET",
                url=f"http://testserver.local/search?q={payload}",
                headers={"Host": "testserver.local"},
                source=RequestSource.REPEATER
            )
            repeater_session.create_tab(f"XSS Test {i+1}", test_request)
        
        # Verify all test tabs were created
        assert len(repeater_session.tabs) >= len(test_payloads)


class TestCompleteE2EWorkflow:
    """Test complete end-to-end workflow across all components."""
    
    @pytest.mark.asyncio
    async def test_full_penetration_testing_workflow(
        self,
        integration_vault: VaultStorage,
        integration_project,
        scan_engine: ScanEngine,
        repeater_session: RepeaterSession
    ):
        """Test complete workflow: proxy → scanner → repeater → findings."""
        # Phase 1: Proxy captures traffic
        captured_flows = []
        endpoints = [
            "/login",
            "/api/users",
            "/api/products",
            "/search",
            "/profile"
        ]
        
        for endpoint in endpoints:
            request = HTTPRequest(
                method="GET",
                url=f"http://testserver.local{endpoint}",
                headers={"Host": "testserver.local", "Cookie": "session=abc123"}
            )
            response = HTTPResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><body>Content</body></html>",
                duration_ms=75
            )
            flow = HTTPFlow(
                request=request,
                response=response,
                metadata=FlowMetadata(
                    project_id=integration_project.id,
                    tags=["initial-scan"]
                )
            )
            captured_flows.append(flow)
            integration_vault.store_flow(integration_project.id, flow)
        
        # Phase 2: Scanner analyzes captured traffic
        policy = ScanPolicy(
            name="Full Pentest Scan",
            enabled_checks=["sql_injection", "xss", "csrf"],
            scan_intensity=ScanIntensity.NORMAL
        )
        
        findings = await scan_engine.passive_scan(captured_flows, policy)
        
        # Store findings
        for finding in findings:
            integration_vault.store_finding(integration_project.id, finding)
        
        # Phase 3: High severity findings go to repeater for verification
        high_severity_findings = [
            f for f in findings 
            if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        # Create tabs for high severity findings
        for i, finding in enumerate(high_severity_findings):
            if finding.evidence.request:
                repeater_session.create_tab(
                    f"High Severity Finding {i+1}",
                    finding.evidence.request
                )
        
        # Phase 4: Verify data integrity across all components
        # Check vault has all flows
        stored_flows = integration_vault.get_flows(integration_project.id)
        assert len(stored_flows) == len(captured_flows)
        
        # Check vault has all findings
        stored_findings = integration_vault.get_findings(integration_project.id)
        assert len(stored_findings) == len(findings)
        
        # Check repeater has high severity requests as tabs
        assert len(repeater_session.tabs) >= len(high_severity_findings)
        
        # Phase 5: Export results
        export_data = {
            "project": integration_project.model_dump(),
            "flows": [f.model_dump() for f in stored_flows],
            "findings": [f.model_dump() for f in stored_findings]
        }
        
        assert export_data["project"]["name"] == integration_project.name
        assert len(export_data["flows"]) > 0
        assert len(export_data["findings"]) >= 0


class TestFilteringWorkflow:
    """Test traffic filtering integration."""
    
    def test_proxy_filtering_integration(
        self,
        integration_vault: VaultStorage,
        integration_project
    ):
        """Test that filtering rules are applied correctly in workflow."""
        # Create flows with different characteristics
        flows_to_test = [
            ("http://testserver.local/api/users", True),  # Should be included
            ("http://testserver.local/admin/config", False),  # Should be excluded
            ("http://testserver.local/public/images/logo.png", True),  # Should be included
            ("http://testserver.local/admin/users", False),  # Should be excluded
        ]
        
        for url, should_include in flows_to_test:
            request = HTTPRequest(
                method="GET",
                url=url,
                headers={"Host": "testserver.local"}
            )
            
            # Check if URL matches scope
            in_scope = any(
                url.startswith(scope.rstrip('*'))
                for scope in integration_project.settings.target_scope
            )
            
            excluded = any(
                url.startswith(excluded.rstrip('*'))
                for excluded in integration_project.settings.excluded_scope
            )
            
            should_store = in_scope and not excluded
            
            if should_store:
                flow = HTTPFlow(
                    request=request,
                    response=None,
                    metadata=FlowMetadata(project_id=integration_project.id)
                )
                integration_vault.store_flow(integration_project.id, flow)
        
        # Verify only in-scope flows were stored
        stored_flows = integration_vault.get_flows(integration_project.id)
        stored_urls = [f.request.url for f in stored_flows]
        
        # Should include non-admin URLs
        assert any("/api/users" in url for url in stored_urls)
        assert any("/public/images" in url for url in stored_urls)
        
        # Should not include admin URLs
        assert not any("/admin/" in url for url in stored_urls)
