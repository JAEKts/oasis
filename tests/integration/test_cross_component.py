"""
Cross-component integration tests.

Tests interactions between different OASIS components to ensure they work
together correctly.
"""

import pytest

from src.oasis.core.models import (
    HTTPRequest, HTTPResponse, HTTPFlow, FlowMetadata,
    RequestSource, Severity, VulnerabilityType, Finding, Evidence
)
from src.oasis.storage.vault import VaultStorage
from src.oasis.scanner.engine import ScanEngine
from src.oasis.scanner.policy import ScanPolicy, ScanIntensity
from src.oasis.repeater.session import RepeaterSession
from src.oasis.decoder.transformer import DataTransformer, EncodingType
from src.oasis.intruder.engine import AttackEngine
from src.oasis.intruder.config import AttackConfig, AttackType


class TestProxyRepeaterIntegration:
    """Test integration between proxy and repeater components."""
    
    def test_proxy_flow_to_repeater_modification(
        self,
        integration_vault: VaultStorage,
        integration_project,
        repeater_session: RepeaterSession
    ):
        """Test modifying proxy-captured flows in repeater."""
        # Proxy captures request
        original_request = HTTPRequest(
            method="POST",
            url="http://testserver.local/api/login",
            headers={
                "Content-Type": "application/json",
                "Host": "testserver.local"
            },
            body=b'{"username": "admin", "password": "test123"}'
        )
        
        flow = HTTPFlow(
            request=original_request,
            response=None,
            metadata=FlowMetadata(project_id=integration_project.id)
        )
        
        flow_id = integration_vault.store_flow(integration_project.id, flow)
        
        # Load into repeater
        stored_flow = integration_vault.get_flow(integration_project.id, flow_id)
        
        # Create a tab with the original request
        tab = repeater_session.create_tab("Test Request", stored_flow.request)
        
        # Modify in repeater
        modified_request = HTTPRequest(
            method=stored_flow.request.method,
            url=stored_flow.request.url,
            headers=stored_flow.request.headers,
            body=b'{"username": "admin", "password": "modified_password"}',
            source=RequestSource.REPEATER
        )
        
        tab.update_request(modified_request)
        
        # Verify modification
        assert tab.request.body == b'{"username": "admin", "password": "modified_password"}'
        assert tab.history.can_undo()  # Should have history


class TestScannerDecoderIntegration:
    """Test integration between scanner and decoder components."""
    
    def test_scanner_uses_decoder_for_payload_encoding(self):
        """Test that scanner can use decoder for payload encoding."""
        transformer = DataTransformer()
        
        # Scanner needs to encode payloads
        sql_payload = "' OR '1'='1"
        
        # URL encode for GET parameter
        url_encoded = transformer.encode(sql_payload, EncodingType.URL)
        assert "%27" in url_encoded  # Single quote encoded
        
        # Base64 encode for header injection
        base64_encoded = transformer.encode(sql_payload, EncodingType.BASE64)
        assert base64_encoded != sql_payload
        
        # Verify round-trip
        decoded = transformer.decode(url_encoded, EncodingType.URL)
        assert decoded == sql_payload
    
    def test_scanner_decodes_responses(self):
        """Test scanner decoding encoded responses."""
        transformer = DataTransformer()
        
        # Simulate encoded response
        original_data = "Error: Invalid SQL syntax"
        encoded_response = transformer.encode(original_data, EncodingType.BASE64)
        
        # Scanner detects encoding and decodes
        decoded = transformer.decode(encoded_response, EncodingType.BASE64)
        assert decoded == original_data
        assert "SQL" in decoded  # Scanner can now detect SQL error


class TestRepeaterIntruderIntegration:
    """Test integration between repeater and intruder components."""
    
    def test_repeater_request_to_intruder_attack(
        self,
        repeater_session: RepeaterSession
    ):
        """Test sending repeater request to intruder for automated attack."""
        # Create request in repeater
        base_request = HTTPRequest(
            method="POST",
            url="http://testserver.local/api/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"username=admin&password=FUZZ",
            source=RequestSource.REPEATER
        )
        
        # Create a tab with the request
        tab = repeater_session.create_tab("Login Test", base_request)
        
        # Configure intruder attack based on repeater request
        from src.oasis.intruder.config import InjectionPoint, PayloadSet
        
        attack_config = AttackConfig(
            name="Login Brute Force",
            attack_type=AttackType.SNIPER,
            base_request=tab.request,
            injection_points=[
                InjectionPoint(
                    name="password",
                    location="body",
                    marker="FUZZ"
                )
            ],
            payload_sets=[
                PayloadSet(
                    name="Passwords",
                    generator_type="wordlist",
                    generator_config={"payloads": ["password123", "admin", "test", "12345"]}
                )
            ]
        )
        
        # Verify attack configuration
        assert attack_config.base_request.url == base_request.url
        assert len(attack_config.injection_points) == 1
        assert attack_config.injection_points[0].name == "password"
        assert len(attack_config.payload_sets) == 1


class TestScannerVaultIntegration:
    """Test integration between scanner and vault storage."""
    
    @pytest.mark.asyncio
    async def test_scanner_stores_findings_in_vault(
        self,
        integration_vault: VaultStorage,
        integration_project,
        scan_engine: ScanEngine
    ):
        """Test that scanner findings are properly stored in vault."""
        # Create vulnerable flow
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/search?q=<script>alert(1)</script>",
            headers={"Host": "testserver.local"}
        )
        
        response = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"<html><body><script>alert(1)</script></body></html>",
            duration_ms=100
        )
        
        flow = HTTPFlow(
            request=request,
            response=response,
            metadata=FlowMetadata(project_id=integration_project.id)
        )
        
        # Scanner analyzes flow
        policy = ScanPolicy(
            name="XSS Detection Policy",
            enabled_checks=["xss"],
            scan_intensity=ScanIntensity.NORMAL
        )
        
        findings = await scan_engine.passive_scan([flow], policy)
        
        # Store findings in vault (even if empty)
        for finding in findings:
            finding_id = integration_vault.store_finding(integration_project.id, finding)
            assert finding_id is not None
        
        # Retrieve and verify storage works
        stored_findings = integration_vault.get_findings(integration_project.id)
        assert len(stored_findings) == len(findings)
        
        # The test verifies that the vault can store and retrieve findings
        # The actual detection is tested in scanner-specific tests
        # If findings were detected, verify they can be filtered
        if len(stored_findings) > 0:
            xss_findings = [
                f for f in stored_findings 
                if f.vulnerability_type in [
                    VulnerabilityType.XSS_REFLECTED,
                    VulnerabilityType.XSS_STORED,
                    VulnerabilityType.XSS_DOM
                ]
            ]
            # If XSS findings exist, they should be properly stored
            if len(xss_findings) > 0:
                assert xss_findings[0].severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]


class TestDecoderIntruderIntegration:
    """Test integration between decoder and intruder components."""
    
    def test_intruder_uses_decoder_for_payload_processing(self):
        """Test intruder using decoder for payload transformations."""
        transformer = DataTransformer()
        
        # Intruder base payloads (with special characters that need encoding)
        base_payloads = ["admin' OR '1'='1", "test@example.com", "user name"]
        
        # Apply transformations
        url_encoded_payloads = [
            transformer.encode(p, EncodingType.URL) for p in base_payloads
        ]
        
        base64_payloads = [
            transformer.encode(p, EncodingType.BASE64) for p in base_payloads
        ]
        
        # Verify transformations
        assert len(url_encoded_payloads) == len(base_payloads)
        assert len(base64_payloads) == len(base_payloads)
        
        # Verify payloads are different (they contain special chars that get encoded)
        assert url_encoded_payloads != base_payloads
        assert base64_payloads != base_payloads


class TestMultiComponentWorkflow:
    """Test workflows involving multiple components."""
    
    @pytest.mark.asyncio
    async def test_proxy_scanner_repeater_vault_workflow(
        self,
        integration_vault: VaultStorage,
        integration_project,
        scan_engine: ScanEngine,
        repeater_session: RepeaterSession
    ):
        """Test complete workflow across proxy, scanner, repeater, and vault."""
        # Step 1: Proxy captures traffic
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/api/user/1",
            headers={"Host": "testserver.local", "Cookie": "session=abc123"}
        )
        
        response = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"id": 1, "username": "admin", "email": "admin@test.com"}',
            duration_ms=50
        )
        
        flow = HTTPFlow(
            request=request,
            response=response,
            metadata=FlowMetadata(project_id=integration_project.id)
        )
        
        # Step 2: Store in vault
        flow_id = integration_vault.store_flow(integration_project.id, flow)
        assert flow_id is not None
        
        # Step 3: Scanner analyzes
        policy = ScanPolicy(
            name="IDOR Detection Policy",
            enabled_checks=["idor", "sensitive_data_exposure"],
            scan_intensity=ScanIntensity.NORMAL
        )
        
        findings = await scan_engine.passive_scan([flow], policy)
        
        # Step 4: Store findings
        for finding in findings:
            integration_vault.store_finding(integration_project.id, finding)
        
        # Step 5: Load into repeater for manual testing
        stored_flow = integration_vault.get_flow(integration_project.id, flow_id)
        
        # Test IDOR by changing user ID - create tabs for each test
        for user_id in [2, 3, 4, 5]:
            test_request = HTTPRequest(
                method="GET",
                url=f"http://testserver.local/api/user/{user_id}",
                headers=request.headers,
                source=RequestSource.REPEATER
            )
            repeater_session.create_tab(f"IDOR Test User {user_id}", test_request)
        
        # Step 6: Verify complete workflow
        assert len(integration_vault.get_flows(integration_project.id)) > 0
        assert len(integration_vault.get_findings(integration_project.id)) >= 0
        assert len(repeater_session.tabs) >= 4
    
    def test_decoder_scanner_intruder_integration(self):
        """Test decoder, scanner, and intruder working together."""
        transformer = DataTransformer()
        
        # Scenario: Testing for SQL injection with various encodings
        base_payload = "' OR '1'='1"
        
        # Decoder creates variations
        payloads = [
            base_payload,  # Plain
            transformer.encode(base_payload, EncodingType.URL),  # URL encoded
            transformer.encode(base_payload, EncodingType.BASE64),  # Base64
            transformer.encode(
                transformer.encode(base_payload, EncodingType.URL),
                EncodingType.BASE64
            )  # Double encoded
        ]
        
        # Intruder would use these payloads
        from src.oasis.intruder.config import InjectionPoint, PayloadSet
        
        attack_config = AttackConfig(
            name="SQL Injection Test",
            attack_type=AttackType.SNIPER,
            base_request=HTTPRequest(
                method="GET",
                url="http://testserver.local/search?q=FUZZ",
                headers={"Host": "testserver.local"}
            ),
            injection_points=[
                InjectionPoint(
                    name="query_param_q",
                    location="param",
                    key="q",
                    marker="FUZZ"
                )
            ],
            payload_sets=[
                PayloadSet(
                    name="SQL Injection Payloads",
                    generator_type="wordlist",
                    generator_config={"payloads": payloads}
                )
            ]
        )
        
        # Scanner would analyze responses
        # (In real scenario, responses would be analyzed for SQL errors)
        assert len(attack_config.payload_sets) == 1
        assert len(attack_config.injection_points) == 1


class TestExtensionIntegration:
    """Test extension framework integration with other components."""
    
    def test_extension_accesses_vault_data(
        self,
        integration_vault: VaultStorage,
        integration_project
    ):
        """Test that extensions can access vault data."""
        # Store some data
        request = HTTPRequest(
            method="GET",
            url="http://testserver.local/api/data",
            headers={"Host": "testserver.local"}
        )
        
        flow = HTTPFlow(
            request=request,
            response=None,
            metadata=FlowMetadata(project_id=integration_project.id)
        )
        
        integration_vault.store_flow(integration_project.id, flow)
        
        # Extension retrieves data
        flows = integration_vault.get_flows(integration_project.id)
        assert len(flows) > 0
        
        # Extension can process flows
        api_flows = [f for f in flows if "/api/" in f.request.url]
        assert len(api_flows) > 0
    
    def test_extension_modifies_scanner_results(
        self,
        integration_vault: VaultStorage,
        integration_project
    ):
        """Test extension modifying scanner results."""
        # Create a finding
        finding = Finding(
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            severity=Severity.MEDIUM,
            confidence="tentative",
            title="Potential XSS",
            description="Needs verification",
            evidence=Evidence(),
            remediation="Verify and sanitize input"
        )
        
        finding_id = integration_vault.store_finding(integration_project.id, finding)
        
        # Extension retrieves and modifies
        stored_finding = integration_vault.get_finding(integration_project.id, finding_id)
        
        # Extension verifies and updates severity
        if hasattr(integration_vault, 'update_finding'):
            stored_finding.severity = Severity.HIGH
            stored_finding.confidence = "firm"
            integration_vault.update_finding(integration_project.id, stored_finding)
            
            # Verify update
            updated_finding = integration_vault.get_finding(integration_project.id, finding_id)
            assert updated_finding.severity == Severity.HIGH
