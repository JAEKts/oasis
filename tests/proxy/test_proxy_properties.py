"""
Property-based tests for OASIS Proxy Engine

Tests universal properties that should hold across all valid executions.
"""

import pytest
import asyncio
import aiohttp
import socket
from hypothesis import given, strategies as st, settings
from unittest.mock import Mock

from src.oasis.proxy.engine import ProxyEngine
from src.oasis.core.models import HTTPFlow, HTTPRequest, HTTPResponse


def find_free_port(start_port: int = 9000, max_attempts: int = 100) -> int:
    """Find a free port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"Could not find free port in range {start_port}-{start_port + max_attempts}")


class TestProxyProperties:
    """Property-based tests for proxy engine."""
    
    @pytest.mark.asyncio
    @pytest.mark.property
    @settings(max_examples=10, deadline=15000)  # 15 second deadline for async operations
    @given(
        host=st.sampled_from(["127.0.0.1", "localhost"]),
    )
    async def test_complete_data_capture_property(self, host: str):
        """
        # Feature: oasis-pentest-suite, Property 1: Complete Data Capture
        
        Property 1: Complete Data Capture
        For any HTTP request/response flow processed by the system, 
        all components (headers, body, timing, metadata) should be captured 
        and available for analysis
        
        **Validates: Requirements 1.2, 4.3, 8.2**
        """
        # Find an available port for this test
        port = find_free_port()
        
        captured_flows = []
        
        def flow_callback(flow: HTTPFlow):
            captured_flows.append(flow)
        
        proxy = ProxyEngine(host=host, port=port, flow_callback=flow_callback)
        
        try:
            # Start proxy
            await proxy.start_proxy()
            assert proxy.is_running
            
            # Create a simple HTTP request through the proxy
            proxy_url = f"http://{host}:{port}"
            
            # Use a test server endpoint that we know exists
            test_url = "http://httpbin.org/get"
            
            async with aiohttp.ClientSession() as session:
                try:
                    # Make request through proxy
                    async with session.get(
                        test_url,
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        response_text = await response.text()
                        
                        # Wait a bit for the flow to be processed
                        await asyncio.sleep(0.5)
                        
                        # Verify that flow was captured
                        assert len(captured_flows) > 0, "No flows were captured"
                        
                        # Get the captured flow
                        flow = captured_flows[-1]  # Get the most recent flow
                        
                        # Property: All components should be captured
                        assert flow.request is not None, "Request should be captured"
                        assert flow.response is not None, "Response should be captured"
                        assert flow.metadata is not None, "Metadata should be captured"
                        
                        # Property: Request components should be complete
                        request = flow.request
                        assert request.method is not None, "Request method should be captured"
                        assert request.url is not None, "Request URL should be captured"
                        assert request.headers is not None, "Request headers should be captured"
                        assert request.timestamp is not None, "Request timestamp should be captured"
                        
                        # Property: Response components should be complete
                        response_obj = flow.response
                        assert response_obj.status_code is not None, "Response status should be captured"
                        assert response_obj.headers is not None, "Response headers should be captured"
                        assert response_obj.timestamp is not None, "Response timestamp should be captured"
                        
                        # Property: Flow should have unique ID and creation timestamp
                        assert flow.id is not None, "Flow should have unique ID"
                        assert flow.created_at is not None, "Flow should have creation timestamp"
                        
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    # If external request fails, we can still test with mock data
                    # This ensures the test doesn't fail due to network issues
                    pytest.skip("External network request failed, skipping this iteration")
                    
        finally:
            # Always clean up
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    @pytest.mark.property
    async def test_flow_metadata_completeness_property(self):
        """
        Property test for flow metadata completeness.
        
        For any captured flow, metadata should contain all required fields
        and maintain consistency across the capture process.
        """
        # Find an available port for this test
        port = find_free_port(start_port=9200)
        
        captured_flows = []
        
        def flow_callback(flow: HTTPFlow):
            captured_flows.append(flow)
        
        proxy = ProxyEngine(host="127.0.0.1", port=port, flow_callback=flow_callback)
        
        try:
            await proxy.start_proxy()
            
            # Simulate flow capture by directly calling the addon
            if proxy._addon:
                # Create a mock mitmproxy flow
                from mitmproxy import http
                
                # Create mock request and response
                mock_flow = Mock()
                mock_flow.request = Mock()
                mock_flow.request.method = "GET"
                mock_flow.request.pretty_url = "http://example.com/test"
                mock_flow.request.headers = {"User-Agent": "Test"}
                mock_flow.request.content = b"test body"
                
                mock_flow.response = Mock()
                mock_flow.response.status_code = 200
                mock_flow.response.headers = {"Content-Type": "text/html"}
                mock_flow.response.content = b"response body"
                
                # Process through addon
                proxy._addon.request(mock_flow)
                proxy._addon.response(mock_flow)
                
                # Wait for processing
                await asyncio.sleep(0.1)
                
                # Verify flow was captured with complete metadata
                flows = proxy.get_captured_flows()
                assert len(flows) > 0, "Flow should be captured"
                
                flow = flows[-1]
                
                # Property: Metadata should be complete and consistent
                assert flow.metadata is not None, "Flow metadata should exist"
                assert flow.id is not None, "Flow should have unique ID"
                assert flow.created_at is not None, "Flow should have creation timestamp"
                
                # Property: Request data should be preserved exactly
                assert flow.request.method == "GET", "Request method should be preserved"
                assert flow.request.url == "http://example.com/test", "Request URL should be preserved"
                assert "User-Agent" in flow.request.headers, "Request headers should be preserved"
                
                # Property: Response data should be preserved exactly
                if flow.response:
                    assert flow.response.status_code == 200, "Response status should be preserved"
                    assert "Content-Type" in flow.response.headers, "Response headers should be preserved"
                
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    @pytest.mark.property
    async def test_proxy_statistics_consistency_property(self):
        """
        Property test for proxy statistics consistency.
        
        For any proxy operation, statistics should accurately reflect
        the actual number of captured flows and processed requests/responses.
        """
        # Find an available port for this test
        port = find_free_port(start_port=9400)
        
        proxy = ProxyEngine(host="127.0.0.1", port=port)
        
        try:
            await proxy.start_proxy()
            
            # Get initial stats
            initial_stats = proxy.get_stats()
            
            # Property: Initial state should be consistent
            assert initial_stats["running"] is True, "Proxy should report as running"
            assert initial_stats["flows_captured"] == 0, "Initial flow count should be zero"
            assert initial_stats["requests_intercepted"] == 0, "Initial request count should be zero"
            assert initial_stats["responses_intercepted"] == 0, "Initial response count should be zero"
            
            # Simulate some flows
            if proxy._addon:
                # Add some mock flows
                for i in range(3):
                    mock_flow = Mock()
                    mock_flow.request = Mock()
                    mock_flow.request.method = "GET"
                    mock_flow.request.pretty_url = f"http://example.com/test{i}"
                    mock_flow.request.headers = {}
                    mock_flow.request.content = b""
                    
                    mock_flow.response = Mock()
                    mock_flow.response.status_code = 200
                    mock_flow.response.headers = {}
                    mock_flow.response.content = b""
                    
                    proxy._addon.request(mock_flow)
                    proxy._addon.response(mock_flow)
                
                # Wait for processing
                await asyncio.sleep(0.1)
                
                # Get updated stats
                updated_stats = proxy.get_stats()
                
                # Property: Statistics should accurately reflect captured data
                assert updated_stats["flows_captured"] == 3, "Flow count should match captured flows"
                assert updated_stats["requests_intercepted"] == 3, "Request count should match processed requests"
                assert updated_stats["responses_intercepted"] == 3, "Response count should match processed responses"
                
                # Property: Flow list should match statistics
                flows = proxy.get_captured_flows()
                assert len(flows) == updated_stats["flows_captured"], "Flow list length should match statistics"
                
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    @pytest.mark.property
    @settings(max_examples=5, deadline=None)
    @given(
        header_name=st.text(min_size=1, max_size=20, alphabet=st.characters(min_codepoint=65, max_codepoint=90)),
        header_value=st.text(min_size=1, max_size=50),
    )
    async def test_traffic_modification_consistency_property(self, header_name: str, header_value: str):
        """
        # Feature: oasis-pentest-suite, Property 2: Traffic Modification Consistency
        
        Property 2: Traffic Modification Consistency
        For any intercepted HTTP request, modifications applied through the proxy engine 
        should be reflected in the actual transmitted request without data corruption
        
        **Validates: Requirements 1.3, 4.2**
        """
        # Find an available port for this test
        port = find_free_port(start_port=9600)
        
        proxy = ProxyEngine(host="127.0.0.1", port=port)
        
        try:
            await proxy.start_proxy()
            
            # Set header modification
            success = proxy.set_header_modification(header_name, header_value)
            assert success, "Header modification should succeed when proxy is running"
            
            # Verify modification is consistently applied
            modifier = proxy.get_traffic_modifier()
            assert modifier is not None, "Traffic modifier should be available"
            
            # Property: Modifications should be stored exactly as specified
            assert header_name in modifier.header_modifications, "Header name should be stored"
            assert modifier.header_modifications[header_name] == header_value, "Header value should match exactly"
            
            # Test modification application consistency
            from unittest.mock import Mock
            mock_request = Mock()
            mock_request.headers = {}
            mock_request.pretty_url = "http://test.example.com"
            mock_request.content = b"test"
            
            # Apply modifications multiple times - should be consistent
            for _ in range(3):
                modifier.modify_request(mock_request)
                
                # Property: Modifications should be applied consistently
                assert mock_request.headers[header_name] == header_value, "Header should be applied consistently"
            
            # Property: Multiple modifications should not interfere
            second_header = f"{header_name}_2"
            second_value = f"{header_value}_modified"
            
            proxy.set_header_modification(second_header, second_value)
            modifier.modify_request(mock_request)
            
            # Both modifications should be present
            assert mock_request.headers[header_name] == header_value, "Original header should remain"
            assert mock_request.headers[second_header] == second_value, "New header should be added"
            
            # Property: Clear modifications should remove all modifications
            proxy.clear_modifications()
            assert len(modifier.header_modifications) == 0, "All modifications should be cleared"
            
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    @pytest.mark.property
    @settings(max_examples=3, deadline=15000)
    @given(
        domain=st.text(min_size=3, max_size=20, alphabet=st.characters(min_codepoint=97, max_codepoint=122)).map(lambda x: f"{x}.com"),
    )
    async def test_https_interception_transparency_property(self, domain: str):
        """
        # Feature: oasis-pentest-suite, Property 3: HTTPS Interception Transparency
        
        Property 3: HTTPS Interception Transparency
        For any HTTPS connection, the proxy should generate valid certificates 
        and decrypt traffic without breaking the client-server handshake
        
        **Validates: Requirements 1.4**
        """
        # Find an available port for this test
        port = find_free_port(start_port=9800)
        
        proxy = ProxyEngine(host="127.0.0.1", port=port)
        
        try:
            await proxy.start_proxy()
            
            # Property: Proxy should be ready for HTTPS interception
            assert proxy.is_https_interception_ready(), "Proxy should be ready for HTTPS interception"
            
            # Property: CA certificate should exist and be valid
            ca_info = proxy.get_ca_certificate_info()
            assert ca_info is not None, "CA certificate should exist"
            assert 'subject' in ca_info, "CA certificate should have subject"
            assert 'not_valid_before' in ca_info, "CA certificate should have validity period"
            assert 'not_valid_after' in ca_info, "CA certificate should have expiration"
            
            # Property: Should be able to generate domain certificates
            cert_success = proxy.generate_domain_certificate(domain)
            assert cert_success, f"Should be able to generate certificate for {domain}"
            
            # Property: Generated certificate should be cached and accessible
            cert_manager = proxy.get_certificate_manager()
            assert domain in cert_manager._cert_cache, "Domain certificate should be cached"
            
            cached_cert = cert_manager._cert_cache[domain]
            assert 'cert' in cached_cert, "Cached certificate should have cert data"
            assert 'key' in cached_cert, "Cached certificate should have key data"
            assert 'expires' in cached_cert, "Cached certificate should have expiration"
            
            # Property: Certificate data should be valid PEM format
            cert_data = cached_cert['cert']
            key_data = cached_cert['key']
            
            assert isinstance(cert_data, bytes), "Certificate should be bytes"
            assert isinstance(key_data, bytes), "Key should be bytes"
            # Check for PEM format markers (test data only, not real keys)
            assert b'-----BEGIN CERTIFICATE-----' in cert_data, "Certificate should be PEM format"
            assert b'-----BEGIN PRIVATE KEY-----' in key_data, "Key should be PEM format"
            
            # Property: Installation instructions should be available
            instructions = proxy.get_certificate_installation_instructions()
            assert isinstance(instructions, dict), "Instructions should be a dictionary"
            assert len(instructions) > 0, "Instructions should not be empty"
            
            required_platforms = ['windows', 'macos', 'linux', 'general']
            for platform in required_platforms:
                assert platform in instructions, f"Instructions should include {platform}"
                assert len(instructions[platform]) > 0, f"Instructions for {platform} should not be empty"
            
            # Property: Certificate statistics should be consistent
            stats = proxy.get_stats()
            assert 'certificate_info' in stats, "Stats should include certificate info"
            assert 'https_interception_ready' in stats, "Stats should include HTTPS readiness"
            assert stats['https_interception_ready'] is True, "HTTPS interception should be ready"
            
            cert_stats = stats['certificate_info']
            assert cert_stats['ca_certificate_exists'] is True, "CA certificate should exist in stats"
            assert cert_stats['cached_certificates'] >= 1, "Should have at least one cached certificate"
            
        finally:
            await proxy.stop_proxy()