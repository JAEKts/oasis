"""
Tests for OASIS Traffic Modification
"""

import pytest
import asyncio
from unittest.mock import Mock

from src.oasis.proxy.engine import ProxyEngine
from src.oasis.proxy.addon import TrafficModifier


class TestTrafficModification:
    """Test cases for traffic modification functionality."""
    
    @pytest.mark.asyncio
    async def test_header_modification(self):
        """Test header modification functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8200)
        
        await proxy.start_proxy()
        
        try:
            # Set header modification
            success = proxy.set_header_modification("X-Custom-Header", "test-value")
            assert success, "Header modification should succeed when proxy is running"
            
            # Verify modification is set
            modifier = proxy.get_traffic_modifier()
            assert modifier is not None
            assert "X-Custom-Header" in modifier.header_modifications
            assert modifier.header_modifications["X-Custom-Header"] == "test-value"
            
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_parameter_modification(self):
        """Test parameter modification functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8201)
        
        await proxy.start_proxy()
        
        try:
            # Set parameter modification
            success = proxy.set_parameter_modification("test_param", "modified_value")
            assert success, "Parameter modification should succeed when proxy is running"
            
            # Verify modification is set
            modifier = proxy.get_traffic_modifier()
            assert modifier is not None
            assert "test_param" in modifier.parameter_modifications
            assert modifier.parameter_modifications["test_param"] == "modified_value"
            
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_body_modification(self):
        """Test body modification functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8202)
        
        await proxy.start_proxy()
        
        try:
            # Set body modification
            test_body = b"modified body content"
            success = proxy.set_body_modification("example.com", test_body)
            assert success, "Body modification should succeed when proxy is running"
            
            # Verify modification is set
            modifier = proxy.get_traffic_modifier()
            assert modifier is not None
            assert "example.com" in modifier.body_modifications
            assert modifier.body_modifications["example.com"] == test_body
            
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_custom_request_modifier(self):
        """Test custom request modifier functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8203)
        
        await proxy.start_proxy()
        
        try:
            # Create custom modifier function
            def custom_modifier(request):
                request.headers["X-Modified"] = "true"
            
            # Add custom modifier
            success = proxy.add_request_modifier(custom_modifier)
            assert success, "Custom modifier should be added when proxy is running"
            
            # Verify modifier is added
            modifier = proxy.get_traffic_modifier()
            assert modifier is not None
            assert len(modifier.request_modifiers) == 1
            
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_clear_modifications(self):
        """Test clearing all modifications."""
        proxy = ProxyEngine(host="127.0.0.1", port=8204)
        
        await proxy.start_proxy()
        
        try:
            # Set various modifications
            proxy.set_header_modification("X-Test", "value")
            proxy.set_parameter_modification("param", "value")
            proxy.set_body_modification("test.com", b"body")
            
            # Verify modifications are set
            modifier = proxy.get_traffic_modifier()
            assert len(modifier.header_modifications) > 0
            assert len(modifier.parameter_modifications) > 0
            assert len(modifier.body_modifications) > 0
            
            # Clear modifications
            success = proxy.clear_modifications()
            assert success, "Clear modifications should succeed when proxy is running"
            
            # Verify modifications are cleared
            assert len(modifier.header_modifications) == 0
            assert len(modifier.parameter_modifications) == 0
            assert len(modifier.body_modifications) == 0
            
        finally:
            await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_modification_when_proxy_not_running(self):
        """Test that modifications fail when proxy is not running."""
        proxy = ProxyEngine(host="127.0.0.1", port=8205)
        
        # Try to set modifications when proxy is not running
        assert not proxy.set_header_modification("X-Test", "value")
        assert not proxy.set_parameter_modification("param", "value")
        assert not proxy.set_body_modification("test.com", b"body")
        assert not proxy.clear_modifications()
        
        # Modifier should be None when proxy is not running
        assert proxy.get_traffic_modifier() is None
    
    def test_traffic_modifier_direct(self):
        """Test TrafficModifier class directly."""
        modifier = TrafficModifier()
        
        # Test header modification
        modifier.set_header_modification("X-Test", "value")
        assert modifier.header_modifications["X-Test"] == "value"
        
        # Test parameter modification
        modifier.set_parameter_modification("param", "value")
        assert modifier.parameter_modifications["param"] == "value"
        
        # Test body modification
        modifier.set_body_modification("test.com", b"body")
        assert modifier.body_modifications["test.com"] == b"body"
        
        # Test custom modifiers
        def test_modifier(request):
            pass
        
        modifier.add_request_modifier(test_modifier)
        assert len(modifier.request_modifiers) == 1
        
        # Test clear
        modifier.clear_modifications()
        assert len(modifier.header_modifications) == 0
        assert len(modifier.parameter_modifications) == 0
        assert len(modifier.body_modifications) == 0
        assert len(modifier.request_modifiers) == 0
    
    def test_request_modification_application(self):
        """Test that request modifications are applied correctly."""
        modifier = TrafficModifier()
        
        # Create mock request
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.pretty_url = "http://example.com/test"
        mock_request.content = b"original body"
        
        # Set modifications
        modifier.set_header_modification("X-Custom", "test-value")
        modifier.set_body_modification("example.com", b"modified body")
        
        # Apply modifications
        modifier.modify_request(mock_request)
        
        # Verify modifications were applied
        assert mock_request.headers["X-Custom"] == "test-value"
        assert mock_request.content == b"modified body"
        assert mock_request.headers["Content-Length"] == str(len(b"modified body"))