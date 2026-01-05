"""
Tests for OASIS Proxy Engine
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import Mock

from src.oasis.proxy.engine import ProxyEngine
from src.oasis.core.exceptions import ProxyError
from src.oasis.core.models import HTTPFlow


class TestProxyEngine:
    """Test cases for ProxyEngine class."""
    
    @pytest.mark.asyncio
    async def test_proxy_initialization(self):
        """Test proxy engine initialization."""
        proxy = ProxyEngine(host="127.0.0.1", port=8081)
        
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 8081
        assert not proxy.is_running
        assert proxy.listen_address == "127.0.0.1:8081"
    
    @pytest.mark.asyncio
    async def test_proxy_start_stop(self):
        """Test basic proxy start and stop functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8082)
        
        # Test start
        await proxy.start_proxy()
        assert proxy.is_running
        
        # Test stop
        await proxy.stop_proxy()
        assert not proxy.is_running
    
    @pytest.mark.asyncio
    async def test_proxy_double_start_error(self):
        """Test that starting an already running proxy raises error."""
        proxy = ProxyEngine(host="127.0.0.1", port=8083)
        
        await proxy.start_proxy()
        
        with pytest.raises(ProxyError, match="already running"):
            await proxy.start_proxy()
        
        await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_proxy_stats(self):
        """Test proxy statistics functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8084)
        
        # Test stats when not running
        stats = proxy.get_stats()
        assert "running" in stats
        assert not stats["running"]
        
        # Test stats when running
        await proxy.start_proxy()
        stats = proxy.get_stats()
        assert stats["running"]
        assert stats["listen_address"] == "127.0.0.1:8084"
        
        await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_flow_callback(self):
        """Test flow callback functionality."""
        callback_mock = Mock()
        proxy = ProxyEngine(host="127.0.0.1", port=8085, flow_callback=callback_mock)
        
        await proxy.start_proxy()
        
        # The callback should be set up
        assert proxy._addon.flow_callback == callback_mock
        
        await proxy.stop_proxy()
    
    @pytest.mark.asyncio
    async def test_captured_flows(self):
        """Test flow capture functionality."""
        proxy = ProxyEngine(host="127.0.0.1", port=8086)
        
        await proxy.start_proxy()
        
        # Initially no flows
        flows = proxy.get_captured_flows()
        assert len(flows) == 0
        
        # Clear flows should work
        proxy.clear_flows()
        
        await proxy.stop_proxy()
    
    @pytest.mark.asyncio 
    async def test_invalid_port_error(self):
        """Test that invalid port raises appropriate error."""
        # Use a port that's likely to be in use or invalid
        proxy = ProxyEngine(host="127.0.0.1", port=80)  # Privileged port
        
        # The error should occur during start_proxy, not initialization
        with pytest.raises(ProxyError):
            await proxy.start_proxy()