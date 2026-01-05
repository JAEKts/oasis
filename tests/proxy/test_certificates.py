"""
Tests for OASIS Certificate Management
"""

import pytest
import tempfile
from pathlib import Path

from src.oasis.proxy.certificates import CertificateManager
from src.oasis.proxy.engine import ProxyEngine


class TestCertificateManager:
    """Test cases for certificate management functionality."""
    
    def test_certificate_manager_initialization(self):
        """Test certificate manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            assert manager.cert_dir == cert_dir
            assert manager.ca_cert_path == cert_dir / "mitmproxy-ca-cert.pem"
            assert manager.ca_key_path == cert_dir / "mitmproxy-ca.pem"
    
    def test_ca_certificate_generation(self):
        """Test CA certificate generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            # Initially no certificates
            assert not manager.ca_cert_path.exists()
            assert not manager.ca_key_path.exists()
            
            # Generate CA certificate
            success = manager.ensure_ca_certificate()
            assert success
            
            # Certificates should now exist
            assert manager.ca_cert_path.exists()
            assert manager.ca_key_path.exists()
            
            # Should not regenerate if already exists
            success = manager.ensure_ca_certificate()
            assert success
    
    def test_ca_certificate_info(self):
        """Test CA certificate information retrieval."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            # No info when certificate doesn't exist
            info = manager.get_ca_certificate_info()
            assert info is None
            
            # Generate certificate
            manager.ensure_ca_certificate()
            
            # Should have info now
            info = manager.get_ca_certificate_info()
            assert info is not None
            assert 'subject' in info
            assert 'issuer' in info
            assert 'serial_number' in info
            assert 'not_valid_before' in info
            assert 'not_valid_after' in info
            assert 'fingerprint' in info
            assert 'path' in info
    
    def test_domain_certificate_generation(self):
        """Test domain-specific certificate generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            # Generate CA first
            manager.ensure_ca_certificate()
            
            # Generate domain certificate
            domain = "example.com"
            cert_data = manager.generate_domain_certificate(domain)
            
            assert cert_data is not None
            assert 'cert' in cert_data
            assert 'key' in cert_data
            assert isinstance(cert_data['cert'], bytes)
            assert isinstance(cert_data['key'], bytes)
            
            # Should be cached
            assert domain in manager._cert_cache
    
    def test_certificate_caching(self):
        """Test certificate caching functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            # Generate CA first
            manager.ensure_ca_certificate()
            
            domain = "test.example.com"
            
            # Generate certificate twice
            cert_data1 = manager.generate_domain_certificate(domain)
            cert_data2 = manager.generate_domain_certificate(domain)
            
            # Should be the same (cached)
            assert cert_data1 == cert_data2
            assert len(manager._cert_cache) == 1
    
    def test_installation_instructions(self):
        """Test installation instructions generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            instructions = manager.get_installation_instructions()
            
            assert isinstance(instructions, dict)
            assert 'windows' in instructions
            assert 'macos' in instructions
            assert 'linux' in instructions
            assert 'general' in instructions
            
            # Should contain the certificate path
            cert_path = str(manager.ca_cert_path)
            assert cert_path in instructions['windows']
            assert cert_path in instructions['macos']
            assert cert_path in instructions['linux']
            assert cert_path in instructions['general']
    
    def test_certificate_stats(self):
        """Test certificate statistics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            manager = CertificateManager(cert_dir=cert_dir)
            
            # Stats without CA certificate
            stats = manager.get_certificate_stats()
            assert stats['ca_certificate_exists'] is False
            assert stats['ca_certificate_info'] is None
            assert stats['cached_certificates'] == 0
            
            # Generate CA certificate
            manager.ensure_ca_certificate()
            
            # Stats with CA certificate
            stats = manager.get_certificate_stats()
            assert stats['ca_certificate_exists'] is True
            assert stats['ca_certificate_info'] is not None
            assert stats['cached_certificates'] == 0
            
            # Generate domain certificate
            manager.generate_domain_certificate("test.com")
            
            # Stats with cached certificate
            stats = manager.get_certificate_stats()
            assert stats['cached_certificates'] == 1


class TestProxyEngineWithCertificates:
    """Test proxy engine certificate integration."""
    
    @pytest.mark.asyncio
    async def test_proxy_certificate_integration(self):
        """Test proxy engine certificate management integration."""
        proxy = ProxyEngine(host="127.0.0.1", port=8300)
        
        # Should have certificate manager
        cert_manager = proxy.get_certificate_manager()
        assert cert_manager is not None
        
        # Should be ready for HTTPS interception
        assert proxy.is_https_interception_ready()
        
        # Should have CA certificate info
        ca_info = proxy.get_ca_certificate_info()
        assert ca_info is not None
        
        # Should have installation instructions
        instructions = proxy.get_certificate_installation_instructions()
        assert isinstance(instructions, dict)
        assert len(instructions) > 0
    
    @pytest.mark.asyncio
    async def test_proxy_stats_include_certificates(self):
        """Test that proxy stats include certificate information."""
        proxy = ProxyEngine(host="127.0.0.1", port=8301)
        
        stats = proxy.get_stats()
        
        assert 'https_interception_ready' in stats
        assert 'certificate_info' in stats
        assert stats['https_interception_ready'] is True
        
        cert_info = stats['certificate_info']
        assert 'ca_certificate_exists' in cert_info
        assert cert_info['ca_certificate_exists'] is True
    
    @pytest.mark.asyncio
    async def test_domain_certificate_generation(self):
        """Test domain certificate generation through proxy engine."""
        proxy = ProxyEngine(host="127.0.0.1", port=8302)
        
        # Generate certificate for domain
        success = proxy.generate_domain_certificate("api.example.com")
        assert success
        
        # Should be cached in certificate manager
        cert_manager = proxy.get_certificate_manager()
        assert "api.example.com" in cert_manager._cert_cache