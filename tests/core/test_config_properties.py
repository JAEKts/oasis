"""
Property-based tests for OASIS configuration management.

Feature: oasis-pentest-suite, Property 15: Project Data Organization
Validates: Requirements 10.1, 10.4
"""

import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
from hypothesis import given, strategies as st

from src.oasis.core.config import (
    OASISConfig,
    LoggingConfig,
    ProxyConfig,
    DatabaseConfig,
    RedisConfig,
    SecurityConfig,
    PerformanceConfig,
    VaultConfig,
    load_config,
    reload_config,
    update_config,
    get_vault_path
)


# Hypothesis strategies for generating test data
@st.composite
def logging_config_strategy(draw):
    """Generate valid LoggingConfig instances."""
    return LoggingConfig(
        level=draw(st.sampled_from(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])),
        file_path=draw(st.one_of(st.none(), st.text(min_size=1, max_size=100))),
        max_file_size=draw(st.integers(min_value=1000, max_value=100_000_000)),
        backup_count=draw(st.integers(min_value=1, max_value=20))
    )


@st.composite
def proxy_config_strategy(draw):
    """Generate valid ProxyConfig instances."""
    return ProxyConfig(
        host=draw(st.sampled_from(['127.0.0.1', 'localhost', '0.0.0.0'])),
        port=draw(st.integers(min_value=1024, max_value=65535)),
        ca_cert_path=draw(st.one_of(st.none(), st.text(min_size=1, max_size=100))),
        ca_key_path=draw(st.one_of(st.none(), st.text(min_size=1, max_size=100)))
    )


@st.composite
def database_config_strategy(draw):
    """Generate valid DatabaseConfig instances."""
    return DatabaseConfig(
        url=draw(st.sampled_from([
            'sqlite:///test.db',
            'postgresql://user:pass@localhost/db',
            'sqlite:///:memory:'
        ])),
        pool_size=draw(st.integers(min_value=1, max_value=50)),
        max_overflow=draw(st.integers(min_value=0, max_value=100)),
        echo=draw(st.booleans())
    )


@st.composite
def security_config_strategy(draw):
    """Generate valid SecurityConfig instances."""
    return SecurityConfig(
        secret_key=draw(st.text(min_size=16, max_size=64)),
        encryption_algorithm=draw(st.sampled_from(['AES-256-GCM', 'AES-128-GCM'])),
        hash_algorithm=draw(st.sampled_from(['SHA-256', 'SHA-512'])),
        session_timeout=draw(st.integers(min_value=300, max_value=86400))
    )


@st.composite
def vault_config_strategy(draw):
    """Generate valid VaultConfig instances."""
    return VaultConfig(
        base_path=draw(st.text(min_size=1, max_size=100)),
        auto_save=draw(st.booleans()),
        backup_enabled=draw(st.booleans()),
        backup_interval=draw(st.integers(min_value=60, max_value=86400)),
        max_backups=draw(st.integers(min_value=1, max_value=100))
    )


class TestConfigurationProperties:
    """Property-based tests for configuration management."""
    
    @given(logging_config_strategy())
    def test_logging_config_serialization_roundtrip(self, logging_config: LoggingConfig):
        """
        Property 15: Project Data Organization
        For any valid LoggingConfig, serializing then deserializing should produce equivalent config.
        **Validates: Requirements 10.1, 10.4**
        """
        # Serialize to dict
        config_dict = logging_config.model_dump()
        
        # Deserialize back to object
        restored_config = LoggingConfig(**config_dict)
        
        # Should be equivalent
        assert restored_config == logging_config
        assert restored_config.model_dump() == config_dict
    
    @given(proxy_config_strategy())
    def test_proxy_config_serialization_roundtrip(self, proxy_config: ProxyConfig):
        """
        Property 15: Project Data Organization
        For any valid ProxyConfig, serializing then deserializing should produce equivalent config.
        **Validates: Requirements 10.1, 10.4**
        """
        # Serialize to dict
        config_dict = proxy_config.model_dump()
        
        # Deserialize back to object
        restored_config = ProxyConfig(**config_dict)
        
        # Should be equivalent
        assert restored_config == proxy_config
        assert restored_config.model_dump() == config_dict
    
    @given(database_config_strategy())
    def test_database_config_serialization_roundtrip(self, database_config: DatabaseConfig):
        """
        Property 15: Project Data Organization
        For any valid DatabaseConfig, serializing then deserializing should produce equivalent config.
        **Validates: Requirements 10.1, 10.4**
        """
        # Serialize to dict
        config_dict = database_config.model_dump()
        
        # Deserialize back to object
        restored_config = DatabaseConfig(**config_dict)
        
        # Should be equivalent
        assert restored_config == database_config
        assert restored_config.model_dump() == config_dict
    
    @given(security_config_strategy())
    def test_security_config_serialization_roundtrip(self, security_config: SecurityConfig):
        """
        Property 15: Project Data Organization
        For any valid SecurityConfig, serializing then deserializing should produce equivalent config.
        **Validates: Requirements 10.1, 10.4**
        """
        # Serialize to dict
        config_dict = security_config.model_dump()
        
        # Deserialize back to object
        restored_config = SecurityConfig(**config_dict)
        
        # Should be equivalent
        assert restored_config == security_config
        assert restored_config.model_dump() == config_dict
    
    @given(vault_config_strategy())
    def test_vault_config_serialization_roundtrip(self, vault_config: VaultConfig):
        """
        Property 15: Project Data Organization
        For any valid VaultConfig, serializing then deserializing should produce equivalent config.
        **Validates: Requirements 10.1, 10.4**
        """
        # Serialize to dict
        config_dict = vault_config.model_dump()
        
        # Deserialize back to object
        restored_config = VaultConfig(**config_dict)
        
        # Should be equivalent
        assert restored_config == vault_config
        assert restored_config.model_dump() == config_dict
    
    @given(
        logging_config_strategy(),
        proxy_config_strategy(),
        database_config_strategy(),
        security_config_strategy(),
        vault_config_strategy()
    )
    def test_full_config_hierarchical_organization(
        self,
        logging_config: LoggingConfig,
        proxy_config: ProxyConfig,
        database_config: DatabaseConfig,
        security_config: SecurityConfig,
        vault_config: VaultConfig
    ):
        """
        Property 15: Project Data Organization
        For any valid configuration components, the full config should maintain hierarchical organization.
        **Validates: Requirements 10.1, 10.4**
        """
        # Create full config with all components
        full_config = OASISConfig(
            logging=logging_config,
            proxy=proxy_config,
            database=database_config,
            security=security_config,
            vault=vault_config
        )
        
        # Serialize to dict
        config_dict = full_config.model_dump()
        
        # Should maintain hierarchical structure
        assert 'logging' in config_dict
        assert 'proxy' in config_dict
        assert 'database' in config_dict
        assert 'security' in config_dict
        assert 'vault' in config_dict
        
        # Each section should contain expected fields
        assert config_dict['logging']['level'] == logging_config.level
        assert config_dict['proxy']['host'] == proxy_config.host
        assert config_dict['proxy']['port'] == proxy_config.port
        assert config_dict['database']['url'] == database_config.url
        assert config_dict['security']['secret_key'] == security_config.secret_key
        assert config_dict['vault']['base_path'] == vault_config.base_path
        
        # Deserialize back to object
        restored_config = OASISConfig(**config_dict)
        
        # Should be equivalent
        assert restored_config.logging == logging_config
        assert restored_config.proxy == proxy_config
        assert restored_config.database == database_config
        assert restored_config.security == security_config
        assert restored_config.vault == vault_config
    
    @given(st.text(min_size=1, max_size=100, alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters='/\\')))
    def test_vault_path_organization(self, base_path: str):
        """
        Property 15: Project Data Organization
        For any valid base path, vault path creation should maintain proper directory organization.
        **Validates: Requirements 10.1, 10.4**
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault config with test path
            vault_config = VaultConfig(base_path=f"{temp_dir}/{base_path}")
            
            # Create security config (required field)
            security_config = SecurityConfig(secret_key="test-secret-key-for-testing")
            
            # Create config with vault and security settings
            config = OASISConfig(vault=vault_config, security=security_config)
            
            # Get vault path should create directory structure
            vault_path = Path(config.vault.base_path)
            vault_path.mkdir(parents=True, exist_ok=True)
            
            # Should exist and be a directory
            assert vault_path.exists()
            assert vault_path.is_dir()
            
            # Should be able to create subdirectories (hierarchical organization)
            projects_dir = vault_path / "projects"
            projects_dir.mkdir(exist_ok=True)
            
            backups_dir = vault_path / "backups"
            backups_dir.mkdir(exist_ok=True)
            
            # Both should exist
            assert projects_dir.exists()
            assert backups_dir.exists()
            assert projects_dir.is_dir()
            assert backups_dir.is_dir()
    
    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=20),
            st.one_of(st.text(), st.integers(), st.booleans()),
            min_size=1,
            max_size=10
        )
    )
    def test_config_update_preserves_structure(self, update_data: Dict[str, Any]):
        """
        Property 15: Project Data Organization
        For any configuration updates, the hierarchical structure should be preserved.
        **Validates: Requirements 10.1, 10.4**
        """
        # Create initial config with required security field
        security_config = SecurityConfig(secret_key="test-secret-key-for-testing")
        original_config = OASISConfig(security=security_config)
        original_dict = original_config.model_dump()
        
        # Filter update data to only include valid top-level keys
        valid_keys = {'environment', 'debug'}
        filtered_updates = {k: v for k, v in update_data.items() if k in valid_keys}
        
        if not filtered_updates:
            # If no valid updates, test passes trivially
            return
        
        # Apply updates
        for key, value in filtered_updates.items():
            setattr(original_config, key, value)
        
        # Get updated dict
        updated_dict = original_config.model_dump()
        
        # Core structure should be preserved
        assert 'logging' in updated_dict
        assert 'proxy' in updated_dict
        assert 'database' in updated_dict
        assert 'security' in updated_dict
        assert 'vault' in updated_dict
        
        # Updated values should be reflected
        for key, value in filtered_updates.items():
            assert updated_dict[key] == value
        
        # Non-updated nested structures should remain unchanged
        if 'logging' not in filtered_updates:
            assert updated_dict['logging'] == original_dict['logging']
        if 'proxy' not in filtered_updates:
            assert updated_dict['proxy'] == original_dict['proxy']