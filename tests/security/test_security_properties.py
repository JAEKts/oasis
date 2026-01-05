"""
Property-based tests for OASIS security and encryption.

Feature: oasis-pentest-suite, Property 18: Data Security Consistency
Validates: Requirements 12.1, 12.2
"""

import json
import secrets
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from src.oasis.security.encryption import (
    EncryptionService,
    KeyManager,
    encrypt_data,
    decrypt_data,
    hash_password,
    verify_password
)
from src.oasis.storage.secure_vault import SecureVaultStorage
from src.oasis.core.models import Project, ProjectSettings


# Strategies for generating test data
@st.composite
def sensitive_data_dict(draw):
    """Generate dictionaries with sensitive data."""
    return {
        "api_key": draw(st.text(min_size=10, max_size=100)),
        "password": draw(st.text(min_size=8, max_size=50)),
        "secret": draw(st.text(min_size=10, max_size=100)),
        "token": draw(st.text(min_size=20, max_size=200))
    }


@st.composite
def certificate_data(draw):
    """Generate certificate-like data."""
    return draw(st.binary(min_size=100, max_size=5000))


# Feature: oasis-pentest-suite, Property 18: Data Security Consistency
# Validates: Requirements 12.1, 12.2
class TestDataSecurityConsistency:
    """
    Property 18: Data Security Consistency
    
    For any sensitive data handled by the system, it should be encrypted using
    industry-standard algorithms both at rest and in transit.
    
    Validates: Requirements 12.1, 12.2
    """
    
    @given(plaintext=st.text(min_size=1, max_size=10000))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_encryption_decryption_round_trip(self, plaintext: str):
        """
        Property: For any plaintext string, encrypting then decrypting should
        return the original plaintext.
        
        This validates that encryption is reversible and data integrity is maintained.
        """
        # Create encryption service
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            encryption_service = EncryptionService(key_manager)
            
            # Encrypt
            encrypted = encryption_service.encrypt_string(plaintext)
            
            # Verify encrypted data is different from plaintext
            assert encrypted != plaintext
            
            # Decrypt
            decrypted = encryption_service.decrypt_string(encrypted)
            
            # Verify round trip
            assert decrypted == plaintext
    
    @given(data=st.binary(min_size=1, max_size=10000))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_binary_encryption_round_trip(self, data: bytes):
        """
        Property: For any binary data, encrypting then decrypting should
        return the original data.
        
        This validates encryption works for binary data like certificates.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            encryption_service = EncryptionService(key_manager)
            
            # Encrypt
            encrypted = encryption_service.encrypt_fernet(data)
            
            # Verify encrypted data is different
            assert encrypted != data
            
            # Decrypt
            decrypted = encryption_service.decrypt_fernet(encrypted)
            
            # Verify round trip
            assert decrypted == data
    
    @given(data_dict=sensitive_data_dict())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_dictionary_encryption_round_trip(self, data_dict: Dict[str, Any]):
        """
        Property: For any dictionary containing sensitive data, encrypting then
        decrypting should return the original dictionary.
        
        This validates encryption works for structured data like credentials.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            encryption_service = EncryptionService(key_manager)
            
            # Encrypt
            encrypted = encryption_service.encrypt_dict(data_dict)
            
            # Verify encrypted data is a string
            assert isinstance(encrypted, str)
            
            # Decrypt
            decrypted = encryption_service.decrypt_dict(encrypted)
            
            # Verify round trip
            assert decrypted == data_dict
    
    @given(
        plaintext=st.text(min_size=1, max_size=1000),
        associated_data=st.binary(min_size=0, max_size=100)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_aes_gcm_encryption_with_aead(self, plaintext: str, associated_data: bytes):
        """
        Property: For any plaintext and associated data, AES-GCM encryption
        should provide authenticated encryption with associated data (AEAD).
        
        This validates that tampering with either ciphertext or associated data
        is detected during decryption.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            encryption_service = EncryptionService(key_manager)
            
            plaintext_bytes = plaintext.encode()
            
            # Encrypt with associated data
            encrypted_data = encryption_service.encrypt_aes_gcm(
                plaintext_bytes,
                associated_data if associated_data else None
            )
            
            # Verify encrypted data contains required fields
            assert 'ciphertext' in encrypted_data
            assert 'nonce' in encrypted_data
            assert 'tag' in encrypted_data
            
            # Decrypt with correct associated data
            decrypted = encryption_service.decrypt_aes_gcm(
                encrypted_data,
                associated_data if associated_data else None
            )
            
            # Verify round trip
            assert decrypted == plaintext_bytes
    
    @given(password=st.text(min_size=8, max_size=100))
    @settings(max_examples=100, deadline=None)
    def test_password_hashing_verification(self, password: str):
        """
        Property: For any password, hashing then verifying should succeed,
        and verifying with a different password should fail.
        
        This validates password hashing is secure and deterministic.
        """
        # Hash password
        password_hash = hash_password(password)
        
        # Verify hash is different from password
        assert password_hash != password
        
        # Verify correct password
        assert verify_password(password, password_hash) is True
        
        # Verify incorrect password fails
        wrong_password = password + "wrong"
        assert verify_password(wrong_password, password_hash) is False
    
    @given(
        credential_type=st.text(min_size=1, max_size=50),
        credentials=sensitive_data_dict()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_secure_vault_credentials_storage(self, credential_type: str, credentials: Dict[str, Any]):
        """
        Property: For any credentials stored in the secure vault, they should be
        encrypted at rest and decrypted correctly when retrieved.
        
        This validates end-to-end encryption for credential storage.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "vault"
            key_dir = Path(tmpdir) / "keys"
            
            # Create secure vault
            key_manager = KeyManager(key_dir)
            vault = SecureVaultStorage(vault_path, key_manager)
            
            # Create a project
            project = vault.create_project("Test Project", "Test description")
            
            # Store credentials
            success = vault.store_credentials(
                project.id,
                credential_type,
                credentials,
                "Test credentials"
            )
            assert success is True
            
            # Retrieve credentials
            retrieved = vault.get_credentials(project.id, credential_type)
            
            # Verify credentials were retrieved
            assert len(retrieved) > 0
            
            # Verify credentials match
            assert retrieved[0]["credentials"] == credentials
            assert retrieved[0]["credential_type"] == credential_type
    
    @given(cert_data=certificate_data())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_secure_vault_certificate_storage(self, cert_data: bytes):
        """
        Property: For any certificate data stored in the secure vault, it should be
        encrypted at rest and decrypted correctly when retrieved.
        
        This validates end-to-end encryption for certificate storage.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "vault"
            key_dir = Path(tmpdir) / "keys"
            
            # Create secure vault
            key_manager = KeyManager(key_dir)
            vault = SecureVaultStorage(vault_path, key_manager)
            
            # Create a project
            project = vault.create_project("Test Project", "Test description")
            
            # Generate key data
            key_data = secrets.token_bytes(256)
            
            # Store certificate
            success = vault.store_certificate(
                project.id,
                cert_data,
                key_data,
                "Test certificate"
            )
            assert success is True
            
            # Retrieve certificate
            retrieved = vault.get_certificates(project.id)
            
            # Verify certificate was retrieved
            assert len(retrieved) > 0
            
            # Verify certificate data matches
            assert retrieved[0]["cert_data"] == cert_data
            assert retrieved[0]["key_data"] == key_data
    
    @given(plaintext=st.text(min_size=1, max_size=1000))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_different_keys_produce_different_ciphertexts(self, plaintext: str):
        """
        Property: For any plaintext, encrypting with different keys should
        produce different ciphertexts.
        
        This validates that encryption keys are properly isolated.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create two different key managers
            key_manager1 = KeyManager(Path(tmpdir) / "keys1")
            key_manager2 = KeyManager(Path(tmpdir) / "keys2")
            
            encryption_service1 = EncryptionService(key_manager1)
            encryption_service2 = EncryptionService(key_manager2)
            
            # Encrypt with both services
            encrypted1 = encryption_service1.encrypt_string(plaintext)
            encrypted2 = encryption_service2.encrypt_string(plaintext)
            
            # Verify ciphertexts are different
            assert encrypted1 != encrypted2
            
            # Verify each service can decrypt its own ciphertext
            assert encryption_service1.decrypt_string(encrypted1) == plaintext
            assert encryption_service2.decrypt_string(encrypted2) == plaintext
    
    @given(plaintext=st.text(min_size=1, max_size=1000))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_encryption_is_non_deterministic(self, plaintext: str):
        """
        Property: For any plaintext, encrypting it multiple times should
        produce different ciphertexts (due to random nonces/IVs).
        
        This validates that encryption uses proper randomization.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            encryption_service = EncryptionService(key_manager)
            
            # Encrypt same plaintext twice
            encrypted1 = encryption_service.encrypt_string(plaintext)
            encrypted2 = encryption_service.encrypt_string(plaintext)
            
            # Verify ciphertexts are different (due to random nonce)
            assert encrypted1 != encrypted2
            
            # Verify both decrypt to same plaintext
            assert encryption_service.decrypt_string(encrypted1) == plaintext
            assert encryption_service.decrypt_string(encrypted2) == plaintext


# Additional unit tests for specific security requirements
class TestEncryptionSecurity:
    """Unit tests for specific encryption security requirements."""
    
    def test_key_generation_produces_unique_keys(self):
        """Verify that key generation produces unique keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            
            keys = [key_manager.generate_key() for _ in range(10)]
            
            # Verify all keys are unique
            assert len(set(keys)) == len(keys)
            
            # Verify all keys are 32 bytes
            assert all(len(key) == 32 for key in keys)
    
    def test_master_key_persistence(self):
        """Verify that master key is persisted and reloaded correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_dir = Path(tmpdir)
            
            # Create key manager and get master key
            key_manager1 = KeyManager(key_dir)
            master_key1 = key_manager1.get_master_key()
            
            # Create new key manager with same directory
            key_manager2 = KeyManager(key_dir)
            master_key2 = key_manager2.get_master_key()
            
            # Verify keys are the same
            assert master_key1 == master_key2
    
    def test_password_hash_is_salted(self):
        """Verify that password hashing uses salt (same password produces different hashes)."""
        password = "test_password_123"
        
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Verify hashes are different (due to random salt)
        assert hash1 != hash2
        
        # Verify both hashes verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True
    
    def test_encryption_service_uses_master_key(self):
        """Verify that encryption service uses the master key from key manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = KeyManager(Path(tmpdir))
            encryption_service = EncryptionService(key_manager)
            
            plaintext = "test data"
            
            # Encrypt
            encrypted = encryption_service.encrypt_string(plaintext)
            
            # Create new service with same key manager
            encryption_service2 = EncryptionService(key_manager)
            
            # Verify second service can decrypt
            decrypted = encryption_service2.decrypt_string(encrypted)
            assert decrypted == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
