"""
OASIS Encryption Service

Provides encryption at rest and in transit for sensitive data including credentials,
certificates, and test results.
"""

import base64
import hashlib
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import argon2

from ..core.config import get_config
from ..core.exceptions import SecurityError
from ..core.logging import get_logger

logger = get_logger(__name__)


class KeyManager:
    """
    Manages encryption keys with secure storage and rotation capabilities.

    Provides:
    - Secure key generation and storage
    - Key rotation with versioning
    - Key derivation from passwords
    - Master key management
    """

    def __init__(self, key_dir: Optional[Path] = None) -> None:
        """
        Initialize key manager.

        Args:
            key_dir: Directory for storing keys (uses config if None)
        """
        if key_dir:
            self.key_dir = key_dir
        else:
            try:
                config = get_config()
                self.key_dir = Path(config.vault.base_path) / ".keys"
            except Exception:
                self.key_dir = Path.home() / ".oasis" / ".keys"

        self.key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._master_key: Optional[bytes] = None
        self._key_version = 1

    def generate_key(self) -> bytes:
        """
        Generate a new encryption key.

        Returns:
            32-byte encryption key
        """
        return secrets.token_bytes(32)

    def derive_key_from_password(
        self, password: str, salt: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Derive an encryption key from a password using PBKDF2.

        Args:
            password: Password to derive key from
            salt: Salt for key derivation (generated if None)

        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )

        key = kdf.derive(password.encode())
        return key, salt

    def get_master_key(self) -> bytes:
        """
        Get or create the master encryption key.

        Returns:
            Master encryption key
        """
        if self._master_key:
            return self._master_key

        key_file = self.key_dir / f"master_key_v{self._key_version}.key"

        if key_file.exists():
            # Load existing key
            try:
                with open(key_file, "rb") as f:
                    self._master_key = f.read()
                logger.info(f"Loaded master key version {self._key_version}")
            except Exception as e:
                raise SecurityError(f"Failed to load master key: {e}")
        else:
            # Generate new key
            self._master_key = self.generate_key()
            try:
                with open(key_file, "wb") as f:
                    f.write(self._master_key)
                os.chmod(key_file, 0o600)
                logger.info(f"Generated new master key version {self._key_version}")
            except Exception as e:
                raise SecurityError(f"Failed to save master key: {e}")

        return self._master_key

    def rotate_master_key(self) -> bytes:
        """
        Rotate the master encryption key.

        Returns:
            New master encryption key
        """
        # Increment version
        self._key_version += 1

        # Generate new key
        new_key = self.generate_key()
        key_file = self.key_dir / f"master_key_v{self._key_version}.key"

        try:
            with open(key_file, "wb") as f:
                f.write(new_key)
            os.chmod(key_file, 0o600)

            self._master_key = new_key
            logger.info(f"Rotated master key to version {self._key_version}")
            return new_key

        except Exception as e:
            raise SecurityError(f"Failed to rotate master key: {e}")

    def get_key_version(self) -> int:
        """Get current key version."""
        return self._key_version


class EncryptionService:
    """
    Provides encryption and decryption services for sensitive data.

    Supports:
    - AES-256-GCM encryption for data at rest
    - Fernet encryption for simpler use cases
    - Authenticated encryption with associated data (AEAD)
    - Secure key management and rotation
    """

    def __init__(self, key_manager: Optional[KeyManager] = None) -> None:
        """
        Initialize encryption service.

        Args:
            key_manager: Key manager instance (creates new if None)
        """
        self.key_manager = key_manager or KeyManager()
        self._fernet: Optional[Fernet] = None

    def _get_fernet(self) -> Fernet:
        """Get or create Fernet instance."""
        if not self._fernet:
            master_key = self.key_manager.get_master_key()
            # Fernet requires base64-encoded 32-byte key
            fernet_key = base64.urlsafe_b64encode(master_key)
            self._fernet = Fernet(fernet_key)
        return self._fernet

    def encrypt_aes_gcm(
        self, plaintext: bytes, associated_data: Optional[bytes] = None
    ) -> Dict[str, bytes]:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional associated data for AEAD

        Returns:
            Dictionary containing ciphertext, nonce, and tag
        """
        try:
            # Generate random nonce
            nonce = secrets.token_bytes(12)

            # Get encryption key
            key = self.key_manager.get_master_key()

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # Add associated data if provided
            if associated_data:
                encryptor.authenticate_additional_data(associated_data)

            # Encrypt
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            return {
                "ciphertext": ciphertext,
                "nonce": nonce,
                "tag": encryptor.tag,
                "version": self.key_manager.get_key_version(),
            }

        except Exception as e:
            raise SecurityError(f"Encryption failed: {e}")

    def decrypt_aes_gcm(
        self, encrypted_data: Dict[str, bytes], associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            encrypted_data: Dictionary containing ciphertext, nonce, and tag
            associated_data: Optional associated data for AEAD

        Returns:
            Decrypted plaintext
        """
        try:
            # Get encryption key
            key = self.key_manager.get_master_key()

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(encrypted_data["nonce"], encrypted_data["tag"]),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()

            # Add associated data if provided
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)

            # Decrypt
            plaintext = (
                decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()
            )

            return plaintext

        except Exception as e:
            raise SecurityError(f"Decryption failed: {e}")

    def encrypt_fernet(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using Fernet (simpler, includes timestamp).

        Args:
            plaintext: Data to encrypt

        Returns:
            Encrypted data
        """
        try:
            fernet = self._get_fernet()
            return fernet.encrypt(plaintext)
        except Exception as e:
            raise SecurityError(f"Fernet encryption failed: {e}")

    def decrypt_fernet(self, ciphertext: bytes, ttl: Optional[int] = None) -> bytes:
        """
        Decrypt data using Fernet.

        Args:
            ciphertext: Encrypted data
            ttl: Time-to-live in seconds (None for no expiration)

        Returns:
            Decrypted plaintext
        """
        try:
            fernet = self._get_fernet()
            if ttl:
                return fernet.decrypt(ciphertext, ttl=ttl)
            return fernet.decrypt(ciphertext)
        except Exception as e:
            raise SecurityError(f"Fernet decryption failed: {e}")

    def encrypt_string(self, plaintext: str) -> str:
        """
        Encrypt a string and return base64-encoded result.

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        encrypted = self.encrypt_fernet(plaintext.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_string(self, ciphertext: str) -> str:
        """
        Decrypt a base64-encoded encrypted string.

        Args:
            ciphertext: Base64-encoded encrypted string

        Returns:
            Decrypted string
        """
        encrypted = base64.b64decode(ciphertext.encode())
        decrypted = self.decrypt_fernet(encrypted)
        return decrypted.decode()

    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """
        Encrypt a dictionary and return base64-encoded result.

        Args:
            data: Dictionary to encrypt

        Returns:
            Base64-encoded encrypted JSON
        """
        import json

        json_str = json.dumps(data)
        return self.encrypt_string(json_str)

    def decrypt_dict(self, ciphertext: str) -> Dict[str, Any]:
        """
        Decrypt a base64-encoded encrypted dictionary.

        Args:
            ciphertext: Base64-encoded encrypted JSON

        Returns:
            Decrypted dictionary
        """
        import json

        json_str = self.decrypt_string(ciphertext)
        return json.loads(json_str)


# Password hashing using Argon2
_password_hasher = argon2.PasswordHasher(
    time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16
)


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.

    Args:
        password: Password to hash

    Returns:
        Hashed password
    """
    try:
        return _password_hasher.hash(password)
    except Exception as e:
        raise SecurityError(f"Password hashing failed: {e}")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        password: Password to verify
        password_hash: Hashed password

    Returns:
        True if password matches, False otherwise
    """
    try:
        _password_hasher.verify(password_hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


# Convenience functions
def encrypt_data(
    data: Union[str, bytes, Dict[str, Any]], service: Optional[EncryptionService] = None
) -> str:
    """
    Encrypt data using the default encryption service.

    Args:
        data: Data to encrypt (string, bytes, or dict)
        service: Encryption service instance (creates new if None)

    Returns:
        Base64-encoded encrypted data
    """
    if service is None:
        service = EncryptionService()

    if isinstance(data, dict):
        return service.encrypt_dict(data)
    elif isinstance(data, str):
        return service.encrypt_string(data)
    elif isinstance(data, bytes):
        encrypted = service.encrypt_fernet(data)
        return base64.b64encode(encrypted).decode()
    else:
        raise ValueError(f"Unsupported data type: {type(data)}")


def decrypt_data(
    ciphertext: str,
    data_type: str = "string",
    service: Optional[EncryptionService] = None,
) -> Union[str, bytes, Dict[str, Any]]:
    """
    Decrypt data using the default encryption service.

    Args:
        ciphertext: Base64-encoded encrypted data
        data_type: Type of data ('string', 'bytes', or 'dict')
        service: Encryption service instance (creates new if None)

    Returns:
        Decrypted data in the specified type
    """
    if service is None:
        service = EncryptionService()

    if data_type == "dict":
        return service.decrypt_dict(ciphertext)
    elif data_type == "string":
        return service.decrypt_string(ciphertext)
    elif data_type == "bytes":
        encrypted = base64.b64decode(ciphertext.encode())
        return service.decrypt_fernet(encrypted)
    else:
        raise ValueError(f"Unsupported data type: {data_type}")
