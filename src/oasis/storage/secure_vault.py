"""
OASIS Secure Vault Storage

Extends the vault storage with encryption at rest for sensitive data.
"""

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.logging import get_logger
from ..core.models import HTTPFlow, Project, Finding
from ..security.encryption import EncryptionService, KeyManager
from ..security.audit import AuditEventType, log_audit_event
from .sqlite_vault import SQLiteVaultStorage

logger = get_logger(__name__)


class SecureVaultStorage(SQLiteVaultStorage):
    """
    Secure vault storage with encryption at rest for sensitive data.

    Extends SQLiteVaultStorage to provide:
    - Encryption of sensitive fields (credentials, certificates, API keys)
    - Transparent encryption/decryption
    - Key rotation support
    - Audit logging of all access
    """

    def __init__(
        self, base_path: Optional[Path] = None, key_manager: Optional[KeyManager] = None
    ) -> None:
        """
        Initialize secure vault storage.

        Args:
            base_path: Base directory for vault storage
            key_manager: Key manager instance (creates new if None)
        """
        super().__init__(base_path)
        self.encryption_service = EncryptionService(key_manager)
        logger.info("Initialized secure vault storage with encryption")

    def _encrypt_sensitive_fields(
        self, data: Dict[str, Any], field_names: List[str]
    ) -> Dict[str, Any]:
        """
        Encrypt sensitive fields in a dictionary.

        Args:
            data: Data dictionary
            field_names: List of field names to encrypt

        Returns:
            Dictionary with encrypted fields
        """
        encrypted_data = data.copy()

        for field_name in field_names:
            if field_name in encrypted_data and encrypted_data[field_name]:
                try:
                    # Convert to string if needed
                    value = encrypted_data[field_name]
                    if isinstance(value, dict):
                        value = json.dumps(value)
                    elif not isinstance(value, str):
                        value = str(value)

                    # Encrypt
                    encrypted_value = self.encryption_service.encrypt_string(value)
                    encrypted_data[field_name] = encrypted_value
                    encrypted_data[f"{field_name}_encrypted"] = True

                except Exception as e:
                    logger.error(f"Failed to encrypt field {field_name}: {e}")

        return encrypted_data

    def _decrypt_sensitive_fields(
        self, data: Dict[str, Any], field_names: List[str]
    ) -> Dict[str, Any]:
        """
        Decrypt sensitive fields in a dictionary.

        Args:
            data: Data dictionary
            field_names: List of field names to decrypt

        Returns:
            Dictionary with decrypted fields
        """
        decrypted_data = data.copy()

        for field_name in field_names:
            if f"{field_name}_encrypted" in decrypted_data and decrypted_data.get(
                f"{field_name}_encrypted"
            ):
                try:
                    # Decrypt
                    encrypted_value = decrypted_data[field_name]
                    decrypted_value = self.encryption_service.decrypt_string(
                        encrypted_value
                    )

                    # Try to parse as JSON if it looks like JSON
                    if decrypted_value.startswith("{") or decrypted_value.startswith(
                        "["
                    ):
                        try:
                            decrypted_value = json.loads(decrypted_value)
                        except json.JSONDecodeError:
                            pass

                    decrypted_data[field_name] = decrypted_value
                    del decrypted_data[f"{field_name}_encrypted"]

                except Exception as e:
                    logger.error(f"Failed to decrypt field {field_name}: {e}")

        return decrypted_data

    def store_credentials(
        self,
        project_id: Union[str, uuid.UUID],
        credential_type: str,
        credentials: Dict[str, Any],
        description: str = "",
    ) -> bool:
        """
        Store encrypted credentials for a project.

        Args:
            project_id: Project ID
            credential_type: Type of credentials (e.g., 'api_key', 'password', 'certificate')
            credentials: Credentials dictionary
            description: Description of credentials

        Returns:
            True if successful, False otherwise
        """
        try:
            # Encrypt entire credentials dictionary
            encrypted_creds = self.encryption_service.encrypt_dict(credentials)

            # Store in database
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS credentials (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        credential_type TEXT NOT NULL,
                        encrypted_data TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
                    )
                """
                )

                cred_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO credentials (id, project_id, credential_type, encrypted_data, description)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        cred_id,
                        str(project_id),
                        credential_type,
                        encrypted_creds,
                        description,
                    ),
                )

            log_audit_event(
                AuditEventType.DATA_WRITE,
                "Stored encrypted credentials",
                resource_type="credentials",
                resource_id=cred_id,
                details={"project_id": str(project_id), "type": credential_type},
            )

            logger.info(f"Stored encrypted credentials for project {project_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store credentials: {e}")
            return False

    def get_credentials(
        self, project_id: Union[str, uuid.UUID], credential_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve and decrypt credentials for a project.

        Args:
            project_id: Project ID
            credential_type: Filter by credential type (optional)

        Returns:
            List of decrypted credentials
        """
        credentials = []
        try:
            with self._get_connection() as conn:
                # Ensure table exists
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS credentials (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        credential_type TEXT NOT NULL,
                        encrypted_data TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
                    )
                """
                )

                query = "SELECT * FROM credentials WHERE project_id = ?"
                params = [str(project_id)]

                if credential_type:
                    query += " AND credential_type = ?"
                    params.append(credential_type)

                cursor = conn.execute(query, params)

                for row in cursor.fetchall():
                    try:
                        # Decrypt credentials
                        decrypted_creds = self.encryption_service.decrypt_dict(
                            row["encrypted_data"]
                        )

                        credentials.append(
                            {
                                "id": row["id"],
                                "credential_type": row["credential_type"],
                                "credentials": decrypted_creds,
                                "description": row["description"],
                                "created_at": row["created_at"],
                            }
                        )

                        log_audit_event(
                            AuditEventType.DATA_READ,
                            "Retrieved encrypted credentials",
                            resource_type="credentials",
                            resource_id=row["id"],
                            details={"project_id": str(project_id)},
                        )

                    except Exception as e:
                        logger.error(f"Failed to decrypt credentials {row['id']}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Failed to get credentials: {e}")

        return credentials

    def store_certificate(
        self,
        project_id: Union[str, uuid.UUID],
        cert_data: bytes,
        key_data: Optional[bytes] = None,
        description: str = "",
    ) -> bool:
        """
        Store encrypted certificate and private key.

        Args:
            project_id: Project ID
            cert_data: Certificate data
            key_data: Private key data (optional)
            description: Description of certificate

        Returns:
            True if successful, False otherwise
        """
        try:
            # Encrypt certificate and key
            encrypted_cert = self.encryption_service.encrypt_fernet(cert_data)
            encrypted_key = (
                self.encryption_service.encrypt_fernet(key_data) if key_data else None
            )

            # Store in database
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS certificates (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        encrypted_cert BLOB NOT NULL,
                        encrypted_key BLOB,
                        description TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
                    )
                """
                )

                cert_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO certificates (id, project_id, encrypted_cert, encrypted_key, description)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        cert_id,
                        str(project_id),
                        encrypted_cert,
                        encrypted_key,
                        description,
                    ),
                )

            log_audit_event(
                AuditEventType.DATA_WRITE,
                "Stored encrypted certificate",
                resource_type="certificate",
                resource_id=cert_id,
                details={"project_id": str(project_id)},
            )

            logger.info(f"Stored encrypted certificate for project {project_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store certificate: {e}")
            return False

    def get_certificates(
        self, project_id: Union[str, uuid.UUID]
    ) -> List[Dict[str, Any]]:
        """
        Retrieve and decrypt certificates for a project.

        Args:
            project_id: Project ID

        Returns:
            List of decrypted certificates
        """
        certificates = []
        try:
            with self._get_connection() as conn:
                # Ensure table exists
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS certificates (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        encrypted_cert BLOB NOT NULL,
                        encrypted_key BLOB,
                        description TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
                    )
                """
                )

                cursor = conn.execute(
                    """
                    SELECT * FROM certificates WHERE project_id = ?
                """,
                    (str(project_id),),
                )

                for row in cursor.fetchall():
                    try:
                        # Decrypt certificate and key
                        cert_data = self.encryption_service.decrypt_fernet(
                            row["encrypted_cert"]
                        )
                        key_data = (
                            self.encryption_service.decrypt_fernet(row["encrypted_key"])
                            if row["encrypted_key"]
                            else None
                        )

                        certificates.append(
                            {
                                "id": row["id"],
                                "cert_data": cert_data,
                                "key_data": key_data,
                                "description": row["description"],
                                "created_at": row["created_at"],
                            }
                        )

                        log_audit_event(
                            AuditEventType.DATA_READ,
                            "Retrieved encrypted certificate",
                            resource_type="certificate",
                            resource_id=row["id"],
                            details={"project_id": str(project_id)},
                        )

                    except Exception as e:
                        logger.error(f"Failed to decrypt certificate {row['id']}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Failed to get certificates: {e}")

        return certificates

    def rotate_encryption_keys(self) -> bool:
        """
        Rotate encryption keys and re-encrypt all sensitive data.

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Starting encryption key rotation")

            # Rotate master key
            old_service = self.encryption_service
            self.encryption_service.key_manager.rotate_master_key()
            new_service = EncryptionService(self.encryption_service.key_manager)

            # Re-encrypt all credentials
            with self._get_connection() as conn:
                # Get all credentials
                cursor = conn.execute("SELECT id, encrypted_data FROM credentials")
                credentials = cursor.fetchall()

                for row in credentials:
                    try:
                        # Decrypt with old key
                        decrypted = old_service.decrypt_dict(row["encrypted_data"])

                        # Encrypt with new key
                        encrypted = new_service.encrypt_dict(decrypted)

                        # Update database
                        conn.execute(
                            """
                            UPDATE credentials SET encrypted_data = ? WHERE id = ?
                        """,
                            (encrypted, row["id"]),
                        )

                    except Exception as e:
                        logger.error(
                            f"Failed to re-encrypt credentials {row['id']}: {e}"
                        )

                # Get all certificates
                cursor = conn.execute(
                    "SELECT id, encrypted_cert, encrypted_key FROM certificates"
                )
                certificates = cursor.fetchall()

                for row in certificates:
                    try:
                        # Decrypt with old key
                        cert_data = old_service.decrypt_fernet(row["encrypted_cert"])
                        key_data = (
                            old_service.decrypt_fernet(row["encrypted_key"])
                            if row["encrypted_key"]
                            else None
                        )

                        # Encrypt with new key
                        encrypted_cert = new_service.encrypt_fernet(cert_data)
                        encrypted_key = (
                            new_service.encrypt_fernet(key_data) if key_data else None
                        )

                        # Update database
                        conn.execute(
                            """
                            UPDATE certificates SET encrypted_cert = ?, encrypted_key = ? WHERE id = ?
                        """,
                            (encrypted_cert, encrypted_key, row["id"]),
                        )

                    except Exception as e:
                        logger.error(
                            f"Failed to re-encrypt certificate {row['id']}: {e}"
                        )

            self.encryption_service = new_service

            log_audit_event(
                AuditEventType.ENCRYPTION_KEY_ROTATE,
                "Encryption keys rotated",
                severity="info",
                details={
                    "credentials_count": len(credentials),
                    "certificates_count": len(certificates),
                },
            )

            logger.info("Encryption key rotation completed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to rotate encryption keys: {e}")
            return False
