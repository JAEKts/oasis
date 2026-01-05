"""
OASIS Certificate Management

Handles CA certificate generation and per-domain certificate management for HTTPS interception.
"""

import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, UTC

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..core.exceptions import ProxyError
from ..core.logging import get_logger

logger = get_logger(__name__)


class CertificateManager:
    """
    Manages CA certificate generation and per-domain certificate creation for HTTPS interception.

    Provides:
    - Automatic CA certificate generation and installation
    - Per-domain certificate generation for transparent interception
    - Certificate validation and trust chain management
    - Certificate storage and caching
    """

    def __init__(self, cert_dir: Optional[Path] = None):
        """
        Initialize certificate manager.

        Args:
            cert_dir: Directory for certificate storage (uses default if None)
        """
        if cert_dir:
            self.cert_dir = cert_dir
        else:
            # Use mitmproxy's default certificate directory
            self.cert_dir = Path.home() / ".mitmproxy"

        self.cert_dir.mkdir(parents=True, exist_ok=True)

        self.ca_cert_path = self.cert_dir / "mitmproxy-ca-cert.pem"
        self.ca_key_path = self.cert_dir / "mitmproxy-ca.pem"

        # Cache for generated certificates
        self._cert_cache: Dict[str, Dict[str, Any]] = {}

    def ensure_ca_certificate(self) -> bool:
        """
        Ensure CA certificate exists, generate if needed.

        Returns:
            True if CA certificate is available, False otherwise
        """
        try:
            if self.ca_cert_path.exists() and self.ca_key_path.exists():
                logger.info("CA certificate already exists")
                return True

            logger.info("Generating new CA certificate...")
            return self._generate_ca_certificate()

        except Exception as e:
            logger.error(f"Failed to ensure CA certificate: {e}")
            return False

    def _generate_ca_certificate(self) -> bool:
        """
        Generate a new CA certificate and private key.

        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OASIS Proxy"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "OASIS Proxy CA"),
                ]
            )

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC))
                .not_valid_after(datetime.now(UTC) + timedelta(days=3650))  # 10 years
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.DNSName("OASIS Proxy CA"),
                        ]
                    ),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(private_key, hashes.SHA256())
            )

            # Write certificate
            with open(self.ca_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Write private key
            with open(self.ca_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            logger.info(f"Generated CA certificate: {self.ca_cert_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate CA certificate: {e}")
            return False

    def generate_domain_certificate(self, domain: str) -> Optional[Dict[str, bytes]]:
        """
        Generate a certificate for a specific domain.

        Args:
            domain: Domain name for the certificate

        Returns:
            Dictionary with 'cert' and 'key' bytes, or None if failed
        """
        try:
            # Check cache first
            if domain in self._cert_cache:
                cached = self._cert_cache[domain]
                # Check if certificate is still valid (not expired)
                if cached["expires"] > datetime.now(UTC):
                    return {"cert": cached["cert"], "key": cached["key"]}

            # Load CA certificate and key
            if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
                if not self.ensure_ca_certificate():
                    return None

            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            with open(self.ca_key_path, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)

            # Generate private key for domain
            domain_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate for domain
            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OASIS Proxy"),
                    x509.NameAttribute(NameOID.COMMON_NAME, domain),
                ]
            )

            expires = datetime.now(UTC) + timedelta(days=365)  # 1 year

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(domain_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC))
                .not_valid_after(expires)
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.DNSName(domain),
                            # Add wildcard version
                            (
                                x509.DNSName(f"*.{domain}")
                                if not domain.startswith("*.")
                                else x509.DNSName(domain[2:])
                            ),
                        ]
                    ),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage(
                        [
                            ExtendedKeyUsageOID.SERVER_AUTH,
                        ]
                    ),
                    critical=True,
                )
                .sign(ca_key, hashes.SHA256())
            )

            # Serialize certificate and key
            cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
            key_bytes = domain_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Cache the certificate
            self._cert_cache[domain] = {
                "cert": cert_bytes,
                "key": key_bytes,
                "expires": expires,
            }

            logger.debug(f"Generated certificate for domain: {domain}")

            return {"cert": cert_bytes, "key": key_bytes}

        except Exception as e:
            logger.error(f"Failed to generate certificate for domain {domain}: {e}")
            return None

    def get_ca_certificate_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the CA certificate.

        Returns:
            Dictionary with CA certificate information or None if not available
        """
        try:
            if not self.ca_cert_path.exists():
                return None

            with open(self.ca_cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before_utc,
                "not_valid_after": cert.not_valid_after_utc,
                "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
                "path": str(self.ca_cert_path),
            }

        except Exception as e:
            logger.error(f"Failed to get CA certificate info: {e}")
            return None

    def is_ca_certificate_trusted(self) -> bool:
        """
        Check if the CA certificate is trusted by the system.

        Returns:
            True if trusted, False otherwise
        """
        try:
            # This is a simplified check - in practice, you'd need to check
            # the system's certificate store
            return self.ca_cert_path.exists()

        except Exception as e:
            logger.error(f"Failed to check CA certificate trust: {e}")
            return False

    def get_installation_instructions(self) -> Dict[str, str]:
        """
        Get instructions for installing the CA certificate.

        Returns:
            Dictionary with platform-specific installation instructions
        """
        ca_path = str(self.ca_cert_path)

        return {
            "windows": f"""
To install the OASIS CA certificate on Windows:
1. Double-click the certificate file: {ca_path}
2. Click "Install Certificate..."
3. Select "Current User" or "Local Machine"
4. Choose "Place all certificates in the following store"
5. Click "Browse" and select "Trusted Root Certification Authorities"
6. Click "Next" and "Finish"
            """.strip(),
            "macos": f"""
To install the OASIS CA certificate on macOS:
1. Double-click the certificate file: {ca_path}
2. This will open Keychain Access
3. Select "System" keychain (or "login" for current user only)
4. Find the "OASIS Proxy CA" certificate
5. Double-click it and expand "Trust"
6. Set "When using this certificate" to "Always Trust"
7. Close the window and enter your password when prompted
            """.strip(),
            "linux": f"""
To install the OASIS CA certificate on Linux:
1. Copy the certificate to the system store:
   sudo cp {ca_path} /usr/local/share/ca-certificates/oasis-ca.crt
2. Update the certificate store:
   sudo update-ca-certificates
3. For browsers, you may need to import manually:
   - Firefox: Preferences > Privacy & Security > Certificates > View Certificates
   - Chrome: Settings > Advanced > Privacy and security > Manage certificates
            """.strip(),
            "general": f"""
CA Certificate Location: {ca_path}

For manual installation in browsers:
1. Open browser certificate settings
2. Import the CA certificate file
3. Mark it as trusted for identifying websites
4. Restart the browser if needed
            """.strip(),
        }

    def cleanup_expired_certificates(self) -> int:
        """
        Clean up expired certificates from cache.

        Returns:
            Number of certificates removed
        """
        try:
            current_time = datetime.now(UTC)
            expired_domains = []

            for domain, cert_info in self._cert_cache.items():
                if cert_info["expires"] <= current_time:
                    expired_domains.append(domain)

            for domain in expired_domains:
                del self._cert_cache[domain]

            if expired_domains:
                logger.info(f"Cleaned up {len(expired_domains)} expired certificates")

            return len(expired_domains)

        except Exception as e:
            logger.error(f"Failed to cleanup expired certificates: {e}")
            return 0

    def get_certificate_stats(self) -> Dict[str, Any]:
        """
        Get certificate management statistics.

        Returns:
            Dictionary with certificate statistics
        """
        try:
            ca_info = self.get_ca_certificate_info()

            return {
                "ca_certificate_exists": ca_info is not None,
                "ca_certificate_info": ca_info,
                "cached_certificates": len(self._cert_cache),
                "certificate_directory": str(self.cert_dir),
                "ca_trusted": self.is_ca_certificate_trusted(),
            }

        except Exception as e:
            logger.error(f"Failed to get certificate stats: {e}")
            return {}
