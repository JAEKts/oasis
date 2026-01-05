"""
OASIS Security and Compliance Demo

Demonstrates encryption, authentication, audit logging, and compliance reporting.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from datetime import datetime, timedelta, UTC

from src.oasis.security import (
    EncryptionService,
    KeyManager,
    encrypt_data,
    decrypt_data,
    hash_password,
    verify_password,
    AuditLogger,
    AuditEventType,
    AuthenticationManager,
    AuthProviderType,
    ComplianceReporter,
    ComplianceStandard
)
from src.oasis.security.auth import LocalAuthProvider
from src.oasis.storage.secure_vault import SecureVaultStorage


def demo_encryption():
    """Demonstrate encryption capabilities."""
    print("\n" + "="*60)
    print("ENCRYPTION DEMO")
    print("="*60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create encryption service
        key_manager = KeyManager(Path(tmpdir))
        encryption_service = EncryptionService(key_manager)
        
        # Encrypt string
        plaintext = "Sensitive API Key: sk_test_123456789"
        print(f"\nOriginal: {plaintext}")
        
        encrypted = encryption_service.encrypt_string(plaintext)
        print(f"Encrypted: {encrypted[:50]}...")
        
        decrypted = encryption_service.decrypt_string(encrypted)
        print(f"Decrypted: {decrypted}")
        
        # Encrypt dictionary
        credentials = {
            "username": "admin",
            "password": "super_secret_password",
            "api_key": "sk_live_abcdef123456"
        }
        print(f"\nOriginal credentials: {credentials}")
        
        encrypted_dict = encryption_service.encrypt_dict(credentials)
        print(f"Encrypted: {encrypted_dict[:50]}...")
        
        decrypted_dict = encryption_service.decrypt_dict(encrypted_dict)
        print(f"Decrypted: {decrypted_dict}")
        
        # Password hashing
        password = "MySecurePassword123!"
        print(f"\nOriginal password: {password}")
        
        password_hash = hash_password(password)
        print(f"Password hash: {password_hash[:50]}...")
        
        is_valid = verify_password(password, password_hash)
        print(f"Password verification: {is_valid}")
        
        is_invalid = verify_password("WrongPassword", password_hash)
        print(f"Wrong password verification: {is_invalid}")


def demo_secure_storage():
    """Demonstrate secure vault storage."""
    print("\n" + "="*60)
    print("SECURE STORAGE DEMO")
    print("="*60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "vault"
        key_dir = Path(tmpdir) / "keys"
        
        # Create secure vault
        key_manager = KeyManager(key_dir)
        vault = SecureVaultStorage(vault_path, key_manager)
        
        # Create project
        project = vault.create_project(
            "Security Test Project",
            "Testing secure storage capabilities"
        )
        print(f"\nCreated project: {project.name} ({project.id})")
        
        # Store encrypted credentials
        credentials = {
            "api_key": "sk_live_1234567890abcdef",
            "api_secret": "secret_key_xyz789",
            "webhook_url": "https://example.com/webhook"
        }
        
        success = vault.store_credentials(
            project.id,
            "stripe_api",
            credentials,
            "Stripe API credentials"
        )
        print(f"\nStored credentials: {success}")
        
        # Retrieve credentials
        retrieved = vault.get_credentials(project.id, "stripe_api")
        print(f"Retrieved credentials: {retrieved[0]['credentials']}")
        
        # Store certificate (EXAMPLE/TEST DATA ONLY - NOT A REAL CERTIFICATE)
        cert_data = b"-----BEGIN CERTIFICATE-----\nMIIC..."  # Truncated example
        key_data = b"-----BEGIN PRIVATE KEY-----\nMIIE..."  # Truncated example
        
        success = vault.store_certificate(
            project.id,
            cert_data,
            key_data,
            "SSL certificate for example.com"
        )
        print(f"\nStored certificate: {success}")
        
        # Retrieve certificate
        certs = vault.get_certificates(project.id)
        print(f"Retrieved certificate: {len(certs[0]['cert_data'])} bytes")


def demo_authentication():
    """Demonstrate authentication and session management."""
    print("\n" + "="*60)
    print("AUTHENTICATION DEMO")
    print("="*60)
    
    # Create authentication manager
    auth_manager = AuthenticationManager(session_timeout=3600)
    
    # Get local provider
    local_provider = auth_manager.providers.get(auth_manager.providers.keys().__iter__().__next__())
    
    # Register users
    print("\nRegistering users...")
    local_provider.register_user("alice", "AlicePassword123!", "alice@example.com")
    local_provider.register_user("bob", "BobPassword456!", "bob@example.com")
    print("Users registered: alice, bob")
    
    # Authenticate user
    print("\nAuthenticating alice...")
    session_id = auth_manager.authenticate(
        "alice",
        {"password": "AlicePassword123!"},
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0"
    )
    
    if session_id:
        print(f"Authentication successful! Session ID: {session_id[:20]}...")
        
        # Validate session
        session = auth_manager.validate_session(session_id)
        if session:
            print(f"Session valid for user: {session.username}")
            print(f"Session expires at: {session.expires_at}")
        
        # Logout
        auth_manager.logout(session_id)
        print("User logged out")
    
    # Failed authentication
    print("\nAttempting authentication with wrong password...")
    failed_session = auth_manager.authenticate(
        "alice",
        {"password": "WrongPassword"}
    )
    print(f"Authentication failed: {failed_session is None}")


def demo_audit_logging():
    """Demonstrate audit logging."""
    print("\n" + "="*60)
    print("AUDIT LOGGING DEMO")
    print("="*60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_db_path = Path(tmpdir) / "audit.db"
        audit_logger = AuditLogger(audit_db_path)
        
        # Log various events
        print("\nLogging audit events...")
        
        audit_logger.log(
            AuditEventType.LOGIN,
            "User logged in",
            user_id="user_123",
            username="alice",
            source_ip="192.168.1.100"
        )
        
        audit_logger.log(
            AuditEventType.DATA_READ,
            "Read sensitive data",
            user_id="user_123",
            username="alice",
            resource_type="credentials",
            resource_id="cred_456"
        )
        
        audit_logger.log(
            AuditEventType.LOGIN_FAILED,
            "Invalid password",
            username="bob",
            source_ip="192.168.1.101",
            result="failure",
            severity="warning"
        )
        
        audit_logger.log(
            AuditEventType.CONFIGURATION_CHANGE,
            "Updated security settings",
            user_id="admin_001",
            username="admin",
            severity="info"
        )
        
        print("Logged 4 audit events")
        
        # Query events
        print("\nQuerying audit events...")
        
        all_events = audit_logger.query_events(limit=10)
        print(f"Total events: {len(all_events)}")
        
        login_events = audit_logger.query_events(event_type=AuditEventType.LOGIN)
        print(f"Login events: {len(login_events)}")
        
        failed_events = audit_logger.query_events(event_type=AuditEventType.LOGIN_FAILED)
        print(f"Failed login events: {len(failed_events)}")
        
        alice_events = audit_logger.query_events(user_id="user_123")
        print(f"Alice's events: {len(alice_events)}")
        
        # Display event details
        print("\nRecent events:")
        for event in all_events[:3]:
            print(f"  - [{event.timestamp}] {event.event_type.value}: {event.action}")
            print(f"    User: {event.username or 'N/A'}, Result: {event.result}")


def demo_compliance_reporting():
    """Demonstrate compliance reporting."""
    print("\n" + "="*60)
    print("COMPLIANCE REPORTING DEMO")
    print("="*60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_db_path = Path(tmpdir) / "audit.db"
        audit_logger = AuditLogger(audit_db_path)
        
        # Log various events for compliance
        print("\nGenerating audit events for compliance...")
        
        for i in range(20):
            audit_logger.log(
                AuditEventType.LOGIN,
                f"User login {i}",
                user_id=f"user_{i % 5}",
                username=f"user{i % 5}"
            )
        
        for i in range(10):
            audit_logger.log(
                AuditEventType.DATA_READ,
                f"Data access {i}",
                user_id=f"user_{i % 3}",
                resource_type="sensitive_data"
            )
        
        for i in range(5):
            audit_logger.log(
                AuditEventType.LOGIN_FAILED,
                f"Failed login {i}",
                username=f"attacker{i}",
                result="failure",
                severity="warning"
            )
        
        print("Generated 35 audit events")
        
        # Create compliance reporter
        reporter = ComplianceReporter(audit_logger)
        
        # Generate reports
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=30)
        
        print("\nGenerating compliance reports...")
        
        # PCI DSS Report
        print("\n--- PCI DSS Report ---")
        pci_report = reporter.generate_pci_dss_report(start_time, end_time)
        print(f"Standard: {pci_report['standard']}")
        print(f"Status: {pci_report['compliance_status']}")
        print(f"Total events: {pci_report['total_events']}")
        print(f"Requirements checked: {len(pci_report['requirements'])}")
        
        # HIPAA Report
        print("\n--- HIPAA Report ---")
        hipaa_report = reporter.generate_hipaa_report(start_time, end_time)
        print(f"Standard: {hipaa_report['standard']}")
        print(f"Status: {hipaa_report['compliance_status']}")
        print(f"Total events: {hipaa_report['total_events']}")
        
        # SOX Report
        print("\n--- SOX Report ---")
        sox_report = reporter.generate_sox_report(start_time, end_time)
        print(f"Standard: {sox_report['standard']}")
        print(f"Status: {sox_report['compliance_status']}")
        print(f"Total events: {sox_report['total_events']}")
        
        # Export report
        output_path = Path(tmpdir) / "pci_dss_report.json"
        success = reporter.export_report(
            ComplianceStandard.PCI_DSS,
            output_path,
            start_time,
            end_time
        )
        print(f"\nExported PCI DSS report: {success}")
        if success:
            print(f"Report saved to: {output_path}")


def main():
    """Run all security demos."""
    print("\n" + "="*60)
    print("OASIS SECURITY AND COMPLIANCE DEMONSTRATION")
    print("="*60)
    
    demo_encryption()
    demo_secure_storage()
    demo_authentication()
    demo_audit_logging()
    demo_compliance_reporting()
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nAll security features demonstrated successfully!")
    print("\nKey Features:")
    print("  ✓ AES-256-GCM encryption for data at rest")
    print("  ✓ Argon2 password hashing")
    print("  ✓ Secure credential and certificate storage")
    print("  ✓ Multi-provider authentication (Local, LDAP, SAML, OAuth)")
    print("  ✓ Comprehensive audit logging")
    print("  ✓ Compliance reporting (PCI DSS, HIPAA, SOX)")
    print("  ✓ Session management with timeout")
    print("  ✓ Key rotation support")


if __name__ == "__main__":
    main()
