# OASIS Security Module

The OASIS Security Module provides comprehensive security features including encryption, authentication, audit logging, and compliance reporting to meet enterprise security requirements.

## Features

### 1. Encryption at Rest and In Transit

- **AES-256-GCM** encryption for sensitive data
- **Fernet** encryption for simpler use cases
- **Argon2** password hashing with salt
- Secure key management and rotation
- Authenticated Encryption with Associated Data (AEAD)

### 2. Authentication and Session Management

- Multiple authentication providers:
  - Local authentication with password hashing
  - LDAP integration (enterprise)
  - SAML integration (enterprise)
  - OAuth integration (enterprise)
- Session management with configurable timeout
- User activity tracking
- Failed login attempt monitoring

### 3. Audit Logging

- Comprehensive logging of all user actions and system events
- Tamper-evident audit trail storage
- Query and filtering capabilities
- Event categorization by severity
- Time-range and user-based filtering

### 4. Compliance Reporting

- **PCI DSS** compliance reporting
- **HIPAA** compliance reporting
- **SOX** compliance reporting
- Automated compliance checks
- Export to JSON, HTML, and PDF formats

## Usage Examples

### Encryption

```python
from src.oasis.security import EncryptionService, KeyManager

# Create encryption service
key_manager = KeyManager()
encryption_service = EncryptionService(key_manager)

# Encrypt string
plaintext = "Sensitive data"
encrypted = encryption_service.encrypt_string(plaintext)
decrypted = encryption_service.decrypt_string(encrypted)

# Encrypt dictionary
credentials = {"api_key": "secret", "password": "pass123"}
encrypted_dict = encryption_service.encrypt_dict(credentials)
decrypted_dict = encryption_service.decrypt_dict(encrypted_dict)

# Password hashing
from src.oasis.security import hash_password, verify_password

password_hash = hash_password("MyPassword123!")
is_valid = verify_password("MyPassword123!", password_hash)
```

### Secure Storage

```python
from src.oasis.storage.secure_vault import SecureVaultStorage

# Create secure vault
vault = SecureVaultStorage()

# Create project
project = vault.create_project("My Project", "Description")

# Store encrypted credentials
credentials = {
    "api_key": "sk_live_123456",
    "api_secret": "secret_xyz"
}
vault.store_credentials(project.id, "stripe_api", credentials)

# Retrieve credentials
creds = vault.get_credentials(project.id, "stripe_api")

# Store certificate (example/test data only)
cert_data = b"-----BEGIN CERTIFICATE-----..."  # Example certificate
key_data = b"-----BEGIN PRIVATE KEY-----..."  # Example private key
vault.store_certificate(project.id, cert_data, key_data)
```

### Authentication

```python
from src.oasis.security import AuthenticationManager
from src.oasis.security.auth import LocalAuthProvider

# Create authentication manager
auth_manager = AuthenticationManager(session_timeout=3600)

# Register user
local_provider = list(auth_manager.providers.values())[0]
local_provider.register_user("alice", "Password123!", "alice@example.com")

# Authenticate
session_id = auth_manager.authenticate(
    "alice",
    {"password": "Password123!"},
    ip_address="192.168.1.100"
)

# Validate session
session = auth_manager.validate_session(session_id)

# Logout
auth_manager.logout(session_id)
```

### Audit Logging

```python
from src.oasis.security import AuditLogger, AuditEventType

# Create audit logger
audit_logger = AuditLogger()

# Log events
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
    resource_type="credentials",
    resource_id="cred_456"
)

# Query events
events = audit_logger.query_events(
    event_type=AuditEventType.LOGIN,
    user_id="user_123"
)

# Get event count
count = audit_logger.get_event_count(
    event_type=AuditEventType.LOGIN_FAILED
)
```

### Compliance Reporting

```python
from src.oasis.security import ComplianceReporter, ComplianceStandard
from datetime import datetime, timedelta, UTC

# Create compliance reporter
reporter = ComplianceReporter()

# Generate PCI DSS report
end_time = datetime.now(UTC)
start_time = end_time - timedelta(days=30)

pci_report = reporter.generate_pci_dss_report(start_time, end_time)
print(f"Status: {pci_report['compliance_status']}")
print(f"Total events: {pci_report['total_events']}")

# Generate HIPAA report
hipaa_report = reporter.generate_hipaa_report(start_time, end_time)

# Generate SOX report
sox_report = reporter.generate_sox_report(start_time, end_time)

# Export report
from pathlib import Path
reporter.export_report(
    ComplianceStandard.PCI_DSS,
    Path("pci_dss_report.json"),
    start_time,
    end_time
)
```

## Security Best Practices

### Key Management

- Master keys are stored in `~/.oasis/.keys/` with restricted permissions (0600)
- Keys are automatically generated on first use
- Support for key rotation with automatic re-encryption
- Never commit keys to version control

### Password Security

- Passwords are hashed using Argon2 with random salt
- Minimum 8 characters recommended
- Failed login attempts are logged for monitoring
- Session timeout prevents unauthorized access

### Audit Trail

- All security-relevant events are logged
- Audit logs are tamper-evident
- Logs include timestamp, user, action, and result
- Regular review of audit logs is recommended

### Compliance

- PCI DSS Requirement 10: Track and monitor all access
- HIPAA 164.312(b): Audit controls
- SOX ITGC: Access controls and audit trails
- Regular compliance reports should be generated

## Architecture

### Encryption Service

```
EncryptionService
├── KeyManager (key generation and storage)
├── AES-256-GCM (authenticated encryption)
├── Fernet (simple encryption with timestamp)
└── Argon2 (password hashing)
```

### Authentication Manager

```
AuthenticationManager
├── LocalAuthProvider (password-based)
├── LDAPAuthProvider (enterprise directory)
├── SAMLAuthProvider (SSO)
├── OAuthAuthProvider (OAuth 2.0)
└── Session Management
```

### Audit Logger

```
AuditLogger
├── SQLite Database (audit events)
├── Event Querying (filtering and search)
├── Event Counting (statistics)
└── Compliance Reporting
```

### Compliance Reporter

```
ComplianceReporter
├── PCI DSS Reports
├── HIPAA Reports
├── SOX Reports
└── Export (JSON, HTML, PDF)
```

## Testing

The security module includes comprehensive property-based tests:

```bash
# Run security tests
pytest tests/security/test_security_properties.py -v

# Run audit tests
pytest tests/security/test_audit_properties.py -v
```

## Requirements

- Python 3.11+
- cryptography >= 41.0.0
- argon2-cffi >= 23.1.0
- pydantic >= 2.0.0

## Demo

Run the security demo to see all features in action:

```bash
python examples/security_demo.py
```

## License

Part of the OASIS Penetration Testing Suite.
