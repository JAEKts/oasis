# OASIS Deployment Module

This module provides secure update mechanisms, vulnerability disclosure processes, and deployment packaging for the OASIS penetration testing suite.

## Components

### Update Manager (`updater.py`)

Handles secure software updates with cryptographic signature verification:

- **Update Checking**: Queries update server for available updates
- **Signature Verification**: Verifies updates using RSA signatures
- **Checksum Validation**: Validates SHA256 checksums
- **Progress Tracking**: Provides real-time update progress
- **Rollback Support**: Maintains backups for rollback capability

**Usage:**

```python
from oasis.deployment import UpdateManager, UpdateChannel, UpdateVerifier

# Initialize update manager
verifier = UpdateVerifier(public_key_path=Path("update_key.pub"))
manager = UpdateManager(
    current_version="0.1.0",
    update_server_url="https://updates.oasis-pentest.org",
    channel=UpdateChannel.STABLE,
    verifier=verifier
)

# Check for updates
update_info = await manager.check_for_updates()
if update_info:
    print(f"Update available: {update_info.version}")
    
    # Perform update
    success = await manager.perform_update(update_info)
    if success:
        print("Update installed successfully")
```

### Vulnerability Disclosure (`security.py`)

Manages responsible vulnerability disclosure and security update pipeline:

- **Report Submission**: Accept vulnerability reports from researchers
- **Status Tracking**: Track vulnerability lifecycle from report to disclosure
- **Disclosure Scheduling**: Schedule coordinated disclosure (default 90 days)
- **Security Updates**: Create and distribute security patches
- **CVE Integration**: Track CVE IDs and CVSS scores

**Usage:**

```python
from oasis.deployment import VulnerabilityDisclosure, VulnerabilitySeverity

# Initialize disclosure manager
disclosure = VulnerabilityDisclosure(
    disclosure_email="security@oasis-pentest.org",
    disclosure_url="https://oasis-pentest.org/security"
)

# Submit vulnerability report
report = disclosure.submit_report(
    title="SQL Injection in Scanner Module",
    description="Detailed vulnerability description...",
    severity=VulnerabilitySeverity.HIGH,
    reporter="John Doe",
    reporter_email="john@example.com",
    affected_versions=["0.1.0", "0.2.0"],
    proof_of_concept="PoC code..."
)

# Update status when fixed
disclosure.update_status(
    report.id,
    DisclosureStatus.FIXED,
    remediation="Updated input validation",
    fixed_version="0.3.0"
)

# Schedule disclosure
disclosure.schedule_disclosure(report.id)
```

### Security Update Pipeline

Automates security update creation and distribution:

```python
from oasis.deployment import SecurityUpdatePipeline

# Initialize pipeline
pipeline = SecurityUpdatePipeline(
    disclosure_manager=disclosure,
    build_server_url="https://build.oasis-pentest.org"
)

# Create security update
update = await pipeline.create_security_update(
    version="0.3.0",
    vulnerability_ids=[report.id],
    description="Security update fixing SQL injection vulnerability"
)

# Get applicable updates for a version
updates = pipeline.get_updates_for_version("0.2.0")
```

### Deployment Packager (`packager.py`)

Creates deployment packages for multiple platforms:

- **Multi-Platform Support**: Windows, macOS, Linux
- **Multiple Formats**: ZIP, TAR.GZ, DEB, RPM, DMG, MSI, AppImage
- **Checksum Generation**: SHA256 checksums for verification
- **Platform-Specific Files**: Launchers, installers, service files

**Usage:**

```python
from oasis.deployment import DeploymentPackager, Platform

# Initialize packager
packager = DeploymentPackager(
    project_root=Path("/path/to/oasis"),
    version="0.3.0"
)

# Package for all platforms
packages = await packager.package_all_platforms()

# Package for specific platform
linux_package = await packager.package_platform(Platform.LINUX)

# Generate release notes
notes = packager.generate_release_notes(packages)
print(notes)
```

## Security Considerations

### Update Security

1. **Signature Verification**: All updates must be signed with RSA private key
2. **Checksum Validation**: SHA256 checksums prevent tampering
3. **HTTPS Only**: All update downloads use HTTPS
4. **Public Key Distribution**: Public key distributed with initial installation

### Vulnerability Disclosure

1. **Responsible Disclosure**: 90-day disclosure timeline by default
2. **Coordinated Release**: Security updates released before public disclosure
3. **CVE Assignment**: Request CVE IDs for significant vulnerabilities
4. **Communication**: Keep reporters informed throughout process

### Package Integrity

1. **Checksums**: SHA256 checksums for all packages
2. **Signatures**: Cryptographic signatures for verification
3. **Secure Distribution**: HTTPS-only download channels
4. **Verification Instructions**: Clear verification steps in documentation

## Update Server API

The update server should implement the following endpoints:

### GET /api/updates/{channel}/latest

Returns information about the latest update:

```json
{
  "version": "0.3.0",
  "release_date": "2026-01-05T12:00:00Z",
  "channel": "stable",
  "download_url": "https://downloads.oasis-pentest.org/oasis-0.3.0.pkg",
  "signature_url": "https://downloads.oasis-pentest.org/oasis-0.3.0.sig",
  "checksum": "abc123...",
  "size_bytes": 52428800,
  "release_notes": "Security update fixing...",
  "critical": true,
  "security_update": true
}
```

### POST /api/build

Triggers a build for a security update:

```json
{
  "version": "0.3.0",
  "vulnerabilities": ["uuid1", "uuid2"],
  "security_update": true
}
```

Returns:

```json
{
  "download_url": "https://downloads.oasis-pentest.org/oasis-0.3.0.pkg",
  "signature_url": "https://downloads.oasis-pentest.org/oasis-0.3.0.sig"
}
```

## Key Generation

Generate RSA key pair for update signing:

```bash
# Generate private key (keep secure!)
openssl genrsa -out update_key.pem 4096

# Extract public key (distribute with application)
openssl rsa -in update_key.pem -pubout -out update_key.pub

# Sign an update package
openssl dgst -sha256 -sign update_key.pem -out oasis-0.3.0.sig oasis-0.3.0.pkg
```

## Testing

Test the deployment components:

```bash
# Run deployment tests
pytest tests/deployment/ -v

# Test update verification
python -m oasis.deployment.updater --verify oasis-0.3.0.pkg

# Test package creation
python -m oasis.deployment.packager --version 0.3.0 --platform linux
```

## Requirements

This module validates **Requirement 12.6**:

> WHEN vulnerabilities are discovered in the tool itself, THE OASIS_System SHALL provide secure update mechanisms and vulnerability disclosure processes

The implementation provides:

- ✅ Secure update mechanisms with signature verification
- ✅ Vulnerability disclosure process with status tracking
- ✅ Security update pipeline for coordinated releases
- ✅ Deployment packaging for multiple platforms (Windows, macOS, Linux)
- ✅ Checksum validation and integrity verification
- ✅ Rollback capabilities for failed updates
