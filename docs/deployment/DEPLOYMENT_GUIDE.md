# OASIS Deployment Guide

This guide covers the deployment process for the OASIS Penetration Testing Suite, including installation, configuration, updates, and security considerations.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Security Setup](#security-setup)
5. [Updates](#updates)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **OS**: Windows 10+, macOS 11+, or Linux (Ubuntu 20.04+, RHEL 8+)
- **CPU**: 4 cores
- **RAM**: 8 GB
- **Disk**: 10 GB free space
- **Python**: 3.11 or higher

### Recommended Requirements

- **OS**: Latest stable version
- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Disk**: 50+ GB SSD
- **Python**: 3.11+
- **Network**: 1 Gbps

## Installation

### Linux Installation

```bash
# Download package
wget https://downloads.oasis-pentest.org/oasis-0.1.0-linux-x64.tar.gz

# Verify checksum
sha256sum oasis-0.1.0-linux-x64.tar.gz
# Compare with published checksum

# Extract
tar -xzf oasis-0.1.0-linux-x64.tar.gz
cd oasis-0.1.0

# Install dependencies
./install.sh

# Run OASIS
./oasis.sh
```

### macOS Installation

```bash
# Download package
curl -O https://downloads.oasis-pentest.org/oasis-0.1.0-macos-x64.tar.gz

# Verify checksum
shasum -a 256 oasis-0.1.0-macos-x64.tar.gz

# Extract
tar -xzf oasis-0.1.0-macos-x64.tar.gz
cd oasis-0.1.0

# Install dependencies
./install.sh

# Run OASIS
./oasis.sh
```

### Windows Installation

```powershell
# Download package
Invoke-WebRequest -Uri https://downloads.oasis-pentest.org/oasis-0.1.0-windows-x64.zip -OutFile oasis-0.1.0-windows-x64.zip

# Verify checksum
Get-FileHash oasis-0.1.0-windows-x64.zip -Algorithm SHA256

# Extract
Expand-Archive oasis-0.1.0-windows-x64.zip -DestinationPath oasis-0.1.0

# Install dependencies
cd oasis-0.1.0
.\install.bat

# Run OASIS
.\oasis.bat
```

### Docker Installation

```bash
# Pull image
docker pull oasis/oasis-pentest:latest

# Run container
docker run -d \
  --name oasis \
  -p 8080:8080 \
  -p 8888:8888 \
  -v oasis-data:/data \
  oasis/oasis-pentest:latest

# Access OASIS
open http://localhost:8080
```

## Configuration

### Initial Configuration

Create configuration file at `~/.oasis/config.yaml`:

```yaml
# OASIS Configuration

# Proxy settings
proxy:
  host: 127.0.0.1
  port: 8888
  https_enabled: true
  certificate_path: ~/.oasis/certs/

# Storage settings
storage:
  type: sqlite  # sqlite, postgresql
  path: ~/.oasis/vault.db
  max_size_mb: 10000
  auto_cleanup: true

# Performance settings
performance:
  max_concurrent_connections: 1000
  max_memory_mb: 2000
  thread_pool_size: 10

# Security settings
security:
  encryption_enabled: true
  audit_logging: true
  audit_log_path: ~/.oasis/audit.log

# Update settings
updates:
  channel: stable  # stable, beta, nightly
  auto_check: true
  auto_install: false
```

### Environment Variables

```bash
# Set OASIS home directory
export OASIS_HOME=~/.oasis

# Set log level
export OASIS_LOG_LEVEL=INFO

# Set proxy port
export OASIS_PROXY_PORT=8888

# Set API port
export OASIS_API_PORT=8080
```

## Security Setup

### Certificate Generation

Generate CA certificate for HTTPS interception:

```bash
# Generate CA private key
openssl genrsa -out ~/.oasis/certs/ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 \
  -key ~/.oasis/certs/ca-key.pem \
  -out ~/.oasis/certs/ca-cert.pem \
  -subj "/CN=OASIS CA"

# Install CA certificate (varies by OS)
# Linux:
sudo cp ~/.oasis/certs/ca-cert.pem /usr/local/share/ca-certificates/oasis-ca.crt
sudo update-ca-certificates

# macOS:
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.oasis/certs/ca-cert.pem

# Windows (run as Administrator):
certutil -addstore -f "ROOT" %USERPROFILE%\.oasis\certs\ca-cert.pem
```

### Encryption Setup

Configure data encryption:

```bash
# Generate encryption key
python -m oasis.security.encryption generate-key \
  --output ~/.oasis/encryption.key

# Set permissions
chmod 600 ~/.oasis/encryption.key

# Configure OASIS to use encryption
oasis config set security.encryption_key_path ~/.oasis/encryption.key
```

### Authentication Setup

Configure authentication (optional):

```yaml
# Add to config.yaml
authentication:
  enabled: true
  type: local  # local, ldap, saml, oauth
  
  # Local authentication
  local:
    users_file: ~/.oasis/users.db
  
  # LDAP authentication
  ldap:
    server: ldap://ldap.example.com
    base_dn: dc=example,dc=com
    bind_dn: cn=admin,dc=example,dc=com
    bind_password: secret
```

## Updates

### Checking for Updates

```bash
# Check for updates
oasis update check

# Check specific channel
oasis update check --channel beta
```

### Installing Updates

```bash
# Download and install update
oasis update install

# Install specific version
oasis update install --version 0.2.0

# Install with automatic backup
oasis update install --backup
```

### Update Verification

Updates are cryptographically signed and verified:

```bash
# Verify update package
oasis update verify oasis-0.2.0.pkg

# Check signature
openssl dgst -sha256 -verify update_key.pub \
  -signature oasis-0.2.0.sig \
  oasis-0.2.0.pkg
```

### Rollback

If an update fails:

```bash
# Rollback to previous version
oasis update rollback

# Rollback to specific version
oasis update rollback --version 0.1.0
```

## Monitoring

### Health Checks

```bash
# Check system health
oasis health

# Check specific component
oasis health --component proxy
oasis health --component scanner
oasis health --component storage
```

### Performance Monitoring

```bash
# View performance metrics
oasis metrics

# Export metrics
oasis metrics export --format prometheus --output metrics.txt
```

### Log Monitoring

```bash
# View logs
oasis logs

# Follow logs
oasis logs --follow

# Filter logs
oasis logs --level ERROR
oasis logs --component proxy
```

### Resource Usage

```bash
# View resource usage
oasis status

# Output:
# CPU: 25%
# Memory: 1.2 GB / 2.0 GB
# Connections: 150 / 1000
# Storage: 5.2 GB / 10.0 GB
```

## Troubleshooting

### Common Issues

#### Proxy Not Starting

```bash
# Check if port is in use
netstat -an | grep 8888

# Try different port
oasis config set proxy.port 8889
oasis restart
```

#### Certificate Errors

```bash
# Regenerate certificates
oasis cert regenerate

# Reinstall CA certificate
oasis cert install
```

#### Performance Issues

```bash
# Check resource usage
oasis status

# Increase memory limit
oasis config set performance.max_memory_mb 4000

# Increase connection limit
oasis config set performance.max_concurrent_connections 2000

# Restart OASIS
oasis restart
```

#### Storage Issues

```bash
# Check storage usage
oasis storage status

# Clean up old data
oasis storage cleanup --older-than 30d

# Compact database
oasis storage compact
```

### Debug Mode

Enable debug logging:

```bash
# Enable debug mode
export OASIS_LOG_LEVEL=DEBUG
oasis restart

# View debug logs
oasis logs --level DEBUG
```

### Support

For additional support:

- **Documentation**: https://docs.oasis-pentest.org
- **GitHub Issues**: https://github.com/oasis-pentest/oasis/issues
- **Community Forum**: https://forum.oasis-pentest.org
- **Email**: support@oasis-pentest.org

## Security Considerations

### Production Deployment

For production deployments:

1. **Use HTTPS**: Always use HTTPS for web interface
2. **Enable Authentication**: Require authentication for all users
3. **Enable Audit Logging**: Track all user actions
4. **Regular Updates**: Keep OASIS up to date
5. **Backup Data**: Regular backups of project data
6. **Network Isolation**: Deploy in isolated network segment
7. **Access Control**: Limit access to authorized users only

### Vulnerability Disclosure

To report security vulnerabilities:

- **Email**: security@oasis-pentest.org
- **PGP Key**: Available at https://oasis-pentest.org/security/pgp-key.asc
- **Disclosure Policy**: 90-day coordinated disclosure

### Security Updates

Security updates are released as needed:

- **Critical**: Released immediately
- **High**: Released within 7 days
- **Medium/Low**: Released in next regular update

Subscribe to security announcements:
- **Mailing List**: security-announce@oasis-pentest.org
- **RSS Feed**: https://oasis-pentest.org/security/feed.xml

## Backup and Recovery

### Backup

```bash
# Backup all data
oasis backup create --output backup-$(date +%Y%m%d).tar.gz

# Backup specific project
oasis backup create --project "Project Name" --output project-backup.tar.gz

# Automated backups
oasis backup schedule --daily --time 02:00 --output /backups/
```

### Recovery

```bash
# Restore from backup
oasis backup restore --input backup-20260105.tar.gz

# Restore specific project
oasis backup restore --input project-backup.tar.gz --project "Project Name"
```

## Uninstallation

### Linux/macOS

```bash
# Stop OASIS
oasis stop

# Remove application
rm -rf ~/oasis-0.1.0

# Remove data (optional)
rm -rf ~/.oasis

# Remove CA certificate
# Linux:
sudo rm /usr/local/share/ca-certificates/oasis-ca.crt
sudo update-ca-certificates

# macOS:
sudo security delete-certificate -c "OASIS CA" \
  /Library/Keychains/System.keychain
```

### Windows

```powershell
# Stop OASIS
oasis stop

# Remove application
Remove-Item -Recurse -Force C:\oasis-0.1.0

# Remove data (optional)
Remove-Item -Recurse -Force $env:USERPROFILE\.oasis

# Remove CA certificate (run as Administrator)
certutil -delstore "ROOT" "OASIS CA"
```

## Conclusion

This guide covers the essential aspects of deploying and managing OASIS. For more detailed information, refer to the complete documentation at https://docs.oasis-pentest.org.
---

**Last Updated**: January 05, 2026
