# OASIS Collaborator Service

The Collaborator Service provides out-of-band application security testing (OAST) capabilities for detecting blind vulnerabilities such as SSRF, XXE, and DNS exfiltration.

## Features

- **Unique Payload Generation**: Creates unique subdomains for DNS-based interaction detection
- **Multi-Protocol Support**: Captures DNS, HTTP, HTTPS, and SMTP interactions
- **Payload Correlation**: Automatically correlates interactions with originating payloads
- **Forensic Analysis**: Captures detailed information including source IP, timing, and payload data
- **Flexible Deployment**: Supports both cloud-hosted and self-hosted deployments

## Usage

### Basic Usage

```python
from oasis.collaborator import CollaboratorService, PayloadType

# Initialize the service
service = CollaboratorService(base_domain="oasis-collab.local")

# Generate a DNS payload
payload = await service.generate_payload(PayloadType.DNS_LOOKUP)
print(f"DNS Payload: {payload.get_dns_payload()}")

# Capture a DNS interaction
interaction = await service.capture_dns_interaction(
    query_name=payload.full_domain,
    query_type="A",
    source_ip="192.168.1.100"
)

# Poll for interactions
interactions = await service.poll_interactions(payload.id)
print(f"Captured {len(interactions)} interactions")
```

### HTTP Payload Generation

```python
# Generate an HTTP payload
http_payload = await service.generate_payload(
    PayloadType.HTTP_REQUEST,
    metadata={"test_id": "ssrf-001"}
)

# Use in testing
url = http_payload.get_http_payload(protocol="https")
# Inject URL into application and wait for callback
```

### SMTP Interaction Capture

```python
# Capture SMTP interaction
smtp_interaction = await service.capture_smtp_interaction(
    from_address="attacker@example.com",
    to_address=f"test@{payload.full_domain}",
    source_ip="10.0.0.50",
    subject="Test Email",
    body="Email body content"
)
```

## Architecture

The Collaborator Service consists of:

1. **Payload Generator**: Creates unique, collision-resistant subdomains
2. **Interaction Capture**: Records all interactions with generated payloads
3. **Correlation Engine**: Maps interactions back to originating payloads
4. **Listener Framework**: Supports multiple protocol listeners (DNS, HTTP, SMTP)

## Deployment Options

### Self-Hosted
- Full control over infrastructure
- No data leaves your network
- Requires DNS and web server configuration

### Cloud-Hosted
- Managed service with public DNS
- Easier setup and maintenance
- Suitable for external testing scenarios
