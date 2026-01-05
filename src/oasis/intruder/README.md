# OASIS Intruder Module

The Intruder module provides automated attack capabilities with customizable payloads for penetration testing.

## Features

- **Multiple Attack Types**: Sniper, Battering Ram, Pitchfork, and Cluster Bomb
- **Flexible Payload Generation**: Wordlists, number ranges, character sets, and custom generators
- **Built-in Wordlists**: Common passwords, usernames, directories, and attack payloads
- **Payload Processing**: URL encoding, Base64, hashing, and custom transformations
- **Rate Limiting**: Configurable delays and concurrent request limits
- **Result Analysis**: Detailed statistics and filtering capabilities

## Attack Types

### Sniper
Uses a single payload set and tests one injection point at a time. Cycles through all injection points with each payload.

**Use case**: Testing multiple parameters with the same payload set.

### Battering Ram
Uses a single payload set and injects the same payload into all injection points simultaneously.

**Use case**: Testing when all parameters need the same value (e.g., authentication bypass).

### Pitchfork
Uses multiple payload sets with synchronized iteration. Each injection point gets payloads from its corresponding set.

**Use case**: Testing username/password combinations where you have paired lists.

### Cluster Bomb
Uses multiple payload sets and tests all possible combinations (cartesian product).

**Use case**: Brute force attacks where you want to test every combination.

## Usage Example

```python
from oasis.intruder import (
    AttackEngine,
    AttackConfig,
    AttackType,
    InjectionPoint,
    PayloadSet,
    PayloadProcessor,
    ProcessorType,
)
from oasis.core.models import HTTPRequest, RequestSource

# Create base request with injection markers
base_request = HTTPRequest(
    method="POST",
    url="https://example.com/login?user=§username§",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    body=b"password=§password§",
    source=RequestSource.INTRUDER
)

# Define injection points
injection_points = [
    InjectionPoint(
        name="Username",
        location="param",
        key="user",
        marker="§username§"
    ),
    InjectionPoint(
        name="Password",
        location="body",
        key="password",
        marker="§password§"
    )
]

# Create payload sets
username_payloads = PayloadSet(
    name="Usernames",
    generator_type="wordlist",
    generator_config={"builtin": "usernames"}
)

password_payloads = PayloadSet(
    name="Passwords",
    generator_type="wordlist",
    generator_config={"builtin": "passwords"},
    processors=[
        PayloadProcessor(
            name="URL Encode",
            processor_type=ProcessorType.URL_ENCODE
        )
    ]
)

# Create attack configuration
attack_config = AttackConfig(
    name="Login Brute Force",
    attack_type=AttackType.CLUSTER_BOMB,
    base_request=base_request,
    injection_points=injection_points,
    payload_sets=[username_payloads, password_payloads]
)

# Execute attack
engine = AttackEngine()
results = await engine.execute_attack(attack_config)

# Analyze results
print(f"Total requests: {results.statistics.total_requests}")
print(f"Successful: {results.statistics.successful_requests}")
print(f"Failed: {results.statistics.failed_requests}")
print(f"Duration: {results.statistics.duration_seconds:.2f}s")
```

## Built-in Wordlists

The module includes several built-in wordlists:

- `passwords`: Common passwords
- `usernames`: Common usernames
- `directories`: Common web directories
- `extensions`: Common file extensions
- `sql_injection`: SQL injection payloads
- `xss`: Cross-site scripting payloads
- `command_injection`: Command injection payloads
- `path_traversal`: Path traversal payloads

## Payload Processors

Processors transform payloads before injection:

- **Encoding**: URL, Base64, HTML, Hex
- **Hashing**: MD5, SHA1, SHA256
- **Text**: Uppercase, Lowercase
- **Modification**: Prefix, Suffix, Replace
- **Custom**: User-defined transformations

## Rate Limiting

Configure rate limiting to avoid detection:

```python
from oasis.intruder.config import RateLimitConfig

rate_limiting = RateLimitConfig(
    requests_per_second=10.0,
    delay_ms=100,
    concurrent_requests=5
)

attack_config = AttackConfig(
    name="Stealthy Attack",
    attack_type=AttackType.SNIPER,
    base_request=base_request,
    injection_points=injection_points,
    payload_sets=[payload_set],
    rate_limiting=rate_limiting
)
```

## Architecture

The Intruder module consists of:

- **config.py**: Attack configuration models and validation
- **payloads.py**: Payload generation system with built-in wordlists
- **engine.py**: Attack execution engine with rate limiting
- **__init__.py**: Public API exports

## Requirements Mapping

This implementation satisfies:

- **Requirement 5.1**: Multiple attack types (sniper, battering ram, pitchfork, cluster bomb)
- **Requirement 5.2**: Built-in wordlists for common attacks
- **Requirement 5.6**: Custom payload processors for encoding and transformation
