# OASIS Vulnerability Scanner

The OASIS Vulnerability Scanner provides automated security testing capabilities for web applications.

## Features

### Core Components

1. **Scan Engine** - Orchestrates vulnerability detection
   - Passive analysis of intercepted traffic
   - Active probing with test payloads
   - Configurable scan policies and intensity levels

2. **Vulnerability Detectors** - OWASP Top 10 coverage
   - SQL Injection (error-based, boolean-based, time-based)
   - Cross-Site Scripting (reflected, stored, DOM-based)
   - Cross-Site Request Forgery (CSRF)
   - Server-Side Request Forgery (SSRF)
   - XML External Entity (XXE)

3. **Finding Management** - Comprehensive result handling
   - Categorization by severity (Critical, High, Medium, Low, Info)
   - False positive tracking and management
   - Filtering by severity, type, and confidence
   - Statistical analysis and reporting

4. **Report Generation** - Multiple output formats
   - JSON, HTML, Markdown, CSV, XML, PDF
   - Customizable filtering and content
   - Proof-of-concept payloads included
   - Remediation guidance for each finding

## Usage

### Basic Passive Scan

```python
from src.oasis.scanner import ScanEngine, ScanPolicy
from src.oasis.core.models import HTTPFlow

# Create scan engine
engine = ScanEngine()

# Run passive scan on intercepted traffic
policy = ScanPolicy.passive_only_policy()
findings = await engine.passive_scan(flows, policy)

# Review findings
for finding in findings:
    print(f"{finding.severity.value}: {finding.title}")
```

### Full Scan Session

```python
from src.oasis.scanner import ScanEngine, ScanTarget, ScanPolicy, ScanIntensity

# Configure scan target
target = ScanTarget(
    base_url="https://example.com",
    scope_patterns=["https://example.com/.*"],
    excluded_patterns=["https://example.com/static/.*"]
)

# Configure scan policy
policy = ScanPolicy(
    name="Comprehensive Scan",
    enabled_checks=["sql_injection", "xss", "csrf", "ssrf", "xxe"],
    scan_intensity=ScanIntensity.THOROUGH
)

# Start scan
engine = ScanEngine()
session = await engine.start_scan(target, policy)

print(f"Found {session.statistics.total_findings} vulnerabilities")
```

### Finding Management

```python
from src.oasis.scanner import FindingManager, FindingFilter
from src.oasis.core.models import Severity

# Create finding manager
manager = FindingManager()
manager.add_findings(findings)

# Filter by severity
critical = manager.get_findings_by_severity(Severity.CRITICAL)

# Mark false positives
manager.mark_false_positive(finding_id, "Expected behavior")

# Get statistics
stats = manager.get_statistics()
print(f"Total: {stats['total_findings']}")
print(f"Critical: {stats['by_severity']['critical']}")
```

### Report Generation

```python
from src.oasis.scanner import ReportGenerator, ReportFormat

# Create report generator
generator = ReportGenerator(finding_manager)

# Generate report
report = generator.generate_report(
    session,
    format=ReportFormat.MARKDOWN,
    include_false_positives=False
)

# Save to file
with open("scan_report.md", "w") as f:
    f.write(report)
```

## Scan Policies

### Predefined Policies

- **Default Policy** - Standard vulnerability scanning
- **Passive Only** - Analysis without active probing
- **Aggressive** - Thorough scanning with all checks enabled

### Custom Policies

```python
from src.oasis.scanner import ScanPolicy, ScanIntensity, RateLimitConfig

policy = ScanPolicy(
    name="Custom Policy",
    enabled_checks=["sql_injection", "xss"],
    scan_intensity=ScanIntensity.NORMAL,
    rate_limiting=RateLimitConfig(
        requests_per_second=10.0,
        concurrent_requests=5
    ),
    test_query_params=True,
    test_post_params=True,
    test_headers=False,
    timeout_seconds=30
)
```

## Vulnerability Detection

### Passive Detection

Analyzes intercepted traffic without sending additional requests:
- Sensitive data exposure
- Missing security headers
- Information disclosure
- Insecure cookie configurations

### Active Detection

Sends test payloads to identify vulnerabilities:
- SQL injection with multiple techniques
- XSS in various contexts
- CSRF token validation
- SSRF through URL parameters
- XXE in XML processing

## Architecture

```
scanner/
├── __init__.py          # Module exports
├── engine.py            # Core scan engine
├── policy.py            # Scan policy configuration
├── detector.py          # Base detector class
├── passive.py           # Passive scanner
├── active.py            # Active scanner
├── reporting.py         # Finding management and reporting
└── detectors/           # Vulnerability-specific detectors
    ├── sql_injection.py
    ├── xss.py
    ├── csrf.py
    ├── ssrf.py
    └── xxe.py
```

## Testing

Property-based tests ensure correctness:

```bash
# Run scanner tests
pytest tests/scanner/test_scanner_properties.py -v

# Run with coverage
pytest tests/scanner/ --cov=src/oasis/scanner
```

## Examples

See `examples/scanner_demo.py` for complete usage examples:

```bash
python examples/scanner_demo.py
```

## Requirements Validation

This implementation validates:
- **Requirement 3.1**: OWASP Top 10 vulnerability detection
- **Requirement 3.2**: Passive and active scanning capabilities
- **Requirement 3.3**: Detailed vulnerability reports with PoC
- **Requirement 3.4**: Severity categorization and filtering
- **Requirement 3.5**: False positive management

## Future Enhancements

- Additional vulnerability detectors (IDOR, authentication issues)
- Machine learning for improved detection accuracy
- Integration with external vulnerability databases
- Automated exploit generation
- Collaborative scanning for distributed testing
