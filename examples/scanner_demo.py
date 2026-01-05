"""
OASIS Scanner Demo

Demonstrates the vulnerability scanner functionality.
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, UTC

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.oasis.core.models import HTTPRequest, HTTPResponse, HTTPFlow, FlowMetadata, RequestSource
from src.oasis.scanner import (
    ScanEngine, ScanPolicy, ScanTarget, ScanIntensity,
    FindingManager, ReportGenerator, ReportFormat, FindingFilter
)
from src.oasis.core.models import Severity


async def demo_passive_scan():
    """Demonstrate passive scanning of HTTP traffic."""
    print("=" * 60)
    print("PASSIVE SCANNING DEMO")
    print("=" * 60)
    
    # Create a sample HTTP flow with potential vulnerabilities
    request = HTTPRequest(
        method="GET",
        url="https://example.com/api/user?id=123",
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json"
        },
        timestamp=datetime.now(UTC),
        source=RequestSource.PROXY
    )
    
    response = HTTPResponse(
        status_code=200,
        headers={
            "Content-Type": "application/json",
            # Missing security headers
        },
        body=b'{"user": "admin", "api_key": "sk_live_1234567890abcdef"}',
        timestamp=datetime.now(UTC),
        duration_ms=150
    )
    
    flow = HTTPFlow(
        request=request,
        response=response,
        metadata=FlowMetadata()
    )
    
    # Create scan engine and run passive scan
    engine = ScanEngine()
    policy = ScanPolicy.passive_only_policy()
    
    findings = await engine.passive_scan([flow], policy)
    
    print(f"\nFound {len(findings)} potential vulnerabilities:\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"{i}. {finding.title}")
        print(f"   Severity: {finding.severity.value.upper()}")
        print(f"   Type: {finding.vulnerability_type.value}")
        print(f"   Description: {finding.description[:100]}...")
        print()


async def demo_scan_session():
    """Demonstrate a full scan session."""
    print("=" * 60)
    print("SCAN SESSION DEMO")
    print("=" * 60)
    
    # Create scan target
    target = ScanTarget(
        base_url="https://example.com",
        scope_patterns=["https://example.com/.*"],
        excluded_patterns=["https://example.com/static/.*"]
    )
    
    # Create scan policy
    policy = ScanPolicy(
        name="Demo Scan",
        description="Demonstration scan with all checks enabled",
        enabled_checks=["sql_injection", "xss", "csrf", "ssrf", "xxe"],
        scan_intensity=ScanIntensity.NORMAL
    )
    
    # Start scan
    engine = ScanEngine()
    
    print(f"\nStarting scan of {target.base_url}...")
    print(f"Policy: {policy.name}")
    print(f"Intensity: {policy.scan_intensity.value}")
    
    session = await engine.start_scan(target, policy)
    
    print(f"\nScan completed!")
    print(f"Status: {session.status.value}")
    print(f"Duration: {session.statistics.duration_seconds:.2f} seconds")
    print(f"Total findings: {session.statistics.total_findings}")


def demo_finding_management():
    """Demonstrate finding management and filtering."""
    print("=" * 60)
    print("FINDING MANAGEMENT DEMO")
    print("=" * 60)
    
    from src.oasis.core.models import Finding, Evidence, VulnerabilityType, Confidence
    
    # Create finding manager
    manager = FindingManager()
    
    # Add some sample findings
    findings = [
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.FIRM,
            title="SQL Injection in login form",
            description="The login form is vulnerable to SQL injection attacks.",
            evidence=Evidence(),
            remediation="Use parameterized queries.",
            references=[]
        ),
        Finding(
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            severity=Severity.HIGH,
            confidence=Confidence.CERTAIN,
            title="Reflected XSS in search parameter",
            description="User input is reflected without encoding.",
            evidence=Evidence(),
            remediation="Encode all user input before output.",
            references=[]
        ),
        Finding(
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            severity=Severity.LOW,
            confidence=Confidence.CERTAIN,
            title="Missing X-Frame-Options header",
            description="The response lacks clickjacking protection.",
            evidence=Evidence(),
            remediation="Add X-Frame-Options header.",
            references=[]
        ),
    ]
    
    manager.add_findings(findings)
    
    print(f"\nTotal findings: {len(manager.get_all_findings())}")
    
    # Get statistics
    stats = manager.get_statistics()
    print(f"\nFindings by severity:")
    for severity, count in stats['by_severity'].items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    
    # Filter by severity
    print(f"\nCritical findings:")
    critical = manager.get_findings_by_severity(Severity.CRITICAL)
    for finding in critical:
        print(f"  - {finding.title}")
    
    # Mark false positive
    if findings:
        fp_id = findings[2].id
        manager.mark_false_positive(fp_id, "This is expected behavior")
        print(f"\nMarked 1 finding as false positive")
        print(f"Valid findings: {len(manager.get_all_findings(include_false_positives=False))}")


def demo_report_generation():
    """Demonstrate report generation."""
    print("=" * 60)
    print("REPORT GENERATION DEMO")
    print("=" * 60)
    
    from src.oasis.core.models import Finding, Evidence, VulnerabilityType, Confidence
    from src.oasis.scanner.engine import ScanSession, ScanStatistics
    
    # Create finding manager with sample findings
    manager = FindingManager()
    
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.FIRM,
        title="SQL Injection vulnerability",
        description="Critical SQL injection found in user input.",
        evidence=Evidence(),
        remediation="Use parameterized queries to prevent SQL injection.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
    )
    
    manager.add_finding(finding)
    
    # Create mock session
    session = ScanSession(
        target=ScanTarget(base_url="https://example.com"),
        policy=ScanPolicy.default_policy(),
        findings=[finding],
        statistics=ScanStatistics(total_findings=1)
    )
    
    # Generate reports
    generator = ReportGenerator(manager)
    
    print("\nGenerating Markdown report...")
    markdown_report = generator.generate_report(session, ReportFormat.MARKDOWN)
    print(markdown_report[:500] + "...\n")
    
    print("Report generation complete!")
    print(f"Available formats: {', '.join([f.value for f in ReportFormat])}")


async def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("OASIS VULNERABILITY SCANNER DEMO")
    print("=" * 60 + "\n")
    
    # Run demos
    await demo_passive_scan()
    print()
    
    await demo_scan_session()
    print()
    
    demo_finding_management()
    print()
    
    demo_report_generation()
    print()
    
    print("=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
