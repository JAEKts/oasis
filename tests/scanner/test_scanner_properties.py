"""
Property-based tests for the scanner module.

Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
Validates: Requirements 3.3, 3.4, 5.5, 7.3
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from datetime import datetime, UTC
import uuid

from src.oasis.core.models import (
    HTTPRequest, HTTPResponse, HTTPFlow, FlowMetadata,
    Finding, Severity, Confidence, VulnerabilityType, RequestSource
)
from src.oasis.scanner import (
    ScanEngine, ScanPolicy, ScanTarget, FindingManager, FindingFilter, ReportFormat, ReportGenerator
)
from src.oasis.scanner.passive import PassiveScanner
from src.oasis.scanner.detector import ScanContext


# Strategies for generating test data
http_methods = st.sampled_from(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
status_codes = st.integers(min_value=200, max_value=599)
severities = st.sampled_from(list(Severity))
confidences = st.sampled_from(list(Confidence))
vulnerability_types = st.sampled_from(list(VulnerabilityType))

# Generate valid URLs
def url_strategy():
    """Generate valid HTTP URLs."""
    domains = st.sampled_from(['example.com', 'test.org', 'api.example.com'])
    paths = st.lists(st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=10), min_size=0, max_size=3)
    
    @st.composite
    def _url(draw):
        domain = draw(domains)
        path_parts = draw(paths)
        path = '/' + '/'.join(path_parts) if path_parts else '/'
        return f"https://{domain}{path}"
    
    return _url()


# Generate HTTP headers
def headers_strategy():
    """Generate HTTP headers."""
    return st.dictionaries(
        keys=st.sampled_from(['Content-Type', 'User-Agent', 'Accept', 'Authorization']),
        values=st.text(min_size=1, max_size=50),
        min_size=0,
        max_size=5
    )


# Generate HTTP requests
@st.composite
def http_request_strategy(draw):
    """Generate valid HTTP requests."""
    return HTTPRequest(
        method=draw(http_methods),
        url=draw(url_strategy()),
        headers=draw(headers_strategy()),
        body=None,
        timestamp=datetime.now(UTC),
        source=RequestSource.SCANNER
    )


# Generate HTTP responses
@st.composite
def http_response_strategy(draw):
    """Generate valid HTTP responses."""
    return HTTPResponse(
        status_code=draw(status_codes),
        headers=draw(headers_strategy()),
        body=None,
        timestamp=datetime.now(UTC),
        duration_ms=draw(st.integers(min_value=10, max_value=5000))
    )


# Generate HTTP flows
@st.composite
def http_flow_strategy(draw):
    """Generate valid HTTP flows."""
    return HTTPFlow(
        request=draw(http_request_strategy()),
        response=draw(http_response_strategy()),
        metadata=FlowMetadata()
    )


# Generate findings
@st.composite
def finding_strategy(draw):
    """Generate valid findings."""
    from src.oasis.core.models import Evidence
    
    return Finding(
        vulnerability_type=draw(vulnerability_types),
        severity=draw(severities),
        confidence=draw(confidences),
        title=draw(st.text(min_size=10, max_size=100)),
        description=draw(st.text(min_size=20, max_size=200)),
        evidence=Evidence(),
        remediation=draw(st.text(min_size=20, max_size=200)),
        references=[]
    )


class TestVulnerabilityDetectionCompleteness:
    """
    Property 8: Vulnerability Detection Completeness
    
    For any scan session, findings should be categorized with appropriate
    severity levels and include complete evidence and remediation information.
    """
    
    @settings(max_examples=100)
    @given(finding=finding_strategy())
    def test_finding_has_required_fields(self, finding: Finding):
        """
        Test that all findings have required fields populated.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.3, 3.4
        """
        # Every finding must have a valid severity
        assert finding.severity in Severity, f"Invalid severity: {finding.severity}"
        
        # Every finding must have a valid confidence level
        assert finding.confidence in Confidence, f"Invalid confidence: {finding.confidence}"
        
        # Every finding must have a valid vulnerability type
        assert finding.vulnerability_type in VulnerabilityType, (
            f"Invalid vulnerability type: {finding.vulnerability_type}"
        )
        
        # Every finding must have a non-empty title
        assert finding.title and len(finding.title.strip()) > 0, "Finding must have a title"
        
        # Every finding must have a non-empty description
        assert finding.description and len(finding.description.strip()) > 0, (
            "Finding must have a description"
        )
        
        # Every finding must have remediation guidance
        assert finding.remediation and len(finding.remediation.strip()) > 0, (
            "Finding must have remediation guidance"
        )
        
        # Every finding must have evidence
        assert finding.evidence is not None, "Finding must have evidence"
        
        # Every finding must have a unique ID
        assert finding.id is not None, "Finding must have an ID"
        assert isinstance(finding.id, uuid.UUID), "Finding ID must be a UUID"
    
    @settings(max_examples=100)
    @given(findings=st.lists(finding_strategy(), min_size=1, max_size=20))
    def test_finding_manager_categorization(self, findings: list):
        """
        Test that FindingManager correctly categorizes findings by severity.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.4
        """
        manager = FindingManager()
        
        # Add all findings
        manager.add_findings(findings)
        
        # Count expected findings by severity
        expected_counts = {}
        for finding in findings:
            severity = finding.severity
            expected_counts[severity] = expected_counts.get(severity, 0) + 1
        
        # Verify categorization
        for severity in Severity:
            severity_findings = manager.get_findings_by_severity(severity)
            expected_count = expected_counts.get(severity, 0)
            
            assert len(severity_findings) == expected_count, (
                f"Expected {expected_count} {severity.value} findings, "
                f"got {len(severity_findings)}"
            )
            
            # Verify all returned findings have the correct severity
            for finding in severity_findings:
                assert finding.severity == severity, (
                    f"Finding with severity {finding.severity.value} "
                    f"returned in {severity.value} category"
                )
    
    @settings(max_examples=100)
    @given(findings=st.lists(finding_strategy(), min_size=1, max_size=20))
    def test_finding_manager_type_filtering(self, findings: list):
        """
        Test that FindingManager correctly filters findings by vulnerability type.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.4
        """
        manager = FindingManager()
        manager.add_findings(findings)
        
        # Count expected findings by type
        expected_counts = {}
        for finding in findings:
            vuln_type = finding.vulnerability_type
            expected_counts[vuln_type] = expected_counts.get(vuln_type, 0) + 1
        
        # Verify filtering by type
        for vuln_type in VulnerabilityType:
            type_findings = manager.get_findings_by_type(vuln_type)
            expected_count = expected_counts.get(vuln_type, 0)
            
            assert len(type_findings) == expected_count, (
                f"Expected {expected_count} {vuln_type.value} findings, "
                f"got {len(type_findings)}"
            )
            
            # Verify all returned findings have the correct type
            for finding in type_findings:
                assert finding.vulnerability_type == vuln_type, (
                    f"Finding with type {finding.vulnerability_type.value} "
                    f"returned in {vuln_type.value} filter"
                )
    
    @settings(max_examples=100)
    @given(
        findings=st.lists(finding_strategy(), min_size=5, max_size=20),
        false_positive_indices=st.lists(st.integers(min_value=0, max_value=19), min_size=0, max_size=5)
    )
    def test_false_positive_management(self, findings: list, false_positive_indices: list):
        """
        Test that false positive management works correctly.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.5
        """
        # Ensure indices are valid
        false_positive_indices = [i for i in false_positive_indices if i < len(findings)]
        
        manager = FindingManager()
        manager.add_findings(findings)
        
        # Mark some findings as false positives
        fp_ids = set()
        for idx in false_positive_indices:
            finding_id = findings[idx].id
            fp_ids.add(finding_id)
            success = manager.mark_false_positive(finding_id, "Test false positive")
            assert success, f"Failed to mark finding {finding_id} as false positive"
        
        # Verify false positive status
        for finding in findings:
            is_fp = manager.is_false_positive(finding.id)
            should_be_fp = finding.id in fp_ids
            
            assert is_fp == should_be_fp, (
                f"Finding {finding.id} false positive status mismatch: "
                f"expected {should_be_fp}, got {is_fp}"
            )
        
        # Verify filtering excludes false positives by default
        all_findings = manager.get_all_findings(include_false_positives=False)
        assert len(all_findings) == len(findings) - len(fp_ids), (
            f"Expected {len(findings) - len(fp_ids)} findings (excluding FPs), "
            f"got {len(all_findings)}"
        )
        
        # Verify including false positives returns all
        all_with_fp = manager.get_all_findings(include_false_positives=True)
        assert len(all_with_fp) == len(findings), (
            f"Expected {len(findings)} findings (including FPs), "
            f"got {len(all_with_fp)}"
        )
    
    @settings(max_examples=100)
    @given(findings=st.lists(finding_strategy(), min_size=1, max_size=20))
    def test_statistics_accuracy(self, findings: list):
        """
        Test that statistics are calculated accurately.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.4
        """
        manager = FindingManager()
        manager.add_findings(findings)
        
        stats = manager.get_statistics()
        
        # Verify total count
        assert stats['total_findings'] == len(findings), (
            f"Expected {len(findings)} total findings, got {stats['total_findings']}"
        )
        
        # Verify severity counts
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
        
        for severity in Severity:
            expected = severity_counts.get(severity.value, 0)
            actual = stats['by_severity'][severity.value]
            assert actual == expected, (
                f"Severity count mismatch for {severity.value}: "
                f"expected {expected}, got {actual}"
            )
        
        # Verify confidence counts
        confidence_counts = {}
        for finding in findings:
            confidence_counts[finding.confidence.value] = confidence_counts.get(finding.confidence.value, 0) + 1
        
        for confidence in Confidence:
            expected = confidence_counts.get(confidence.value, 0)
            actual = stats['by_confidence'][confidence.value]
            assert actual == expected, (
                f"Confidence count mismatch for {confidence.value}: "
                f"expected {expected}, got {actual}"
            )
    
    @settings(max_examples=100)
    @given(
        findings=st.lists(finding_strategy(), min_size=1, max_size=10),
        filter_severity=st.one_of(st.none(), severities)
    )
    def test_finding_filter_consistency(self, findings: list, filter_severity):
        """
        Test that finding filters are applied consistently.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.4, 3.5
        """
        manager = FindingManager()
        manager.add_findings(findings)
        
        # Create filter
        if filter_severity:
            filter_criteria = FindingFilter(severities=[filter_severity])
        else:
            filter_criteria = FindingFilter()
        
        # Apply filter
        filtered = manager.filter_findings(filter_criteria)
        
        # Verify all filtered findings match criteria
        for finding in filtered:
            if filter_severity:
                assert finding.severity == filter_severity, (
                    f"Filtered finding has wrong severity: "
                    f"expected {filter_severity.value}, got {finding.severity.value}"
                )
        
        # Verify no matching findings were excluded
        if filter_severity:
            expected_count = sum(1 for f in findings if f.severity == filter_severity)
            assert len(filtered) == expected_count, (
                f"Filter excluded valid findings: "
                f"expected {expected_count}, got {len(filtered)}"
            )
    
    @settings(max_examples=50)
    @given(flow=http_flow_strategy())
    def test_passive_scanner_completeness(self, flow: HTTPFlow):
        """
        Test that passive scanner returns complete findings.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.3, 3.4
        """
        import asyncio
        
        scanner = PassiveScanner()
        policy = ScanPolicy.passive_only_policy()
        context = ScanContext(flow=flow, policy=policy)
        
        # Run passive scan
        findings = asyncio.run(scanner.analyze_flow(context))
        
        # Verify all findings are complete
        for finding in findings:
            # Must have valid severity
            assert finding.severity in Severity
            
            # Must have valid confidence
            assert finding.confidence in Confidence
            
            # Must have valid type
            assert finding.vulnerability_type in VulnerabilityType
            
            # Must have non-empty title and description
            assert finding.title and len(finding.title.strip()) > 0
            assert finding.description and len(finding.description.strip()) > 0
            
            # Must have remediation
            assert finding.remediation and len(finding.remediation.strip()) > 0
            
            # Must have evidence
            assert finding.evidence is not None


class TestReportGeneration:
    """Tests for report generation completeness."""
    
    @settings(max_examples=50)
    @given(findings=st.lists(finding_strategy(), min_size=1, max_size=10))
    def test_report_contains_all_findings(self, findings: list):
        """
        Test that generated reports contain all findings.
        
        Feature: oasis-pentest-suite, Property 8: Vulnerability Detection Completeness
        Validates: Requirements 3.3, 3.4
        """
        from src.oasis.scanner.engine import ScanSession, ScanStatistics
        
        manager = FindingManager()
        manager.add_findings(findings)
        
        # Create a mock scan session
        session = ScanSession(
            target=ScanTarget(base_url="https://example.com"),
            policy=ScanPolicy.default_policy(),
            findings=findings,
            statistics=ScanStatistics()
        )
        
        generator = ReportGenerator(manager)
        
        # Generate JSON report
        json_report = generator.generate_report(session, ReportFormat.JSON)
        
        # Verify report is not empty
        assert json_report and len(json_report) > 0, "Report should not be empty"
        
        # Verify report contains findings
        import json
        report_data = json.loads(json_report)
        
        assert 'findings' in report_data, "Report must contain findings"
        assert len(report_data['findings']) == len(findings), (
            f"Report should contain {len(findings)} findings, "
            f"got {len(report_data['findings'])}"
        )
        
        # Verify statistics are included
        assert 'statistics' in report_data, "Report must contain statistics"
