"""
Property-based tests for OASIS core data models.

Feature: oasis-pentest-suite, Property 16: Export Format Integrity
Validates: Requirements 10.2
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from src.oasis.core.models import (
    HTTPRequest, HTTPResponse, Project, Finding, Evidence, HTTPFlow,
    User, ProjectSettings, FlowMetadata,
    Severity, Confidence, VulnerabilityType, RequestSource,
    serialize_model, deserialize_model
)


# Hypothesis strategies for generating test data
@st.composite
def http_request_strategy(draw):
    """Generate valid HTTPRequest instances."""
    method = draw(st.sampled_from(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']))
    
    # Generate simpler, more reliable URLs
    path = draw(st.text(min_size=1, max_size=50, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/'))
    url = f"https://example.com/{path.replace(' ', '_')}"
    
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'),
        st.text(min_size=1, max_size=100),
        max_size=5
    ))
    
    body = draw(st.one_of(st.none(), st.binary(max_size=1000)))
    source = draw(st.sampled_from(list(RequestSource)))
    
    return HTTPRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        source=source
    )


@st.composite
def http_response_strategy(draw):
    """Generate valid HTTPResponse instances."""
    status_code = draw(st.integers(min_value=100, max_value=599))
    headers = draw(st.dictionaries(
        st.text(min_size=1, max_size=50, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'),
        st.text(min_size=1, max_size=100),
        max_size=10
    ))
    body = draw(st.one_of(st.none(), st.binary(max_size=1000)))
    duration_ms = draw(st.integers(min_value=0, max_value=60000))
    
    return HTTPResponse(
        status_code=status_code,
        headers=headers,
        body=body,
        duration_ms=duration_ms
    )


@st.composite
def user_strategy(draw):
    """Generate valid User instances."""
    # Use only ASCII letters and numbers for username
    username = draw(st.text(min_size=1, max_size=50, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'))
    
    # Generate valid email with ASCII-only characters
    local_part = draw(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-'))
    domain = draw(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'))
    tld = draw(st.sampled_from(['com', 'org', 'net', 'edu', 'gov']))  # Use common TLDs
    email = f"{local_part}@{domain}.{tld}"
    
    return User(username=username, email=email)


@st.composite
def project_strategy(draw):
    """Generate valid Project instances."""
    name = draw(st.text(min_size=1, max_size=100).filter(lambda x: x.strip()))
    description = draw(st.text(max_size=500))
    
    # Generate project settings
    target_scope = draw(st.lists(st.text(min_size=1, max_size=100), max_size=5))
    excluded_scope = draw(st.lists(st.text(min_size=1, max_size=100), max_size=5))
    
    settings = ProjectSettings(
        target_scope=target_scope,
        excluded_scope=excluded_scope
    )
    
    collaborators = draw(st.lists(user_strategy(), max_size=3))
    
    return Project(
        name=name,
        description=description,
        settings=settings,
        collaborators=collaborators
    )


@st.composite
def evidence_strategy(draw):
    """Generate valid Evidence instances."""
    request = draw(st.one_of(st.none(), http_request_strategy()))
    response = draw(st.one_of(st.none(), http_response_strategy()))
    payload = draw(st.one_of(st.none(), st.text(max_size=200)))
    location = draw(st.one_of(st.none(), st.text(max_size=100)))
    proof_of_concept = draw(st.one_of(st.none(), st.text(max_size=500)))
    
    return Evidence(
        request=request,
        response=response,
        payload=payload,
        location=location,
        proof_of_concept=proof_of_concept
    )


@st.composite
def finding_strategy(draw):
    """Generate valid Finding instances."""
    vulnerability_type = draw(st.sampled_from(list(VulnerabilityType)))
    severity = draw(st.sampled_from(list(Severity)))
    confidence = draw(st.sampled_from(list(Confidence)))
    title = draw(st.text(min_size=1, max_size=200))
    description = draw(st.text(min_size=1, max_size=1000))
    evidence = draw(evidence_strategy())
    remediation = draw(st.text(min_size=1, max_size=500))
    references = draw(st.lists(st.text(min_size=1, max_size=200), max_size=5))
    
    return Finding(
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        references=references
    )


class TestDataModelSerialization:
    """Property-based tests for data model serialization integrity."""
    
    @given(http_request_strategy())
    @settings(suppress_health_check=[HealthCheck.filter_too_much], max_examples=50)
    def test_http_request_serialization_round_trip(self, request: HTTPRequest):
        """
        Property 16: Export Format Integrity
        For any HTTPRequest, serializing then deserializing should produce an equivalent object.
        **Validates: Requirements 10.2**
        """
        # Serialize to dict
        serialized = serialize_model(request)
        
        # Verify serialized data is JSON-serializable
        json_str = json.dumps(serialized, default=str)
        assert isinstance(json_str, str)
        
        # Deserialize back to object
        deserialized = deserialize_model(HTTPRequest, serialized)
        
        # Verify equivalence (excluding timestamp precision differences)
        assert deserialized.method == request.method
        assert deserialized.url == request.url
        assert deserialized.headers == request.headers
        assert deserialized.body == request.body
        assert deserialized.source == request.source
    
    @given(http_response_strategy())
    def test_http_response_serialization_round_trip(self, response: HTTPResponse):
        """
        Property 16: Export Format Integrity
        For any HTTPResponse, serializing then deserializing should produce an equivalent object.
        **Validates: Requirements 10.2**
        """
        # Serialize to dict
        serialized = serialize_model(response)
        
        # Verify serialized data is JSON-serializable
        json_str = json.dumps(serialized, default=str)
        assert isinstance(json_str, str)
        
        # Deserialize back to object
        deserialized = deserialize_model(HTTPResponse, serialized)
        
        # Verify equivalence
        assert deserialized.status_code == response.status_code
        assert deserialized.headers == response.headers
        assert deserialized.body == response.body
        assert deserialized.duration_ms == response.duration_ms
    
    @given(project_strategy())
    @settings(max_examples=50)
    def test_project_serialization_round_trip(self, project: Project):
        """
        Property 16: Export Format Integrity
        For any Project, serializing then deserializing should produce an equivalent object.
        **Validates: Requirements 10.2**
        """
        # Serialize to dict
        serialized = serialize_model(project)
        
        # Verify serialized data is JSON-serializable
        json_str = json.dumps(serialized, default=str)
        assert isinstance(json_str, str)
        
        # Deserialize back to object
        deserialized = deserialize_model(Project, serialized)
        
        # Verify equivalence
        assert deserialized.name == project.name
        assert deserialized.description == project.description
        assert deserialized.settings.target_scope == project.settings.target_scope
        assert deserialized.settings.excluded_scope == project.settings.excluded_scope
        assert len(deserialized.collaborators) == len(project.collaborators)
    
    @given(finding_strategy())
    @settings(max_examples=50)
    def test_finding_serialization_round_trip(self, finding: Finding):
        """
        Property 16: Export Format Integrity
        For any Finding, serializing then deserializing should produce an equivalent object.
        **Validates: Requirements 10.2**
        """
        # Serialize to dict
        serialized = serialize_model(finding)
        
        # Verify serialized data is JSON-serializable
        json_str = json.dumps(serialized, default=str)
        assert isinstance(json_str, str)
        
        # Deserialize back to object
        deserialized = deserialize_model(Finding, serialized)
        
        # Verify equivalence
        assert deserialized.vulnerability_type == finding.vulnerability_type
        assert deserialized.severity == finding.severity
        assert deserialized.confidence == finding.confidence
        assert deserialized.title == finding.title
        assert deserialized.description == finding.description
        assert deserialized.remediation == finding.remediation
        assert deserialized.references == finding.references
    
    @given(st.lists(st.one_of(
        http_request_strategy(),
        http_response_strategy(), 
        project_strategy(),
        finding_strategy()
    ), min_size=1, max_size=10))
    @settings(max_examples=30)
    def test_batch_serialization_integrity(self, models):
        """
        Property 16: Export Format Integrity
        For any collection of models, batch serialization should maintain individual integrity.
        **Validates: Requirements 10.2**
        """
        # Serialize all models
        serialized_batch = [serialize_model(model) for model in models]
        
        # Verify batch is JSON-serializable
        json_str = json.dumps(serialized_batch, default=str)
        assert isinstance(json_str, str)
        
        # Verify each serialized model contains required fields
        for i, serialized in enumerate(serialized_batch):
            original = models[i]
            
            # All models should have these basic fields
            if hasattr(original, 'id'):
                assert 'id' in serialized
            if hasattr(original, 'created_at'):
                assert 'created_at' in serialized
            
            # Verify no data loss in serialization
            assert len(serialized) > 0
            assert all(value is not None or key.endswith('_at') or key in ['body', 'response', 'request', 'last_login'] 
                      for key, value in serialized.items())