"""
Property-based tests for the collaborator module.

Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
Validates: Requirements 8.1, 8.3, 8.5, 8.6
"""

import pytest
import asyncio
from hypothesis import given, strategies as st, settings
from typing import Dict

from src.oasis.collaborator import (
    CollaboratorService,
    PayloadType,
    Protocol,
)


# Strategies for generating test data
base_domains = st.sampled_from([
    "oasis-collab.local",
    "test.example.com",
    "pentest.internal",
])

payload_types = st.sampled_from(list(PayloadType))

ip_addresses = st.from_regex(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    fullmatch=True
)

dns_query_types = st.sampled_from(['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS'])

http_methods = st.sampled_from(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])

email_addresses = st.from_regex(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    fullmatch=True
)


class TestCollaboratorPayloadCorrelation:
    """
    Property 13: Collaborator Payload Correlation
    
    For any out-of-band interaction received, it should be correctly correlated
    with its originating payload and include complete forensic data.
    """
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        payload_type=payload_types,
        source_ip=ip_addresses,
        query_type=dns_query_types
    )
    def test_dns_interaction_correlation(
        self,
        base_domain: str,
        payload_type: PayloadType,
        source_ip: str,
        query_type: str
    ):
        """
        Test that DNS interactions are correctly correlated with payloads.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.1, 8.3, 8.5, 8.6
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate payload
        payload = asyncio.run(service.generate_payload(payload_type))
        
        # Capture DNS interaction using the payload's domain
        interaction = asyncio.run(service.capture_dns_interaction(
            query_name=payload.full_domain,
            query_type=query_type,
            source_ip=source_ip
        ))
        
        # Interaction should be captured
        assert interaction is not None, "DNS interaction should be captured"
        
        # Interaction should be correlated with the payload
        assert interaction.payload_id == payload.id, (
            f"Interaction not correlated correctly: "
            f"expected {payload.id}, got {interaction.payload_id}"
        )
        
        # Interaction should have correct protocol
        assert interaction.protocol == Protocol.DNS
        
        # Forensic data should be complete
        assert interaction.source_ip == source_ip
        assert interaction.dns_query is not None
        assert interaction.dns_query.query_name == payload.full_domain
        assert interaction.dns_query.query_type == query_type
        assert interaction.timestamp is not None
        
        # Should be able to poll for the interaction
        interactions = asyncio.run(service.poll_interactions(payload.id))
        assert len(interactions) == 1
        assert interactions[0].id == interaction.id
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        payload_type=payload_types,
        source_ip=ip_addresses,
        method=http_methods,
        path=st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=50)
    )
    def test_http_interaction_correlation(
        self,
        base_domain: str,
        payload_type: PayloadType,
        source_ip: str,
        method: str,
        path: str
    ):
        """
        Test that HTTP interactions are correctly correlated with payloads.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.1, 8.3, 8.5, 8.6
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate payload
        payload = asyncio.run(service.generate_payload(payload_type))
        
        # Capture HTTP interaction
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html"
        }
        
        interaction = asyncio.run(service.capture_http_interaction(
            host=payload.full_domain,
            method=method,
            path=f"/{path}",
            headers=headers,
            source_ip=source_ip
        ))
        
        # Interaction should be captured
        assert interaction is not None, "HTTP interaction should be captured"
        
        # Interaction should be correlated with the payload
        assert interaction.payload_id == payload.id
        
        # Interaction should have correct protocol
        assert interaction.protocol in [Protocol.HTTP, Protocol.HTTPS]
        
        # Forensic data should be complete
        assert interaction.source_ip == source_ip
        assert interaction.http_request is not None
        assert interaction.http_request["method"] == method
        assert interaction.http_request["host"] == payload.full_domain
        assert interaction.user_agent == "Mozilla/5.0"
        assert interaction.headers == headers
        assert interaction.timestamp is not None
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        payload_type=payload_types,
        source_ip=ip_addresses,
        from_email=email_addresses,
        subject=st.text(min_size=0, max_size=100)
    )
    def test_smtp_interaction_correlation(
        self,
        base_domain: str,
        payload_type: PayloadType,
        source_ip: str,
        from_email: str,
        subject: str
    ):
        """
        Test that SMTP interactions are correctly correlated with payloads.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.1, 8.3, 8.5, 8.6
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate payload
        payload = asyncio.run(service.generate_payload(payload_type))
        
        # Create email address using payload domain
        to_email = f"test@{payload.full_domain}"
        
        # Capture SMTP interaction
        interaction = asyncio.run(service.capture_smtp_interaction(
            from_address=from_email,
            to_address=to_email,
            source_ip=source_ip,
            subject=subject,
            body="Test email body"
        ))
        
        # Interaction should be captured
        assert interaction is not None, "SMTP interaction should be captured"
        
        # Interaction should be correlated with the payload
        assert interaction.payload_id == payload.id
        
        # Interaction should have correct protocol
        assert interaction.protocol == Protocol.SMTP
        
        # Forensic data should be complete
        assert interaction.source_ip == source_ip
        assert interaction.smtp_message is not None
        assert interaction.smtp_message.from_address == from_email
        assert interaction.smtp_message.to_address == to_email
        assert interaction.smtp_message.subject == subject
        assert interaction.timestamp is not None
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        num_payloads=st.integers(min_value=1, max_value=10),
        source_ip=ip_addresses
    )
    def test_multiple_payload_correlation(
        self,
        base_domain: str,
        num_payloads: int,
        source_ip: str
    ):
        """
        Test that multiple payloads can be tracked independently.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.1, 8.3
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate multiple payloads
        payloads = []
        for _ in range(num_payloads):
            payload = asyncio.run(service.generate_payload(PayloadType.DNS_LOOKUP))
            payloads.append(payload)
        
        # All payloads should have unique subdomains
        subdomains = [p.subdomain for p in payloads]
        assert len(subdomains) == len(set(subdomains)), "Subdomains should be unique"
        
        # Capture interactions for each payload
        for payload in payloads:
            asyncio.run(service.capture_dns_interaction(
                query_name=payload.full_domain,
                query_type="A",
                source_ip=source_ip
            ))
        
        # Each payload should have exactly one interaction
        for payload in payloads:
            interactions = asyncio.run(service.poll_interactions(payload.id))
            assert len(interactions) == 1, (
                f"Payload {payload.id} should have exactly 1 interaction, "
                f"got {len(interactions)}"
            )
            assert interactions[0].payload_id == payload.id
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        source_ip=ip_addresses,
        num_interactions=st.integers(min_value=1, max_value=20)
    )
    def test_multiple_interactions_per_payload(
        self,
        base_domain: str,
        source_ip: str,
        num_interactions: int
    ):
        """
        Test that multiple interactions can be tracked for a single payload.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.3, 8.5
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate single payload
        payload = asyncio.run(service.generate_payload(PayloadType.DNS_LOOKUP))
        
        # Capture multiple interactions
        for i in range(num_interactions):
            asyncio.run(service.capture_dns_interaction(
                query_name=payload.full_domain,
                query_type="A",
                source_ip=source_ip
            ))
        
        # Should have all interactions
        interactions = asyncio.run(service.poll_interactions(payload.id))
        assert len(interactions) == num_interactions, (
            f"Expected {num_interactions} interactions, got {len(interactions)}"
        )
        
        # All interactions should be correlated with the same payload
        for interaction in interactions:
            assert interaction.payload_id == payload.id
            assert interaction.source_ip == source_ip
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        source_ip=ip_addresses
    )
    def test_uncorrelated_interaction_rejected(
        self,
        base_domain: str,
        source_ip: str
    ):
        """
        Test that interactions without matching payloads are not captured.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.1, 8.3
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Try to capture interaction without generating payload
        fake_domain = f"nonexistent.{base_domain}"
        
        interaction = asyncio.run(service.capture_dns_interaction(
            query_name=fake_domain,
            query_type="A",
            source_ip=source_ip
        ))
        
        # Interaction should not be captured
        assert interaction is None, (
            "Interaction without matching payload should not be captured"
        )
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        payload_type=payload_types
    )
    def test_payload_retrieval(
        self,
        base_domain: str,
        payload_type: PayloadType
    ):
        """
        Test that payloads can be retrieved by ID.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.1
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate payload
        payload = asyncio.run(service.generate_payload(payload_type))
        
        # Should be able to retrieve payload
        retrieved = service.get_payload(payload.id)
        assert retrieved is not None
        assert retrieved.id == payload.id
        assert retrieved.subdomain == payload.subdomain
        assert retrieved.full_domain == payload.full_domain
        assert retrieved.payload_type == payload_type
    
    @settings(max_examples=100)
    @given(
        base_domain=base_domains,
        source_ip=ip_addresses
    )
    def test_interaction_count_accuracy(
        self,
        base_domain: str,
        source_ip: str
    ):
        """
        Test that interaction counts are accurate.
        
        Feature: oasis-pentest-suite, Property 13: Collaborator Payload Correlation
        Validates: Requirements 8.5
        """
        # Create service
        service = CollaboratorService(base_domain=base_domain)
        
        # Generate payload
        payload = asyncio.run(service.generate_payload(PayloadType.DNS_LOOKUP))
        
        # Initially should have zero interactions
        assert service.get_interaction_count(payload.id) == 0
        
        # Capture some interactions
        for i in range(5):
            asyncio.run(service.capture_dns_interaction(
                query_name=payload.full_domain,
                query_type="A",
                source_ip=source_ip
            ))
        
        # Count should be accurate
        assert service.get_interaction_count(payload.id) == 5
