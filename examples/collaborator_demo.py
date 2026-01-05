"""
OASIS Collaborator Service Demo

Demonstrates out-of-band interaction detection and forensic analysis.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.oasis.collaborator import (
    CollaboratorService,
    PayloadType,
    Interaction,
)


async def notification_callback(interaction: Interaction):
    """Callback for real-time notifications."""
    print(f"\n🔔 Real-time notification: Interaction captured!")
    print(f"   Protocol: {interaction.protocol.value}")
    print(f"   Source IP: {interaction.source_ip}")
    print(f"   Timestamp: {interaction.timestamp}")


async def main():
    print("=" * 70)
    print("OASIS Collaborator Service Demo")
    print("=" * 70)
    
    # Initialize the service
    print("\n1. Initializing Collaborator Service...")
    service = CollaboratorService(
        base_domain="oasis-collab.local",
        self_hosted=True,
        enable_notifications=True,
        log_file="collaborator_interactions.log"
    )
    
    # Register notification callback
    service.register_async_notification_callback(notification_callback)
    print("   ✓ Service initialized with notifications enabled")
    
    # Generate DNS payload
    print("\n2. Generating DNS Payload...")
    dns_payload = await service.generate_payload(
        PayloadType.DNS_LOOKUP,
        metadata={"test_id": "dns-001", "vulnerability": "XXE"}
    )
    print(f"   ✓ DNS Payload: {dns_payload.get_dns_payload()}")
    print(f"   ✓ Subdomain: {dns_payload.subdomain}")
    
    # Generate HTTP payload
    print("\n3. Generating HTTP Payload...")
    http_payload = await service.generate_payload(
        PayloadType.HTTP_REQUEST,
        metadata={"test_id": "http-001", "vulnerability": "SSRF"}
    )
    print(f"   ✓ HTTP Payload: {http_payload.get_http_payload(protocol='https')}")
    
    # Simulate DNS interaction
    print("\n4. Simulating DNS Interaction...")
    dns_interaction = await service.capture_dns_interaction(
        query_name=dns_payload.full_domain,
        query_type="A",
        source_ip="192.168.1.100",
        raw_data="DNS query data"
    )
    print(f"   ✓ DNS interaction captured: {dns_interaction.id}")
    
    # Simulate HTTP interaction
    print("\n5. Simulating HTTP Interaction...")
    http_interaction = await service.capture_http_interaction(
        host=http_payload.full_domain,
        method="GET",
        path="/admin/config",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html",
            "Referer": "http://internal-server.local"
        },
        source_ip="10.0.0.50",
        body=None
    )
    print(f"   ✓ HTTP interaction captured: {http_interaction.id}")
    
    # Simulate SMTP interaction
    print("\n6. Simulating SMTP Interaction...")
    smtp_payload = await service.generate_payload(PayloadType.SMTP_CONNECTION)
    smtp_interaction = await service.capture_smtp_interaction(
        from_address="attacker@example.com",
        to_address=f"test@{smtp_payload.full_domain}",
        source_ip="172.16.0.10",
        subject="Test Email",
        body="This is a test email body"
    )
    print(f"   ✓ SMTP interaction captured: {smtp_interaction.id}")
    
    # Poll for interactions
    print("\n7. Polling for Interactions...")
    dns_interactions = await service.poll_interactions(dns_payload.id)
    print(f"   ✓ DNS payload has {len(dns_interactions)} interaction(s)")
    
    http_interactions = await service.poll_interactions(http_payload.id)
    print(f"   ✓ HTTP payload has {len(http_interactions)} interaction(s)")
    
    # Perform forensic analysis
    print("\n8. Performing Forensic Analysis...")
    if http_interaction:
        analysis = service.analyze_interaction(http_interaction)
        print(f"   ✓ HTTP Interaction Analysis:")
        print(f"      - Protocol: {analysis['protocol']}")
        print(f"      - Source IP: {analysis['source_ip']}")
        forensic = analysis.get('forensic_details', {})
        if forensic:
            print(f"      - Method: {forensic.get('method')}")
            print(f"      - Path: {forensic.get('path')}")
            ua_analysis = forensic.get('user_agent_analysis', {})
            if ua_analysis:
                print(f"      - Is Browser: {ua_analysis.get('is_browser')}")
                print(f"      - Is Bot: {ua_analysis.get('is_bot')}")
    
    # Generate forensic report
    print("\n9. Generating Forensic Report...")
    report = service.generate_forensic_report(http_payload.id)
    print(f"   ✓ Forensic Report Generated:")
    print(f"      - Payload ID: {report['payload_id']}")
    print(f"      - Payload Type: {report['payload_type']}")
    print(f"      - Interaction Count: {report['interaction_count']}")
    
    if 'detected_patterns' in report:
        patterns = report['detected_patterns']
        if patterns:
            print(f"      - Detected Patterns: {len(patterns)}")
            for pattern in patterns:
                print(f"         • {pattern['type']}: {pattern['description']}")
        else:
            print(f"      - No suspicious patterns detected")
    
    # Detect patterns across multiple interactions
    print("\n10. Pattern Detection...")
    # Simulate rapid interactions for pattern detection
    for i in range(3):
        await service.capture_dns_interaction(
            query_name=dns_payload.full_domain,
            query_type="A",
            source_ip="192.168.1.100"
        )
        await asyncio.sleep(0.1)  # Small delay
    
    patterns = service.detect_interaction_patterns(dns_payload.id)
    print(f"   ✓ Detected {len(patterns)} pattern(s)")
    for pattern in patterns:
        print(f"      - {pattern['type']}: {pattern['description']}")
        print(f"        Possible vulnerability: {pattern['possible_vulnerability']}")
    
    # Show interaction logs
    print("\n11. Interaction Logs...")
    logs = service.get_interaction_logs()
    print(f"   ✓ Total logged interactions: {len(logs)}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Demo Summary")
    print("=" * 70)
    all_payloads = service.get_all_payloads()
    print(f"Total Payloads Generated: {len(all_payloads)}")
    
    total_interactions = 0
    for payload in all_payloads:
        count = service.get_interaction_count(payload.id)
        total_interactions += count
        print(f"  - {payload.payload_type.value}: {count} interaction(s)")
    
    print(f"\nTotal Interactions Captured: {total_interactions}")
    print("\n✓ Demo completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
