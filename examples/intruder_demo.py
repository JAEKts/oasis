"""
OASIS Intruder Demo

Demonstrates the attack engine capabilities with various attack types.
"""

import asyncio
from oasis.intruder import (
    AttackEngine,
    AttackConfig,
    AttackType,
    InjectionPoint,
    PayloadSet,
    PayloadProcessor,
    ProcessorType,
)
from oasis.intruder.payloads import BuiltinWordlists
from oasis.core.models import HTTPRequest, RequestSource


async def demo_sniper_attack():
    """Demonstrate SNIPER attack type."""
    print("\n=== SNIPER ATTACK DEMO ===")
    print("Testing multiple injection points with the same payload set")
    
    # Create base request with multiple injection points
    base_request = HTTPRequest(
        method="GET",
        url="https://example.com/search?q=§query§&category=§category§",
        headers={"User-Agent": "OASIS-Intruder"},
        source=RequestSource.INTRUDER
    )
    
    # Define injection points
    injection_points = [
        InjectionPoint(
            name="Search Query",
            location="param",
            key="q",
            marker="§query§"
        ),
        InjectionPoint(
            name="Category",
            location="param",
            key="category",
            marker="§category§"
        )
    ]
    
    # Create payload set with XSS payloads
    payload_set = PayloadSet(
        name="XSS Payloads",
        generator_type="wordlist",
        generator_config={"builtin": "xss"}
    )
    
    # Create attack configuration
    attack_config = AttackConfig(
        name="XSS Sniper Attack",
        attack_type=AttackType.SNIPER,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Execute attack
    engine = AttackEngine()
    results = await engine.execute_attack(attack_config)
    
    # Display results
    print(f"Total requests: {results.statistics.total_requests}")
    print(f"Successful: {results.statistics.successful_requests}")
    print(f"Duration: {results.statistics.duration_seconds:.2f}s")
    print(f"First 3 results:")
    for i, result in enumerate(results.results[:3]):
        print(f"  {i+1}. Payloads: {result.payloads}")


async def demo_battering_ram_attack():
    """Demonstrate BATTERING_RAM attack type."""
    print("\n=== BATTERING RAM ATTACK DEMO ===")
    print("Testing all injection points with the same payload simultaneously")
    
    # Create base request
    base_request = HTTPRequest(
        method="POST",
        url="https://example.com/api/auth",
        headers={"Content-Type": "application/json"},
        body='{"username": "§value§", "password": "§value§", "token": "§value§"}'.encode('utf-8'),
        source=RequestSource.INTRUDER
    )
    
    # Define injection points (all use same marker)
    injection_points = [
        InjectionPoint(name="Username", location="body", marker="§value§"),
        InjectionPoint(name="Password", location="body", marker="§value§"),
        InjectionPoint(name="Token", location="body", marker="§value§"),
    ]
    
    # Create payload set with common values
    payload_set = PayloadSet(
        name="Common Values",
        generator_type="wordlist",
        generator_config={"wordlist": ["admin", "test", "null", "undefined", "0"]}
    )
    
    # Create attack configuration
    attack_config = AttackConfig(
        name="Battering Ram Auth Bypass",
        attack_type=AttackType.BATTERING_RAM,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Execute attack
    engine = AttackEngine()
    results = await engine.execute_attack(attack_config)
    
    # Display results
    print(f"Total requests: {results.statistics.total_requests}")
    print(f"Total payloads tested: {results.statistics.total_payloads}")
    print(f"Duration: {results.statistics.duration_seconds:.2f}s")


async def demo_pitchfork_attack():
    """Demonstrate PITCHFORK attack type."""
    print("\n=== PITCHFORK ATTACK DEMO ===")
    print("Testing paired username/password combinations")
    
    # Create base request
    base_request = HTTPRequest(
        method="POST",
        url="https://example.com/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="username=§username§&password=§password§".encode('utf-8'),
        source=RequestSource.INTRUDER
    )
    
    # Define injection points
    injection_points = [
        InjectionPoint(name="Username", location="body", key="username", marker="§username§"),
        InjectionPoint(name="Password", location="body", key="password", marker="§password§"),
    ]
    
    # Create paired payload sets
    username_set = PayloadSet(
        name="Usernames",
        generator_type="wordlist",
        generator_config={"wordlist": ["admin", "root", "user", "test"]}
    )
    
    password_set = PayloadSet(
        name="Passwords",
        generator_type="wordlist",
        generator_config={"wordlist": ["admin123", "root123", "user123", "test123"]}
    )
    
    # Create attack configuration
    attack_config = AttackConfig(
        name="Credential Stuffing",
        attack_type=AttackType.PITCHFORK,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[username_set, password_set]
    )
    
    # Execute attack
    engine = AttackEngine()
    results = await engine.execute_attack(attack_config)
    
    # Display results
    print(f"Total requests: {results.statistics.total_requests}")
    print(f"Credential pairs tested: {results.statistics.total_payloads}")
    print(f"Duration: {results.statistics.duration_seconds:.2f}s")
    print(f"Tested combinations:")
    for i, result in enumerate(results.results[:4]):
        print(f"  {i+1}. {result.payloads}")


async def demo_cluster_bomb_attack():
    """Demonstrate CLUSTER_BOMB attack type."""
    print("\n=== CLUSTER BOMB ATTACK DEMO ===")
    print("Testing all combinations of usernames and passwords")
    
    # Create base request
    base_request = HTTPRequest(
        method="POST",
        url="https://example.com/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="username=§username§&password=§password§".encode('utf-8'),
        source=RequestSource.INTRUDER
    )
    
    # Define injection points
    injection_points = [
        InjectionPoint(name="Username", location="body", key="username", marker="§username§"),
        InjectionPoint(name="Password", location="body", key="password", marker="§password§"),
    ]
    
    # Create payload sets
    username_set = PayloadSet(
        name="Usernames",
        generator_type="wordlist",
        generator_config={"builtin": "usernames"}
    )
    
    password_set = PayloadSet(
        name="Passwords",
        generator_type="wordlist",
        generator_config={"builtin": "passwords"}
    )
    
    # Create attack configuration with rate limiting
    from oasis.intruder.config import RateLimitConfig
    
    attack_config = AttackConfig(
        name="Brute Force Login",
        attack_type=AttackType.CLUSTER_BOMB,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[username_set, password_set],
        rate_limiting=RateLimitConfig(
            concurrent_requests=5,
            delay_ms=50
        )
    )
    
    # Execute attack
    engine = AttackEngine()
    results = await engine.execute_attack(attack_config)
    
    # Display results
    print(f"Total requests: {results.statistics.total_requests}")
    print(f"Total combinations: {results.statistics.total_payloads}")
    print(f"Duration: {results.statistics.duration_seconds:.2f}s")
    print(f"Requests per second: {results.statistics.requests_per_second:.2f}")


async def demo_payload_processors():
    """Demonstrate payload processors."""
    print("\n=== PAYLOAD PROCESSORS DEMO ===")
    print("Testing payload transformations")
    
    # Create base request
    base_request = HTTPRequest(
        method="GET",
        url="https://example.com/api?token=§token§",
        headers={"User-Agent": "OASIS-Intruder"},
        source=RequestSource.INTRUDER
    )
    
    # Define injection point
    injection_points = [
        InjectionPoint(name="Token", location="param", key="token", marker="§token§")
    ]
    
    # Create payload set with processors
    payload_set = PayloadSet(
        name="Processed Tokens",
        generator_type="wordlist",
        generator_config={"wordlist": ["admin", "test", "user"]},
        processors=[
            PayloadProcessor(
                name="Base64 Encode",
                processor_type=ProcessorType.BASE64_ENCODE
            ),
            PayloadProcessor(
                name="URL Encode",
                processor_type=ProcessorType.URL_ENCODE
            )
        ]
    )
    
    # Create attack configuration
    attack_config = AttackConfig(
        name="Token Processing Test",
        attack_type=AttackType.SNIPER,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Execute attack
    engine = AttackEngine()
    results = await engine.execute_attack(attack_config)
    
    # Display results
    print(f"Total requests: {results.statistics.total_requests}")
    print(f"Processed payloads:")
    for i, result in enumerate(results.results):
        print(f"  {i+1}. {result.payloads}")


async def demo_number_generator():
    """Demonstrate number generator."""
    print("\n=== NUMBER GENERATOR DEMO ===")
    print("Testing numeric ranges")
    
    # Create base request
    base_request = HTTPRequest(
        method="GET",
        url="https://example.com/api/user/§id§",
        headers={"User-Agent": "OASIS-Intruder"},
        source=RequestSource.INTRUDER
    )
    
    # Define injection point
    injection_points = [
        InjectionPoint(name="User ID", location="path", marker="§id§")
    ]
    
    # Create payload set with number generator
    payload_set = PayloadSet(
        name="User IDs",
        generator_type="numbers",
        generator_config={
            "start": 1,
            "end": 10,
            "step": 1,
            "format": "{:04d}"  # Zero-padded 4 digits
        }
    )
    
    # Create attack configuration
    attack_config = AttackConfig(
        name="User Enumeration",
        attack_type=AttackType.SNIPER,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Execute attack
    engine = AttackEngine()
    results = await engine.execute_attack(attack_config)
    
    # Display results
    print(f"Total requests: {results.statistics.total_requests}")
    print(f"ID range tested: 0001-0010")
    print(f"Sample payloads:")
    for i, result in enumerate(results.results[:5]):
        print(f"  {i+1}. {result.payloads}")


async def demo_builtin_wordlists():
    """Demonstrate built-in wordlists."""
    print("\n=== BUILT-IN WORDLISTS DEMO ===")
    
    # List available wordlists
    wordlists = BuiltinWordlists.list_wordlists()
    print(f"Available wordlists: {', '.join(wordlists)}")
    
    # Show sample payloads from each wordlist
    for name in ['passwords', 'sql_injection', 'xss']:
        payloads = BuiltinWordlists.get_wordlist(name)
        print(f"\n{name.upper()} ({len(payloads)} payloads):")
        for i, payload in enumerate(payloads[:3]):
            print(f"  {i+1}. {payload}")


async def main():
    """Run all demos."""
    print("=" * 60)
    print("OASIS INTRUDER MODULE DEMONSTRATION")
    print("=" * 60)
    
    # Run demos
    await demo_sniper_attack()
    await demo_battering_ram_attack()
    await demo_pitchfork_attack()
    await demo_cluster_bomb_attack()
    await demo_payload_processors()
    await demo_number_generator()
    await demo_builtin_wordlists()
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
