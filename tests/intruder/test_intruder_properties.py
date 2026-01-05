"""
Property-based tests for OASIS Intruder/Attack Engine.

Feature: oasis-pentest-suite, Property 10: Attack Configuration Correctness
Validates: Requirements 5.3
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from datetime import datetime, UTC
import asyncio

from src.oasis.core.models import HTTPRequest, RequestSource
from src.oasis.intruder.config import (
    AttackType,
    AttackConfig,
    InjectionPoint,
    PayloadSet,
    PayloadProcessor,
    ProcessorType,
    RateLimitConfig,
)
from src.oasis.intruder.payloads import (
    WordlistGenerator,
    NumberGenerator,
    CharsetGenerator,
    create_generator,
)
from src.oasis.intruder.engine import AttackEngine


# Custom strategies for generating attack configurations

@st.composite
def http_request_with_markers_strategy(draw):
    """Generate HTTPRequest with injection markers."""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    method = draw(st.sampled_from(methods))
    
    # Generate URL with marker
    host = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Ll',), min_codepoint=97, max_codepoint=122),
        min_size=3,
        max_size=15
    ))
    
    # Decide where to place markers
    has_url_marker = draw(st.booleans())
    has_body_marker = draw(st.booleans()) and method in ['POST', 'PUT', 'PATCH']
    
    if has_url_marker:
        url = f"https://{host}.com/test?param=§marker1§"
    else:
        url = f"https://{host}.com/test"
    
    headers = {'Host': f'{host}.com', 'User-Agent': 'OASIS-Intruder'}
    
    body = None
    if has_body_marker:
        body = "data=§marker2§&other=value".encode('utf-8')
    
    return HTTPRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        source=RequestSource.INTRUDER
    )


@st.composite
def injection_point_strategy(draw, marker):
    """Generate InjectionPoint with specified marker."""
    locations = ['param', 'body', 'header', 'path']
    location = draw(st.sampled_from(locations))
    
    name = draw(st.text(min_size=3, max_size=20))
    key = draw(st.text(min_size=1, max_size=15)) if location in ['param', 'header'] else None
    
    return InjectionPoint(
        name=name,
        location=location,
        key=key,
        marker=marker
    )


@st.composite
def payload_set_strategy(draw):
    """Generate PayloadSet configuration."""
    generator_types = ['wordlist', 'numbers', 'charset']
    gen_type = draw(st.sampled_from(generator_types))
    
    name = draw(st.text(min_size=3, max_size=20))
    
    if gen_type == 'wordlist':
        wordlist = draw(st.lists(
            st.text(min_size=1, max_size=20),
            min_size=1,
            max_size=10
        ))
        config = {'wordlist': wordlist}
    
    elif gen_type == 'numbers':
        start = draw(st.integers(min_value=0, max_value=50))
        end = draw(st.integers(min_value=start + 1, max_value=start + 20))
        config = {'start': start, 'end': end, 'step': 1}
    
    else:  # charset
        charset = draw(st.text(
            alphabet=st.characters(whitelist_categories=('Ll',), min_codepoint=97, max_codepoint=122),
            min_size=2,
            max_size=5
        ))
        min_len = draw(st.integers(min_value=1, max_value=2))
        max_len = draw(st.integers(min_value=min_len, max_value=min_len + 1))
        config = {'charset': charset, 'min_length': min_len, 'max_length': max_len}
    
    return PayloadSet(
        name=name,
        generator_type=gen_type,
        generator_config=config
    )


# Property 10: Attack Configuration Correctness
# For any intruder attack configuration, payload generation and execution should
# follow the specified attack type algorithm exactly


@given(
    attack_type=st.sampled_from([AttackType.SNIPER, AttackType.BATTERING_RAM]),
    num_injection_points=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_sniper_and_battering_ram_require_single_payload_set(attack_type, num_injection_points):
    """
    Property 10: Attack Configuration Correctness (SNIPER/BATTERING_RAM Validation)
    
    For any SNIPER or BATTERING_RAM attack, exactly one payload set must be configured,
    regardless of the number of injection points.
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_injection_points)
    ]
    
    # Create single payload set
    payload_set = PayloadSet(
        name="Test Payloads",
        generator_type='wordlist',
        generator_config={'wordlist': ['test1', 'test2']}
    )
    
    # Property assertion 1: Configuration with one payload set should be valid
    config = AttackConfig(
        name="Test Attack",
        attack_type=attack_type,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Should not raise exception
    config.validate_attack_configuration()
    
    # Property assertion 2: Configuration with multiple payload sets should be invalid
    payload_set2 = PayloadSet(
        name="Test Payloads 2",
        generator_type='wordlist',
        generator_config={'wordlist': ['test3', 'test4']}
    )
    
    config_invalid = AttackConfig(
        name="Invalid Attack",
        attack_type=attack_type,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set, payload_set2]
    )
    
    with pytest.raises(ValueError, match="requires exactly one payload set"):
        config_invalid.validate_attack_configuration()


@given(
    num_injection_points=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_pitchfork_requires_matching_payload_sets(num_injection_points):
    """
    Property 10: Attack Configuration Correctness (PITCHFORK Validation)
    
    For any PITCHFORK attack, the number of payload sets must exactly match
    the number of injection points for synchronized iteration.
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_injection_points)
    ]
    
    # Create matching number of payload sets
    payload_sets = [
        PayloadSet(
            name=f"Payloads{i}",
            generator_type='wordlist',
            generator_config={'wordlist': [f'test{i}a', f'test{i}b']}
        )
        for i in range(num_injection_points)
    ]
    
    # Property assertion 1: Matching counts should be valid
    config = AttackConfig(
        name="Test Pitchfork",
        attack_type=AttackType.PITCHFORK,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=payload_sets
    )
    
    config.validate_attack_configuration()
    
    # Property assertion 2: Mismatched counts should be invalid
    if num_injection_points > 1:
        config_invalid = AttackConfig(
            name="Invalid Pitchfork",
            attack_type=AttackType.PITCHFORK,
            base_request=base_request,
            injection_points=injection_points,
            payload_sets=payload_sets[:-1]  # One less payload set
        )
        
        with pytest.raises(ValueError, match="equal number of payload sets"):
            config_invalid.validate_attack_configuration()


@given(
    num_injection_points=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_cluster_bomb_requires_matching_payload_sets(num_injection_points):
    """
    Property 10: Attack Configuration Correctness (CLUSTER_BOMB Validation)
    
    For any CLUSTER_BOMB attack, the number of payload sets must exactly match
    the number of injection points for cartesian product generation.
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_injection_points)
    ]
    
    # Create matching number of payload sets
    payload_sets = [
        PayloadSet(
            name=f"Payloads{i}",
            generator_type='wordlist',
            generator_config={'wordlist': [f'test{i}a', f'test{i}b']}
        )
        for i in range(num_injection_points)
    ]
    
    # Property assertion 1: Matching counts should be valid
    config = AttackConfig(
        name="Test Cluster Bomb",
        attack_type=AttackType.CLUSTER_BOMB,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=payload_sets
    )
    
    config.validate_attack_configuration()
    
    # Property assertion 2: Mismatched counts should be invalid
    if num_injection_points > 1:
        config_invalid = AttackConfig(
            name="Invalid Cluster Bomb",
            attack_type=AttackType.CLUSTER_BOMB,
            base_request=base_request,
            injection_points=injection_points,
            payload_sets=payload_sets[:-1]  # One less payload set
        )
        
        with pytest.raises(ValueError, match="equal number of payload sets"):
            config_invalid.validate_attack_configuration()


@given(
    payloads=st.lists(st.text(min_size=1, max_size=20), min_size=2, max_size=10),
    num_injection_points=st.integers(min_value=2, max_value=4),
)
@settings(max_examples=100, deadline=None)
def test_sniper_attack_payload_distribution(payloads, num_injection_points):
    """
    Property 10: Attack Configuration Correctness (SNIPER Payload Distribution)
    
    For any SNIPER attack with N injection points and M payloads, the total number
    of requests should be N * M (each payload tested at each injection point).
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_injection_points)
    ]
    
    # Create payload set
    payload_set = PayloadSet(
        name="Test Payloads",
        generator_type='wordlist',
        generator_config={'wordlist': payloads}
    )
    
    config = AttackConfig(
        name="Sniper Test",
        attack_type=AttackType.SNIPER,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Generate payload combinations
    engine = AttackEngine()
    combinations = asyncio.run(engine._generate_payload_combinations(config))
    
    # Property assertion: Total combinations should be N * M
    expected_count = num_injection_points * len(payloads)
    assert len(combinations) == expected_count, \
        f"SNIPER should generate {expected_count} combinations, got {len(combinations)}"
    
    # Property assertion: Each injection point should appear exactly M times
    marker_counts = {ip.marker: 0 for ip in injection_points}
    for combo in combinations:
        for marker in combo.keys():
            if marker in marker_counts:
                marker_counts[marker] += 1
    
    for marker, count in marker_counts.items():
        assert count == len(payloads), \
            f"Each injection point should appear {len(payloads)} times, {marker} appeared {count} times"


@given(
    payloads=st.lists(st.text(min_size=1, max_size=20), min_size=2, max_size=10),
    num_injection_points=st.integers(min_value=2, max_value=4),
)
@settings(max_examples=100, deadline=None)
def test_battering_ram_attack_payload_distribution(payloads, num_injection_points):
    """
    Property 10: Attack Configuration Correctness (BATTERING_RAM Payload Distribution)
    
    For any BATTERING_RAM attack with N injection points and M payloads, the total
    number of requests should be M (same payload applied to all injection points).
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_injection_points)
    ]
    
    # Create payload set
    payload_set = PayloadSet(
        name="Test Payloads",
        generator_type='wordlist',
        generator_config={'wordlist': payloads}
    )
    
    config = AttackConfig(
        name="Battering Ram Test",
        attack_type=AttackType.BATTERING_RAM,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=[payload_set]
    )
    
    # Generate payload combinations
    engine = AttackEngine()
    combinations = asyncio.run(engine._generate_payload_combinations(config))
    
    # Property assertion 1: Total combinations should be M
    assert len(combinations) == len(payloads), \
        f"BATTERING_RAM should generate {len(payloads)} combinations, got {len(combinations)}"
    
    # Property assertion 2: Each combination should have all injection points with same payload
    for combo in combinations:
        # All markers should be present
        assert len(combo) == num_injection_points, \
            f"Each combination should have {num_injection_points} markers"
        
        # All markers should have the same payload value
        payload_values = list(combo.values())
        assert all(v == payload_values[0] for v in payload_values), \
            "All injection points should have the same payload in BATTERING_RAM"


@given(
    payload_lists=st.lists(
        st.lists(st.text(min_size=1, max_size=15), min_size=2, max_size=5),
        min_size=2,
        max_size=4
    ),
)
@settings(max_examples=100, deadline=None)
def test_pitchfork_attack_synchronized_iteration(payload_lists):
    """
    Property 10: Attack Configuration Correctness (PITCHFORK Synchronized Iteration)
    
    For any PITCHFORK attack with N payload sets, iteration should be synchronized
    (one-to-one mapping), and total requests should equal the length of the shortest set.
    
    Validates: Requirements 5.3
    """
    num_points = len(payload_lists)
    
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_points)
    ]
    
    # Create payload sets
    payload_sets = [
        PayloadSet(
            name=f"Payloads{i}",
            generator_type='wordlist',
            generator_config={'wordlist': payload_lists[i]}
        )
        for i in range(num_points)
    ]
    
    config = AttackConfig(
        name="Pitchfork Test",
        attack_type=AttackType.PITCHFORK,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=payload_sets
    )
    
    # Generate payload combinations
    engine = AttackEngine()
    combinations = asyncio.run(engine._generate_payload_combinations(config))
    
    # Property assertion 1: Total combinations should equal shortest payload list
    min_length = min(len(pl) for pl in payload_lists)
    assert len(combinations) == min_length, \
        f"PITCHFORK should generate {min_length} combinations, got {len(combinations)}"
    
    # Property assertion 2: Each combination should have all injection points
    for combo in combinations:
        assert len(combo) == num_points, \
            f"Each combination should have {num_points} markers"
    
    # Property assertion 3: Payloads should be synchronized (index-matched)
    for i, combo in enumerate(combinations):
        for j, (marker, payload) in enumerate(combo.items()):
            expected_payload = payload_lists[j][i]
            assert payload == expected_payload, \
                f"Payload mismatch at combination {i}, position {j}: expected {expected_payload}, got {payload}"


@given(
    payload_lists=st.lists(
        st.lists(st.text(min_size=1, max_size=10), min_size=2, max_size=3),
        min_size=2,
        max_size=3
    ),
)
@settings(max_examples=50, deadline=None)
def test_cluster_bomb_attack_cartesian_product(payload_lists):
    """
    Property 10: Attack Configuration Correctness (CLUSTER_BOMB Cartesian Product)
    
    For any CLUSTER_BOMB attack with N payload sets of sizes [M1, M2, ..., MN],
    the total number of requests should be M1 * M2 * ... * MN (cartesian product).
    
    Validates: Requirements 5.3
    """
    num_points = len(payload_lists)
    
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    # Create injection points
    injection_points = [
        InjectionPoint(
            name=f"Point{i}",
            location='param',
            marker=f"§marker{i}§"
        )
        for i in range(num_points)
    ]
    
    # Create payload sets
    payload_sets = [
        PayloadSet(
            name=f"Payloads{i}",
            generator_type='wordlist',
            generator_config={'wordlist': payload_lists[i]}
        )
        for i in range(num_points)
    ]
    
    config = AttackConfig(
        name="Cluster Bomb Test",
        attack_type=AttackType.CLUSTER_BOMB,
        base_request=base_request,
        injection_points=injection_points,
        payload_sets=payload_sets
    )
    
    # Generate payload combinations
    engine = AttackEngine()
    combinations = asyncio.run(engine._generate_payload_combinations(config))
    
    # Property assertion 1: Total combinations should be cartesian product
    import math
    expected_count = math.prod(len(pl) for pl in payload_lists)
    assert len(combinations) == expected_count, \
        f"CLUSTER_BOMB should generate {expected_count} combinations, got {len(combinations)}"
    
    # Property assertion 2: Each combination should have all injection points
    for combo in combinations:
        assert len(combo) == num_points, \
            f"Each combination should have {num_points} markers"
    
    # Property assertion 3: All possible combinations should be present
    # Convert combinations to tuples for set comparison
    combo_tuples = set()
    for combo in combinations:
        # Sort by marker to ensure consistent ordering
        sorted_items = sorted(combo.items(), key=lambda x: x[0])
        combo_tuple = tuple(v for k, v in sorted_items)
        combo_tuples.add(combo_tuple)
    
    # Generate expected combinations
    import itertools
    expected_combos = set(itertools.product(*payload_lists))
    
    assert combo_tuples == expected_combos, \
        "CLUSTER_BOMB should generate all possible combinations"


@given(
    processor_type=st.sampled_from([
        ProcessorType.URL_ENCODE,
        ProcessorType.BASE64_ENCODE,
        ProcessorType.UPPERCASE,
        ProcessorType.LOWERCASE,
    ]),
    payloads=st.lists(st.text(min_size=1, max_size=20), min_size=2, max_size=5),
)
@settings(max_examples=100, deadline=None)
def test_payload_processors_applied_correctly(processor_type, payloads):
    """
    Property 10: Attack Configuration Correctness (Payload Processing)
    
    For any payload set with processors, all payloads should be transformed
    according to the processor configuration before injection.
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test?param=§marker§',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    injection_point = InjectionPoint(
        name="Test Point",
        location='param',
        marker="§marker§"
    )
    
    # Create processor
    processor = PayloadProcessor(
        name="Test Processor",
        processor_type=processor_type
    )
    
    # Create payload set with processor
    payload_set = PayloadSet(
        name="Processed Payloads",
        generator_type='wordlist',
        generator_config={'wordlist': payloads},
        processors=[processor]
    )
    
    config = AttackConfig(
        name="Processor Test",
        attack_type=AttackType.SNIPER,
        base_request=base_request,
        injection_points=[injection_point],
        payload_sets=[payload_set]
    )
    
    # Generate payload combinations
    engine = AttackEngine()
    combinations = asyncio.run(engine._generate_payload_combinations(config))
    
    # Property assertion: All payloads should be processed
    for i, combo in enumerate(combinations):
        actual_payload = combo["§marker§"]
        original_payload = payloads[i]
        expected_payload = processor.process(original_payload)
        
        assert actual_payload == expected_payload, \
            f"Payload should be processed: expected {expected_payload}, got {actual_payload}"


@given(
    concurrent_requests=st.integers(min_value=1, max_value=20),
    delay_ms=st.integers(min_value=0, max_value=500),
)
@settings(max_examples=100, deadline=None)
def test_rate_limiting_configuration_validation(concurrent_requests, delay_ms):
    """
    Property 10: Attack Configuration Correctness (Rate Limiting)
    
    For any rate limiting configuration, the values should be validated and
    applied correctly to control attack execution speed.
    
    Validates: Requirements 5.3
    """
    # Property assertion 1: Valid configurations should be accepted
    if 1 <= concurrent_requests <= 100:
        rate_limit = RateLimitConfig(
            concurrent_requests=concurrent_requests,
            delay_ms=delay_ms
        )
        
        assert rate_limit.concurrent_requests == concurrent_requests
        assert rate_limit.delay_ms == delay_ms
    
    # Property assertion 2: Invalid concurrent_requests should be rejected
    if concurrent_requests < 1 or concurrent_requests > 100:
        with pytest.raises(ValueError):
            RateLimitConfig(concurrent_requests=concurrent_requests, delay_ms=delay_ms)
    
    # Property assertion 3: Negative delay should be rejected
    if delay_ms < 0:
        with pytest.raises(ValueError):
            RateLimitConfig(concurrent_requests=5, delay_ms=delay_ms)


@given(
    timeout=st.integers(min_value=-10, max_value=400),
)
@settings(max_examples=100, deadline=None)
def test_attack_timeout_validation(timeout):
    """
    Property 10: Attack Configuration Correctness (Timeout Validation)
    
    For any timeout configuration, values should be validated to ensure
    they are within acceptable ranges (1-300 seconds).
    
    Validates: Requirements 5.3
    """
    base_request = HTTPRequest(
        method='GET',
        url='https://example.com/test',
        headers={'Host': 'example.com'},
        source=RequestSource.INTRUDER
    )
    
    injection_point = InjectionPoint(
        name="Test",
        location='param',
        marker="§marker§"
    )
    
    payload_set = PayloadSet(
        name="Test",
        generator_type='wordlist',
        generator_config={'wordlist': ['test']}
    )
    
    # Property assertion: Valid timeouts (1-300) should be accepted
    if 1 <= timeout <= 300:
        config = AttackConfig(
            name="Timeout Test",
            attack_type=AttackType.SNIPER,
            base_request=base_request,
            injection_points=[injection_point],
            payload_sets=[payload_set],
            timeout_seconds=timeout
        )
        assert config.timeout_seconds == timeout
    
    # Property assertion: Invalid timeouts should be rejected
    else:
        with pytest.raises(ValueError):
            AttackConfig(
                name="Invalid Timeout",
                attack_type=AttackType.SNIPER,
                base_request=base_request,
                injection_points=[injection_point],
                payload_sets=[payload_set],
                timeout_seconds=timeout
            )
