"""
Property-based tests for OASIS Request Repeater Tool.

Feature: oasis-pentest-suite, Property 9: Request History Integrity
Validates: Requirements 4.5
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from datetime import datetime, UTC

from src.oasis.core.models import HTTPRequest, RequestSource
from src.oasis.repeater.session import RequestHistory, RepeaterTab


# Custom strategies for generating HTTP requests
@st.composite
def http_request_strategy(draw):
    """Generate valid HTTPRequest objects for testing."""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    method = draw(st.sampled_from(methods))
    
    # Generate URL
    schemes = ['http', 'https']
    scheme = draw(st.sampled_from(schemes))
    host = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), min_codepoint=97, max_codepoint=122),
        min_size=3,
        max_size=20
    ))
    path = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), min_codepoint=97, max_codepoint=122),
        min_size=1,
        max_size=30
    ))
    url = f"{scheme}://{host}.com/{path}"
    
    # Generate headers
    num_headers = draw(st.integers(min_value=1, max_value=10))
    headers = {'Host': f'{host}.com'}
    for i in range(num_headers - 1):
        key = draw(st.text(
            alphabet=st.characters(whitelist_categories=('Lu', 'Ll'), min_codepoint=65, max_codepoint=122),
            min_size=3,
            max_size=20
        ))
        value = draw(st.text(min_size=1, max_size=50))
        headers[key] = value
    
    # Generate body (optional)
    has_body = draw(st.booleans())
    body = None
    if has_body and method in ['POST', 'PUT', 'PATCH']:
        body_text = draw(st.text(min_size=0, max_size=1000))
        body = body_text.encode('utf-8') if body_text else None
    
    return HTTPRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        source=RequestSource.REPEATER
    )


# Property 9: Request History Integrity
# For any sequence of request modifications in the repeater, undo/redo operations
# should maintain perfect bidirectional consistency


@given(
    requests=st.lists(http_request_strategy(), min_size=1, max_size=20),
)
@settings(max_examples=100, deadline=None)
def test_request_history_undo_redo_consistency(requests):
    """
    Property 9: Request History Integrity (Undo/Redo Consistency)
    
    For any sequence of request modifications, performing undo followed by redo
    should return to the exact same state, maintaining perfect bidirectional consistency.
    
    Validates: Requirements 4.5
    """
    history = RequestHistory()
    
    # Add all requests to history
    for request in requests:
        history.add(request)
    
    # Property assertion 1: Current request should be the last added
    current = history.current()
    assert current is not None
    assert current.url == requests[-1].url
    assert current.method == requests[-1].method
    
    # Perform undo operations and track states
    undo_states = []
    while history.can_undo():
        prev = history.undo()
        if prev:
            undo_states.append(prev)
    
    # Property assertion 2: Number of undo operations should be len(requests) - 1
    assert len(undo_states) == len(requests) - 1
    
    # Property assertion 3: Undo states should match original requests in reverse
    for i, state in enumerate(undo_states):
        expected_index = len(requests) - 2 - i
        assert state.url == requests[expected_index].url
        assert state.method == requests[expected_index].method
    
    # Now perform redo operations
    redo_states = []
    while history.can_redo():
        next_req = history.redo()
        if next_req:
            redo_states.append(next_req)
    
    # Property assertion 4: Number of redo operations should equal undo operations
    assert len(redo_states) == len(undo_states)
    
    # Property assertion 5: Redo should restore exact same states as before undo
    for i, state in enumerate(redo_states):
        expected_index = i + 1
        assert state.url == requests[expected_index].url
        assert state.method == requests[expected_index].method
    
    # Property assertion 6: Final state should match original final state
    final = history.current()
    assert final is not None
    assert final.url == requests[-1].url
    assert final.method == requests[-1].method


@given(
    requests=st.lists(http_request_strategy(), min_size=2, max_size=15),
    undo_count=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=100, deadline=None)
def test_request_history_add_after_undo_truncates(requests, undo_count):
    """
    Property 9: Request History Integrity (Add After Undo)
    
    For any history state, adding a new request after undo operations should
    truncate the forward history, maintaining consistency.
    
    Validates: Requirements 4.5
    """
    assume(undo_count < len(requests))
    
    history = RequestHistory()
    
    # Add all requests
    for request in requests:
        history.add(request)
    
    # Perform some undo operations
    for _ in range(undo_count):
        if history.can_undo():
            history.undo()
    
    # Property assertion 1: Should be able to redo after undo
    assert history.can_redo()
    
    # Add a new request
    new_request = HTTPRequest(
        method='POST',
        url='https://newhost.com/newpath',
        headers={'Host': 'newhost.com'},
        source=RequestSource.REPEATER
    )
    history.add(new_request)
    
    # Property assertion 2: Should NOT be able to redo after adding new request
    assert not history.can_redo(), "Adding after undo should truncate forward history"
    
    # Property assertion 3: Current request should be the newly added one
    current = history.current()
    assert current is not None
    assert current.url == new_request.url
    assert current.method == new_request.method
    
    # Property assertion 4: Can undo to previous states
    assert history.can_undo()
    prev = history.undo()
    assert prev is not None
    # Should be at the state before the new request
    expected_index = len(requests) - undo_count - 1
    assert prev.url == requests[expected_index].url


@given(
    requests=st.lists(http_request_strategy(), min_size=1, max_size=10),
)
@settings(max_examples=100, deadline=None)
def test_request_history_serialization_roundtrip(requests):
    """
    Property 9: Request History Integrity (Serialization)
    
    For any request history, serializing to dict and deserializing should
    preserve all history state including current position.
    
    Validates: Requirements 4.5
    """
    history = RequestHistory()
    
    # Add requests
    for request in requests:
        history.add(request)
    
    # Perform some random undo/redo operations
    if len(requests) > 1:
        history.undo()
        if history.can_redo():
            history.redo()
    
    # Get current state
    original_current = history.current()
    original_can_undo = history.can_undo()
    original_can_redo = history.can_redo()
    
    # Serialize and deserialize
    data = history.to_dict()
    restored_history = RequestHistory.from_dict(data)
    
    # Property assertion 1: Current request should be preserved
    restored_current = restored_history.current()
    if original_current:
        assert restored_current is not None
        assert restored_current.url == original_current.url
        assert restored_current.method == original_current.method
        assert restored_current.headers == original_current.headers
    else:
        assert restored_current is None
    
    # Property assertion 2: Undo/redo capabilities should be preserved
    assert restored_history.can_undo() == original_can_undo
    assert restored_history.can_redo() == original_can_redo
    
    # Property assertion 3: History size should be preserved
    assert len(restored_history._history) == len(history._history)
    
    # Property assertion 4: All history entries should be preserved
    for i, (orig_entry, restored_entry) in enumerate(
        zip(history._history, restored_history._history)
    ):
        assert orig_entry.request.url == restored_entry.request.url
        assert orig_entry.request.method == restored_entry.request.method


@given(
    requests=st.lists(http_request_strategy(), min_size=1, max_size=20),
)
@settings(max_examples=100, deadline=None)
def test_repeater_tab_history_integration(requests):
    """
    Property 9: Request History Integrity (Tab Integration)
    
    For any sequence of request updates in a repeater tab, the tab's
    undo/redo operations should maintain consistency with the underlying history.
    
    Validates: Requirements 4.5
    """
    # Create tab with first request
    tab = RepeaterTab(name="Test Tab", request=requests[0])
    
    # Update with remaining requests
    for request in requests[1:]:
        tab.update_request(request)
    
    # Property assertion 1: Current request should be the last one
    assert tab.request is not None
    assert tab.request.url == requests[-1].url
    
    # Property assertion 2: Can undo if we have multiple requests
    if len(requests) > 1:
        assert tab.history.can_undo()
        
        # Perform undo
        success = tab.undo()
        assert success
        
        # Current request should be previous one
        assert tab.request.url == requests[-2].url
        
        # Property assertion 3: Can redo after undo
        assert tab.history.can_redo()
        
        # Perform redo
        success = tab.redo()
        assert success
        
        # Should be back to last request
        assert tab.request.url == requests[-1].url
    
    # Property assertion 4: Modified timestamp should be updated
    assert tab.modified_at >= tab.created_at


@given(
    initial_requests=st.lists(http_request_strategy(), min_size=1, max_size=10),
)
@settings(max_examples=100, deadline=None)
def test_repeater_tab_serialization_preserves_history(initial_requests):
    """
    Property 9: Request History Integrity (Tab Serialization)
    
    For any repeater tab with history, serializing and deserializing should
    preserve the complete history and current state.
    
    Validates: Requirements 4.5
    """
    # Create tab with requests
    tab = RepeaterTab(name="Test Tab", request=initial_requests[0])
    for request in initial_requests[1:]:
        tab.update_request(request)
    
    # Perform some undo operations if possible
    if len(initial_requests) > 1:
        tab.undo()
    
    # Get current state
    original_request = tab.request
    original_can_undo = tab.history.can_undo()
    original_can_redo = tab.history.can_redo()
    
    # Serialize and deserialize
    data = tab.to_dict()
    restored_tab = RepeaterTab.from_dict(data)
    
    # Property assertion 1: Tab metadata should be preserved
    assert restored_tab.id == tab.id
    assert restored_tab.name == tab.name
    
    # Property assertion 2: Current request should be preserved
    if original_request:
        assert restored_tab.request is not None
        assert restored_tab.request.url == original_request.url
        assert restored_tab.request.method == original_request.method
    
    # Property assertion 3: History state should be preserved
    assert restored_tab.history.can_undo() == original_can_undo
    assert restored_tab.history.can_redo() == original_can_redo
    
    # Property assertion 4: Undo/redo should work on restored tab
    if restored_tab.history.can_redo():
        success = restored_tab.redo()
        assert success
        # Should be back to last request
        assert restored_tab.request.url == initial_requests[-1].url


@given(
    max_size=st.integers(min_value=2, max_value=10),
    num_requests=st.integers(min_value=3, max_value=20),
)
@settings(max_examples=100, deadline=None)
def test_request_history_respects_max_size(max_size, num_requests):
    """
    Property 9: Request History Integrity (Size Limit)
    
    For any max_size configuration, the history should never exceed that size
    and should maintain oldest entries when limit is reached.
    
    Validates: Requirements 4.5
    """
    assume(num_requests > max_size)
    
    history = RequestHistory(max_size=max_size)
    
    # Add more requests than max_size
    requests = []
    for i in range(num_requests):
        request = HTTPRequest(
            method='GET',
            url=f'https://example.com/path{i}',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        requests.append(request)
        history.add(request)
    
    # Property assertion 1: History size should not exceed max_size
    assert len(history._history) <= max_size
    
    # Property assertion 2: History should contain the most recent requests
    current = history.current()
    assert current is not None
    assert current.url == requests[-1].url
    
    # Property assertion 3: Oldest requests should be removed
    # The history should contain requests from index (num_requests - max_size) onwards
    expected_start_index = num_requests - max_size
    
    # Undo to beginning
    while history.can_undo():
        history.undo()
    
    # First request in history should be from expected_start_index
    first_in_history = history.current()
    assert first_in_history is not None
    assert first_in_history.url == requests[expected_start_index].url


@given(
    requests=st.lists(http_request_strategy(), min_size=2, max_size=10),
    operations=st.lists(
        st.sampled_from(['undo', 'redo', 'add']),
        min_size=1,
        max_size=20
    ),
)
@settings(max_examples=50, deadline=None)
def test_request_history_complex_operation_sequence(requests, operations):
    """
    Property 9: Request History Integrity (Complex Operations)
    
    For any complex sequence of undo/redo/add operations, the history should
    maintain consistency and never enter an invalid state.
    
    Validates: Requirements 4.5
    """
    history = RequestHistory()
    
    # Add initial requests
    for request in requests:
        history.add(request)
    
    # Perform complex operation sequence
    for operation in operations:
        if operation == 'undo':
            if history.can_undo():
                prev = history.undo()
                # Property assertion: Undo should return a valid request
                assert prev is not None
        
        elif operation == 'redo':
            if history.can_redo():
                next_req = history.redo()
                # Property assertion: Redo should return a valid request
                assert next_req is not None
        
        elif operation == 'add':
            new_request = HTTPRequest(
                method='POST',
                url=f'https://test.com/op{len(operations)}',
                headers={'Host': 'test.com'},
                source=RequestSource.REPEATER
            )
            history.add(new_request)
            
            # Property assertion: After add, current should be the new request
            current = history.current()
            assert current is not None
            assert current.url == new_request.url
            
            # Property assertion: After add, redo should not be available
            assert not history.can_redo()
    
    # Final property assertions:
    # 1. History should always have a current request
    assert history.current() is not None
    
    # 2. Current index should be valid
    assert 0 <= history._current_index < len(history._history)
    
    # 3. History should not be empty
    assert len(history._history) > 0
