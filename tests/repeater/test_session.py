"""
Unit tests for Repeater Session Management.
"""

import pytest
import tempfile
import json
from pathlib import Path

from src.oasis.repeater.session import (
    RepeaterSession,
    RepeaterTab,
    RequestHistory,
    RepeaterError,
)
from src.oasis.core.models import HTTPRequest, RequestSource


class TestRequestHistory:
    """Tests for request history management."""
    
    def test_add_and_retrieve_request(self):
        """Test adding and retrieving requests from history."""
        history = RequestHistory()
        
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        history.add(request)
        
        current = history.current()
        assert current is not None
        assert current.url == request.url
    
    def test_undo_redo_operations(self):
        """Test undo and redo operations."""
        history = RequestHistory()
        
        req1 = HTTPRequest(
            method='GET',
            url='https://example.com/1',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        req2 = HTTPRequest(
            method='GET',
            url='https://example.com/2',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        history.add(req1)
        history.add(req2)
        
        # Current should be req2
        assert history.current().url == req2.url
        
        # Undo to req1
        prev = history.undo()
        assert prev.url == req1.url
        assert history.current().url == req1.url
        
        # Redo to req2
        next_req = history.redo()
        assert next_req.url == req2.url
        assert history.current().url == req2.url
    
    def test_history_max_size(self):
        """Test that history respects max size limit."""
        history = RequestHistory(max_size=3)
        
        # Add 5 requests
        for i in range(5):
            request = HTTPRequest(
                method='GET',
                url=f'https://example.com/{i}',
                headers={'Host': 'example.com'},
                source=RequestSource.REPEATER
            )
            history.add(request)
        
        # Should only have 3 requests
        assert len(history._history) == 3
        
        # Current should be the last one
        assert history.current().url == 'https://example.com/4'


class TestRepeaterTab:
    """Tests for repeater tab functionality."""
    
    def test_create_tab_with_request(self):
        """Test creating a tab with an initial request."""
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab = RepeaterTab(name="Test Tab", request=request)
        
        assert tab.name == "Test Tab"
        assert tab.request.url == request.url
        assert tab.history.current() is not None
    
    def test_update_request_adds_to_history(self):
        """Test that updating request adds to history."""
        request1 = HTTPRequest(
            method='GET',
            url='https://example.com/1',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab = RepeaterTab(name="Test Tab", request=request1)
        
        request2 = HTTPRequest(
            method='POST',
            url='https://example.com/2',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab.update_request(request2)
        
        assert tab.request.url == request2.url
        assert tab.history.can_undo()
    
    def test_tab_undo_redo(self):
        """Test tab undo and redo operations."""
        request1 = HTTPRequest(
            method='GET',
            url='https://example.com/1',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        request2 = HTTPRequest(
            method='GET',
            url='https://example.com/2',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab = RepeaterTab(name="Test Tab", request=request1)
        tab.update_request(request2)
        
        # Undo
        success = tab.undo()
        assert success
        assert tab.request.url == request1.url
        
        # Redo
        success = tab.redo()
        assert success
        assert tab.request.url == request2.url
    
    def test_tab_serialization(self):
        """Test tab serialization and deserialization."""
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab = RepeaterTab(name="Test Tab", request=request)
        
        # Serialize
        data = tab.to_dict()
        
        # Deserialize
        restored_tab = RepeaterTab.from_dict(data)
        
        assert restored_tab.name == tab.name
        assert restored_tab.request.url == tab.request.url
        assert restored_tab.id == tab.id


class TestRepeaterSession:
    """Tests for repeater session management."""
    
    def test_create_session(self):
        """Test creating a repeater session."""
        session = RepeaterSession()
        
        assert session.id is not None
        assert len(session.tabs) == 0
        assert session.active_tab_id is None
    
    def test_create_and_manage_tabs(self):
        """Test creating and managing multiple tabs."""
        session = RepeaterSession()
        
        request1 = HTTPRequest(
            method='GET',
            url='https://example.com/1',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        request2 = HTTPRequest(
            method='GET',
            url='https://example.com/2',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        # Create tabs
        tab1 = session.create_tab("Tab 1", request1)
        tab2 = session.create_tab("Tab 2", request2)
        
        assert len(session.tabs) == 2
        assert session.active_tab_id == tab2.id
        
        # Get active tab
        active = session.get_active_tab()
        assert active.name == "Tab 2"
        
        # Switch active tab
        session.set_active_tab(tab1.id)
        assert session.active_tab_id == tab1.id
    
    def test_close_tab(self):
        """Test closing a tab."""
        session = RepeaterSession()
        
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab = session.create_tab("Test Tab", request)
        tab_id = tab.id
        
        # Close tab
        success = session.close_tab(tab_id)
        assert success
        assert len(session.tabs) == 0
        assert session.active_tab_id is None
    
    def test_session_save_and_load(self):
        """Test saving and loading session."""
        session = RepeaterSession()
        
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        tab = session.create_tab("Test Tab", request)
        
        # Save to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = Path(f.name)
        
        try:
            session.save_session(temp_path)
            
            # Load session
            loaded_session = RepeaterSession.load_session(temp_path)
            
            assert loaded_session.id == session.id
            assert len(loaded_session.tabs) == 1
            
            loaded_tab = list(loaded_session.tabs.values())[0]
            assert loaded_tab.name == "Test Tab"
            assert loaded_tab.request.url == request.url
        
        finally:
            temp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_send_request_error_handling(self):
        """Test error handling when sending requests."""
        session = RepeaterSession()
        
        # Create request with invalid URL
        request = HTTPRequest(
            method='GET',
            url='http://invalid-host-that-does-not-exist-12345.com/api',
            headers={'Host': 'invalid-host-that-does-not-exist-12345.com'},
            source=RequestSource.REPEATER
        )
        
        # Should raise RepeaterError
        with pytest.raises(RepeaterError):
            await session.send_request(request)
