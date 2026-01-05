"""
Demo script showing how to use the OASIS Request Repeater Tool.

This demonstrates the core functionality of the repeater including:
- Parsing raw HTTP requests
- Formatting requests
- Managing tabs and sessions
- Request history with undo/redo
- Comparing responses
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.oasis.repeater import (
    HTTPRequestEditor,
    RepeaterSession,
)
from src.oasis.core.models import HTTPRequest, RequestSource


def demo_request_parsing():
    """Demonstrate HTTP request parsing and formatting."""
    print("=" * 60)
    print("Demo 1: Request Parsing and Formatting")
    print("=" * 60)
    
    editor = HTTPRequestEditor()
    
    # Raw HTTP request
    raw_request = """POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
User-Agent: OASIS/1.0

{"name":"John Doe","email":"john@example.com"}"""
    
    print("\nOriginal Raw Request:")
    print(raw_request)
    
    # Parse the request
    request = editor.parse_raw_http(raw_request)
    print(f"\nParsed Request:")
    print(f"  Method: {request.method}")
    print(f"  URL: {request.url}")
    print(f"  Headers: {len(request.headers)} headers")
    print(f"  Body: {len(request.body) if request.body else 0} bytes")
    
    # Validate the request
    validation = editor.validate_request(request)
    print(f"\nValidation Result:")
    print(f"  Valid: {validation.valid}")
    print(f"  Errors: {len(validation.errors)}")
    print(f"  Warnings: {len(validation.warnings)}")
    
    # Format back to raw
    formatted = editor.format_http_request(request)
    print(f"\nFormatted Request:")
    print(formatted)


def demo_request_history():
    """Demonstrate request history with undo/redo."""
    print("\n" + "=" * 60)
    print("Demo 2: Request History with Undo/Redo")
    print("=" * 60)
    
    session = RepeaterSession()
    
    # Create a tab
    initial_request = HTTPRequest(
        method='GET',
        url='https://api.example.com/users',
        headers={'Host': 'api.example.com'},
        source=RequestSource.REPEATER
    )
    
    tab = session.create_tab("API Testing", initial_request)
    print(f"\nCreated tab: {tab.name}")
    print(f"Initial request: {tab.request.method} {tab.request.url}")
    
    # Modify the request several times
    modifications = [
        ('POST', 'https://api.example.com/users', 'Changed to POST'),
        ('POST', 'https://api.example.com/users/123', 'Added user ID'),
        ('PUT', 'https://api.example.com/users/123', 'Changed to PUT'),
    ]
    
    for method, url, description in modifications:
        modified_request = HTTPRequest(
            method=method,
            url=url,
            headers={'Host': 'api.example.com'},
            source=RequestSource.REPEATER
        )
        tab.update_request(modified_request)
        print(f"\n{description}: {method} {url}")
    
    print(f"\nCurrent request: {tab.request.method} {tab.request.url}")
    print(f"Can undo: {tab.history.can_undo()}")
    print(f"Can redo: {tab.history.can_redo()}")
    
    # Undo operations
    print("\n--- Performing Undo Operations ---")
    undo_count = 0
    while tab.history.can_undo() and undo_count < 2:
        tab.undo()
        undo_count += 1
        print(f"After undo {undo_count}: {tab.request.method} {tab.request.url}")
    
    # Redo operations
    print("\n--- Performing Redo Operations ---")
    redo_count = 0
    while tab.history.can_redo() and redo_count < 1:
        tab.redo()
        redo_count += 1
        print(f"After redo {redo_count}: {tab.request.method} {tab.request.url}")


def demo_multi_tab_session():
    """Demonstrate multi-tab session management."""
    print("\n" + "=" * 60)
    print("Demo 3: Multi-Tab Session Management")
    print("=" * 60)
    
    session = RepeaterSession()
    
    # Create multiple tabs
    tabs_data = [
        ("Login API", "POST", "https://api.example.com/auth/login"),
        ("Get Users", "GET", "https://api.example.com/users"),
        ("Update Profile", "PUT", "https://api.example.com/users/me"),
    ]
    
    print("\nCreating tabs:")
    for name, method, url in tabs_data:
        request = HTTPRequest(
            method=method,
            url=url,
            headers={'Host': 'api.example.com'},
            source=RequestSource.REPEATER
        )
        tab = session.create_tab(name, request)
        print(f"  - {name}: {method} {url}")
    
    print(f"\nTotal tabs: {len(session.tabs)}")
    
    # Show active tab
    active_tab = session.get_active_tab()
    print(f"Active tab: {active_tab.name}")
    
    # Switch tabs
    first_tab_id = list(session.tabs.keys())[0]
    session.set_active_tab(first_tab_id)
    active_tab = session.get_active_tab()
    print(f"Switched to: {active_tab.name}")
    
    # List all tabs
    print("\nAll tabs:")
    for tab_id, tab in session.tabs.items():
        is_active = "✓" if tab_id == session.active_tab_id else " "
        print(f"  [{is_active}] {tab.name}: {tab.request.method} {tab.request.url}")


def demo_session_persistence():
    """Demonstrate session save and load."""
    print("\n" + "=" * 60)
    print("Demo 4: Session Persistence")
    print("=" * 60)
    
    from pathlib import Path
    import tempfile
    
    # Create a session with some tabs
    session = RepeaterSession()
    
    request1 = HTTPRequest(
        method='GET',
        url='https://api.example.com/data',
        headers={'Host': 'api.example.com'},
        source=RequestSource.REPEATER
    )
    tab1 = session.create_tab("Data API", request1)
    
    # Modify the request
    request2 = HTTPRequest(
        method='POST',
        url='https://api.example.com/data',
        headers={'Host': 'api.example.com', 'Content-Type': 'application/json'},
        body=b'{"key":"value"}',
        source=RequestSource.REPEATER
    )
    tab1.update_request(request2)
    
    print(f"Created session with {len(session.tabs)} tab(s)")
    print(f"Tab: {tab1.name}")
    print(f"Current request: {tab1.request.method} {tab1.request.url}")
    print(f"History size: {len(tab1.history._history)}")
    
    # Save session
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        temp_path = Path(f.name)
    
    try:
        session.save_session(temp_path)
        print(f"\nSession saved to: {temp_path}")
        
        # Load session
        loaded_session = RepeaterSession.load_session(temp_path)
        print(f"\nSession loaded successfully")
        print(f"Loaded {len(loaded_session.tabs)} tab(s)")
        
        loaded_tab = list(loaded_session.tabs.values())[0]
        print(f"Tab: {loaded_tab.name}")
        print(f"Current request: {loaded_tab.request.method} {loaded_tab.request.url}")
        print(f"History size: {len(loaded_tab.history._history)}")
        print(f"Can undo: {loaded_tab.history.can_undo()}")
        
    finally:
        temp_path.unlink()
        print(f"\nCleaned up temp file")


async def demo_send_request():
    """Demonstrate sending HTTP requests (requires network)."""
    print("\n" + "=" * 60)
    print("Demo 5: Sending HTTP Requests")
    print("=" * 60)
    
    session = RepeaterSession()
    
    # Create a request to a public API
    request = HTTPRequest(
        method='GET',
        url='https://httpbin.org/get',
        headers={
            'Host': 'httpbin.org',
            'User-Agent': 'OASIS-Repeater/1.0'
        },
        source=RequestSource.REPEATER
    )
    
    print(f"\nSending request: {request.method} {request.url}")
    
    try:
        response = await session.send_request(request)
        
        print(f"\nResponse received:")
        print(f"  Status: {response.status_code}")
        print(f"  Duration: {response.duration_ms}ms")
        print(f"  Body size: {len(response.body) if response.body else 0} bytes")
        print(f"  Headers: {len(response.headers)} headers")
        
        # Show some response headers
        print(f"\nSample headers:")
        for key in list(response.headers.keys())[:3]:
            print(f"  {key}: {response.headers[key]}")
        
    except Exception as e:
        print(f"\nError sending request: {e}")
        print("(This is expected if you don't have internet connectivity)")


def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("OASIS Request Repeater Tool - Demo")
    print("=" * 60)
    
    # Run synchronous demos
    demo_request_parsing()
    demo_request_history()
    demo_multi_tab_session()
    demo_session_persistence()
    
    # Run async demo
    print("\n" + "=" * 60)
    print("Running async demo...")
    print("=" * 60)
    asyncio.run(demo_send_request())
    
    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
