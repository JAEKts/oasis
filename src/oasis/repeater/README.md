# OASIS Request Repeater Tool

The Request Repeater Tool provides manual HTTP request crafting, modification, and analysis capabilities for penetration testing workflows.

## Features

- **HTTP Request Parsing** - Parse raw HTTP requests into structured objects
- **Request Formatting** - Format requests back to raw HTTP for editing
- **Syntax Validation** - Validate request syntax with detailed error reporting
- **Request History** - Full undo/redo support with configurable history size
- **Multi-Tab Sessions** - Manage multiple requests simultaneously
- **Session Persistence** - Save and load sessions with complete state
- **Request Sending** - Send HTTP requests and capture responses
- **Response Comparison** - Compare responses with detailed diff analysis

## Quick Start

```python
from oasis.repeater import HTTPRequestEditor, RepeaterSession

# Parse a raw HTTP request
editor = HTTPRequestEditor()
request = editor.parse_raw_http("""
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"name":"John"}
""")

# Create a session and tab
session = RepeaterSession()
tab = session.create_tab("Test", request)

# Modify and track history
tab.update_request(modified_request)
tab.undo()  # Go back
tab.redo()  # Go forward

# Send request
response = await session.send_request(request)
```

## Components

### HTTPRequestEditor

High-level interface for request editing:
- `parse_raw_http(raw)` - Parse raw HTTP string
- `format_http_request(request)` - Format to raw HTTP
- `validate_syntax(raw)` - Validate request syntax
- `get_syntax_highlights(raw)` - Get highlighting info

### RepeaterSession

Session management with multi-tab support:
- `create_tab(name, request)` - Create new tab
- `close_tab(tab_id)` - Close tab
- `get_active_tab()` - Get current tab
- `send_request(request)` - Send HTTP request
- `save_session(path)` - Save to file
- `load_session(path)` - Load from file

### RepeaterTab

Individual tab with history:
- `update_request(request)` - Update and add to history
- `undo()` - Undo to previous request
- `redo()` - Redo to next request
- `history` - Access request history

### ResponseComparator

Compare HTTP responses:
- `compare_responses(r1, r2)` - Compare two responses
- `compare_multiple_responses(responses)` - Compare list
- `find_unique_responses(responses)` - Find unique ones

## Testing

Run tests:
```bash
pytest tests/repeater/ -v
```

Run property-based tests:
```bash
pytest tests/repeater/test_repeater_properties.py -v
```

## Demo

See `examples/repeater_demo.py` for comprehensive usage examples.

## Requirements Validated

- ✅ 4.1 - HTTP request editor with syntax highlighting
- ✅ 4.2 - Request modification and sending capabilities  
- ✅ 4.3 - Request/response display with metadata
- ✅ 4.4 - Tabbed interface with session persistence
- ✅ 4.5 - Request history with undo/redo
- ✅ 4.6 - Request comparison functionality
