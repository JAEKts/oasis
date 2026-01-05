"""
Unit tests for HTTP Request Editor functionality.
"""

import pytest
from src.oasis.repeater.editor import (
    HTTPRequestParser,
    HTTPRequestFormatter,
    HTTPRequestValidator,
    HTTPRequestEditor,
    HTTPParseError,
    ValidationResult,
)
from src.oasis.core.models import HTTPRequest, HTTPResponse, RequestSource


class TestHTTPRequestParser:
    """Tests for HTTP request parsing."""
    
    def test_parse_simple_get_request(self):
        """Test parsing a simple GET request."""
        raw = """GET /api/users HTTP/1.1
Host: example.com
User-Agent: TestClient/1.0

"""
        request = HTTPRequestParser.parse_raw_http(raw)
        
        assert request.method == 'GET'
        assert request.url == 'https://example.com/api/users'
        assert request.headers['Host'] == 'example.com'
        assert request.headers['User-Agent'] == 'TestClient/1.0'
        assert request.body is None
    
    def test_parse_post_request_with_body(self):
        """Test parsing a POST request with body."""
        raw = """POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 27

{"name":"John","age":30}"""
        
        request = HTTPRequestParser.parse_raw_http(raw)
        
        assert request.method == 'POST'
        assert request.url == 'https://api.example.com/api/users'
        assert request.headers['Content-Type'] == 'application/json'
        assert request.body == b'{"name":"John","age":30}'
    
    def test_parse_request_with_query_params(self):
        """Test parsing request with query parameters."""
        raw = """GET /search?q=test&limit=10 HTTP/1.1
Host: search.example.com

"""
        request = HTTPRequestParser.parse_raw_http(raw)
        
        assert request.method == 'GET'
        assert 'q=test' in request.url
        assert 'limit=10' in request.url
    
    def test_parse_empty_request_raises_error(self):
        """Test that parsing empty request raises error."""
        with pytest.raises(HTTPParseError, match="Empty request"):
            HTTPRequestParser.parse_raw_http("")
    
    def test_parse_request_without_host_raises_error(self):
        """Test that parsing request without Host header raises error."""
        raw = """GET /api/users HTTP/1.1
User-Agent: TestClient/1.0

"""
        with pytest.raises(HTTPParseError, match="Missing Host header"):
            HTTPRequestParser.parse_raw_http(raw)


class TestHTTPRequestFormatter:
    """Tests for HTTP request formatting."""
    
    def test_format_simple_get_request(self):
        """Test formatting a simple GET request."""
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api/users',
            headers={'Host': 'example.com', 'User-Agent': 'TestClient/1.0'},
            source=RequestSource.REPEATER
        )
        
        formatted = HTTPRequestFormatter.format_http_request(request)
        
        assert 'GET /api/users HTTP/1.1' in formatted
        assert 'Host: example.com' in formatted
        assert 'User-Agent: TestClient/1.0' in formatted
    
    def test_format_post_request_with_body(self):
        """Test formatting a POST request with body."""
        request = HTTPRequest(
            method='POST',
            url='https://api.example.com/api/users',
            headers={
                'Host': 'api.example.com',
                'Content-Type': 'application/json'
            },
            body=b'{"name":"John"}',
            source=RequestSource.REPEATER
        )
        
        formatted = HTTPRequestFormatter.format_http_request(request)
        
        assert 'POST /api/users HTTP/1.1' in formatted
        assert 'Content-Type: application/json' in formatted
        assert '{"name":"John"}' in formatted
    
    def test_format_adds_host_header_if_missing(self):
        """Test that formatter adds Host header if not present."""
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api/users',
            headers={},
            source=RequestSource.REPEATER
        )
        
        formatted = HTTPRequestFormatter.format_http_request(request)
        
        assert 'Host: example.com' in formatted
    
    def test_format_response(self):
        """Test formatting an HTTP response."""
        response = HTTPResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body=b'{"status":"ok"}',
            duration_ms=150
        )
        
        formatted = HTTPRequestFormatter.format_http_response(response)
        
        assert 'HTTP/1.1 200 OK' in formatted
        assert 'Content-Type: application/json' in formatted
        assert '{"status":"ok"}' in formatted


class TestHTTPRequestValidator:
    """Tests for HTTP request validation."""
    
    def test_validate_valid_request(self):
        """Test validation of a valid request."""
        raw = """GET /api/users HTTP/1.1
Host: example.com

"""
        result = HTTPRequestValidator.validate_syntax(raw)
        
        assert result.valid
        assert len(result.errors) == 0
    
    def test_validate_request_without_host(self):
        """Test validation catches missing Host header."""
        raw = """GET /api/users HTTP/1.1
User-Agent: TestClient/1.0

"""
        result = HTTPRequestValidator.validate_syntax(raw)
        
        assert not result.valid
        assert any('Host' in error for error in result.errors)
    
    def test_validate_request_with_invalid_header(self):
        """Test validation catches invalid header format."""
        raw = """GET /api/users HTTP/1.1
Host: example.com
InvalidHeaderWithoutColon

"""
        result = HTTPRequestValidator.validate_syntax(raw)
        
        assert not result.valid
        assert any('Invalid header' in error for error in result.errors)
    
    def test_validate_request_object(self):
        """Test validation of HTTPRequest object."""
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api/users',
            headers={'Host': 'example.com'},
            source=RequestSource.REPEATER
        )
        
        result = HTTPRequestValidator.validate_request(request)
        
        assert result.valid
        assert len(result.errors) == 0
    
    def test_validate_warns_on_get_with_body(self):
        """Test validation warns about GET request with body."""
        request = HTTPRequest(
            method='GET',
            url='https://example.com/api/users',
            headers={'Host': 'example.com'},
            body=b'unexpected body',
            source=RequestSource.REPEATER
        )
        
        result = HTTPRequestValidator.validate_request(request)
        
        assert result.valid  # Still valid, just unusual
        assert len(result.warnings) > 0
        assert any('body' in warning.lower() for warning in result.warnings)


class TestHTTPRequestEditor:
    """Tests for the integrated HTTP request editor."""
    
    def test_editor_parse_and_format_roundtrip(self):
        """Test that parsing and formatting is reversible."""
        editor = HTTPRequestEditor()
        
        original_raw = """POST /api/data HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"key":"value"}"""
        
        # Parse
        request = editor.parse_raw_http(original_raw)
        
        # Format
        formatted = editor.format_http_request(request)
        
        # Parse again
        request2 = editor.parse_raw_http(formatted)
        
        # Should be equivalent
        assert request.method == request2.method
        assert request.url == request2.url
        assert request.body == request2.body
    
    def test_editor_syntax_highlighting(self):
        """Test syntax highlighting generation."""
        editor = HTTPRequestEditor()
        
        raw = """GET /api/users HTTP/1.1
Host: example.com

"""
        highlights = editor.get_syntax_highlights(raw)
        
        # Should have highlights for method, path, version, and headers
        assert len(highlights) > 0
        
        # Check that we have different token types
        token_types = {h[2] for h in highlights}
        assert 'method' in token_types
        assert 'path' in token_types
    
    def test_editor_validates_before_parsing(self):
        """Test that editor can validate before parsing."""
        editor = HTTPRequestEditor()
        
        invalid_raw = """GET /api/users
InvalidHeader

"""
        # Validate first
        result = editor.validate_syntax(invalid_raw)
        assert not result.valid
        
        # Parsing should fail
        with pytest.raises(HTTPParseError):
            editor.parse_raw_http(invalid_raw)
