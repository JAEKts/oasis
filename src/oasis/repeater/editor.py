"""
HTTP Request Editor with Parsing, Formatting, and Validation

Provides raw HTTP request parsing, formatting, and syntax validation.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from ..core.models import HTTPRequest, HTTPResponse, RequestSource
from ..core.exceptions import OASISException


class HTTPParseError(OASISException):
    """Exception raised when HTTP request parsing fails."""

    pass


class HTTPValidationError(OASISException):
    """Exception raised when HTTP request validation fails."""

    pass


class ValidationResult:
    """Result of HTTP request validation."""

    def __init__(
        self,
        valid: bool,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
    ):
        self.valid = valid
        self.errors = errors or []
        self.warnings = warnings or []

    def __bool__(self) -> bool:
        return self.valid

    def __repr__(self) -> str:
        if self.valid:
            return f"ValidationResult(valid=True, warnings={len(self.warnings)})"
        return f"ValidationResult(valid=False, errors={len(self.errors)})"


class HTTPRequestParser:
    """Parser for raw HTTP requests."""

    @staticmethod
    def parse_raw_http(raw: str) -> HTTPRequest:
        """
        Parse a raw HTTP request string into an HTTPRequest object.

        Args:
            raw: Raw HTTP request string

        Returns:
            HTTPRequest object

        Raises:
            HTTPParseError: If parsing fails
        """
        if not raw or not raw.strip():
            raise HTTPParseError("Empty request")

        lines = raw.split("\n")
        if not lines:
            raise HTTPParseError("No lines in request")

        # Parse request line
        request_line = lines[0].strip()
        if not request_line:
            raise HTTPParseError("Empty request line")

        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            raise HTTPParseError(f"Invalid request line: {request_line}")

        method = parts[0].upper()
        path = parts[1]

        # Parse headers
        headers: Dict[str, str] = {}
        body_start = 1

        for i, line in enumerate(lines[1:], start=1):
            line = line.rstrip("\r")

            # Empty line indicates end of headers
            if not line:
                body_start = i + 1
                break

            # Parse header
            if ":" not in line:
                raise HTTPParseError(f"Invalid header line: {line}")

            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

        # Extract host and construct URL
        host = headers.get("Host", "")
        if not host:
            raise HTTPParseError("Missing Host header")

        # Determine scheme
        scheme = "https" if ":443" in host or not ":" in host else "http"
        url = f"{scheme}://{host}{path}"

        # Parse body
        body: Optional[bytes] = None
        if body_start < len(lines):
            body_lines = lines[body_start:]
            body_str = "\n".join(body_lines)
            if body_str.strip():
                body = body_str.encode("utf-8")

        return HTTPRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            source=RequestSource.REPEATER,
        )

    @staticmethod
    def parse_request_line(line: str) -> Tuple[str, str, str]:
        """
        Parse HTTP request line.

        Args:
            line: Request line (e.g., "GET /path HTTP/1.1")

        Returns:
            Tuple of (method, path, version)

        Raises:
            HTTPParseError: If parsing fails
        """
        parts = line.strip().split(" ", 2)
        if len(parts) < 2:
            raise HTTPParseError(f"Invalid request line: {line}")

        method = parts[0].upper()
        path = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        return method, path, version


class HTTPRequestFormatter:
    """Formatter for HTTP requests."""

    @staticmethod
    def format_http_request(request: HTTPRequest, include_body: bool = True) -> str:
        """
        Format an HTTPRequest object as a raw HTTP request string.

        Args:
            request: HTTPRequest object to format
            include_body: Whether to include the request body

        Returns:
            Formatted raw HTTP request string
        """
        # Parse URL to extract path and query
        parsed = urlparse(request.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Build request line
        lines = [f"{request.method} {path} HTTP/1.1"]

        # Add Host header if not present
        headers = dict(request.headers)
        if "Host" not in headers:
            host = parsed.netloc
            headers["Host"] = host

        # Add headers
        for key, value in headers.items():
            lines.append(f"{key}: {value}")

        # Add empty line to separate headers from body
        lines.append("")

        # Add body if present
        if include_body and request.body:
            try:
                body_str = request.body.decode("utf-8")
                lines.append(body_str)
            except UnicodeDecodeError:
                lines.append(f"<binary data: {len(request.body)} bytes>")

        return "\n".join(lines)

    @staticmethod
    def format_http_response(response: HTTPResponse, include_body: bool = True) -> str:
        """
        Format an HTTPResponse object as a raw HTTP response string.

        Args:
            response: HTTPResponse object to format
            include_body: Whether to include the response body

        Returns:
            Formatted raw HTTP response string
        """
        # Build status line
        status_text = HTTPRequestFormatter._get_status_text(response.status_code)
        lines = [f"HTTP/1.1 {response.status_code} {status_text}"]

        # Add headers
        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")

        # Add empty line to separate headers from body
        lines.append("")

        # Add body if present
        if include_body and response.body:
            try:
                body_str = response.body.decode("utf-8")
                lines.append(body_str)
            except UnicodeDecodeError:
                lines.append(f"<binary data: {len(response.body)} bytes>")

        return "\n".join(lines)

    @staticmethod
    def _get_status_text(status_code: int) -> str:
        """Get HTTP status text for a status code."""
        status_texts = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_texts.get(status_code, "Unknown")


class HTTPRequestValidator:
    """Validator for HTTP requests."""

    @staticmethod
    def validate_syntax(raw: str) -> ValidationResult:
        """
        Validate the syntax of a raw HTTP request.

        Args:
            raw: Raw HTTP request string

        Returns:
            ValidationResult with validation status and any errors/warnings
        """
        errors: List[str] = []
        warnings: List[str] = []

        if not raw or not raw.strip():
            errors.append("Empty request")
            return ValidationResult(False, errors, warnings)

        lines = raw.split("\n")

        # Validate request line
        if not lines:
            errors.append("No lines in request")
            return ValidationResult(False, errors, warnings)

        request_line = lines[0].strip()
        if not request_line:
            errors.append("Empty request line")
            return ValidationResult(False, errors, warnings)

        parts = request_line.split(" ")
        if len(parts) < 2:
            errors.append(f"Invalid request line format: {request_line}")
        else:
            method = parts[0].upper()
            valid_methods = {
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "HEAD",
                "OPTIONS",
                "PATCH",
                "TRACE",
                "CONNECT",
            }
            if method not in valid_methods:
                warnings.append(f"Non-standard HTTP method: {method}")

        # Validate headers
        has_host = False
        header_section = True

        for i, line in enumerate(lines[1:], start=1):
            line = line.rstrip("\r")

            # Empty line indicates end of headers
            if not line:
                header_section = False
                continue

            if header_section:
                if ":" not in line:
                    errors.append(f"Invalid header format at line {i + 1}: {line}")
                else:
                    key, _ = line.split(":", 1)
                    if key.strip().lower() == "host":
                        has_host = True

        if not has_host:
            errors.append("Missing required Host header")

        # Return validation result
        valid = len(errors) == 0
        return ValidationResult(valid, errors, warnings)

    @staticmethod
    def validate_request(request: HTTPRequest) -> ValidationResult:
        """
        Validate an HTTPRequest object.

        Args:
            request: HTTPRequest object to validate

        Returns:
            ValidationResult with validation status and any errors/warnings
        """
        errors: List[str] = []
        warnings: List[str] = []

        # Validate method
        valid_methods = {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "TRACE",
            "CONNECT",
        }
        if request.method.upper() not in valid_methods:
            warnings.append(f"Non-standard HTTP method: {request.method}")

        # Validate URL
        try:
            parsed = urlparse(request.url)
            if not parsed.scheme:
                errors.append("URL missing scheme (http/https)")
            if not parsed.netloc:
                errors.append("URL missing host")
        except Exception as e:
            errors.append(f"Invalid URL: {e}")

        # Validate headers
        if "Host" not in request.headers:
            warnings.append("Missing Host header (will be auto-generated)")

        # Validate body for methods that typically don't have bodies
        if request.method.upper() in {"GET", "HEAD", "DELETE"} and request.body:
            warnings.append(f"{request.method} request with body (unusual but allowed)")

        # Return validation result
        valid = len(errors) == 0
        return ValidationResult(valid, errors, warnings)


class HTTPRequestEditor:
    """
    HTTP Request Editor with parsing, formatting, and validation.

    Provides a high-level interface for editing HTTP requests with
    syntax highlighting support and validation.
    """

    def __init__(self):
        self.parser = HTTPRequestParser()
        self.formatter = HTTPRequestFormatter()
        self.validator = HTTPRequestValidator()

    def parse_raw_http(self, raw: str) -> HTTPRequest:
        """Parse raw HTTP request string."""
        return self.parser.parse_raw_http(raw)

    def format_http_request(
        self, request: HTTPRequest, include_body: bool = True
    ) -> str:
        """Format HTTPRequest as raw HTTP string."""
        return self.formatter.format_http_request(request, include_body)

    def format_http_response(
        self, response: HTTPResponse, include_body: bool = True
    ) -> str:
        """Format HTTPResponse as raw HTTP string."""
        return self.formatter.format_http_response(response, include_body)

    def validate_syntax(self, raw: str) -> ValidationResult:
        """Validate raw HTTP request syntax."""
        return self.validator.validate_syntax(raw)

    def validate_request(self, request: HTTPRequest) -> ValidationResult:
        """Validate HTTPRequest object."""
        return self.validator.validate_request(request)

    def get_syntax_highlights(self, raw: str) -> List[Tuple[int, int, str]]:
        """
        Get syntax highlighting information for raw HTTP request.

        Args:
            raw: Raw HTTP request string

        Returns:
            List of (start_pos, end_pos, token_type) tuples
        """
        highlights: List[Tuple[int, int, str]] = []
        lines = raw.split("\n")
        pos = 0

        if not lines:
            return highlights

        # Highlight request line
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if parts:
            # Method
            highlights.append((pos, pos + len(parts[0]), "method"))
            pos += len(parts[0]) + 1

            if len(parts) > 1:
                # Path
                highlights.append((pos, pos + len(parts[1]), "path"))
                pos += len(parts[1]) + 1

                if len(parts) > 2:
                    # Version
                    highlights.append((pos, pos + len(parts[2]), "version"))

        pos = len(request_line) + 1

        # Highlight headers
        for line in lines[1:]:
            if not line.strip():
                pos += len(line) + 1
                break

            if ":" in line:
                key, value = line.split(":", 1)
                # Header name
                highlights.append((pos, pos + len(key), "header_name"))
                pos += len(key) + 1
                # Header value
                highlights.append((pos, pos + len(value), "header_value"))
                pos += len(value) + 1
            else:
                pos += len(line) + 1

        # Body is everything after headers
        if pos < len(raw):
            highlights.append((pos, len(raw), "body"))

        return highlights
