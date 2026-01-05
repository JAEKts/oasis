"""
Data transformation and encoding/decoding utilities.

Supports URL, HTML, Base64, Hex, ASCII, and Unicode encoding/decoding
with automatic detection and chained operations.
"""

import base64
import binascii
import html
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Union


class EncodingType(Enum):
    """Supported encoding types."""

    URL = "url"
    HTML = "html"
    BASE64 = "base64"
    BASE64_URL = "base64_url"
    HEX = "hex"
    ASCII = "ascii"
    UNICODE = "unicode"
    UTF8 = "utf8"
    UTF16 = "utf16"
    UTF32 = "utf32"


@dataclass
class DecodingResult:
    """Result of an automatic decoding attempt."""

    encoding_type: EncodingType
    decoded_data: str
    confidence: float  # 0.0 to 1.0
    error: Optional[str] = None


class DataTransformer:
    """
    Comprehensive data transformation utility for encoding/decoding operations.

    Supports common encoding schemes used in web applications and provides
    automatic detection and smart decoding capabilities.
    """

    def encode(self, data: str, encoding: EncodingType) -> str:
        """
        Encode data using the specified encoding type.

        Args:
            data: String data to encode
            encoding: Type of encoding to apply

        Returns:
            Encoded string

        Raises:
            ValueError: If encoding fails or encoding type is unsupported
        """
        try:
            if encoding == EncodingType.URL:
                return urllib.parse.quote(data, safe="")

            elif encoding == EncodingType.HTML:
                return html.escape(data)

            elif encoding == EncodingType.BASE64:
                return base64.b64encode(data.encode("utf-8")).decode("ascii")

            elif encoding == EncodingType.BASE64_URL:
                return base64.urlsafe_b64encode(data.encode("utf-8")).decode("ascii")

            elif encoding == EncodingType.HEX:
                return data.encode("utf-8").hex()

            elif encoding == EncodingType.ASCII:
                # Convert to ASCII representation (printable chars only)
                return "".join(c if ord(c) < 128 else f"\\x{ord(c):02x}" for c in data)

            elif encoding == EncodingType.UNICODE:
                # Unicode escape encoding
                return data.encode("unicode-escape").decode("ascii")

            elif encoding == EncodingType.UTF8:
                return data.encode("utf-8").decode("utf-8")

            elif encoding == EncodingType.UTF16:
                return data.encode("utf-16").decode("utf-16")

            elif encoding == EncodingType.UTF32:
                return data.encode("utf-32").decode("utf-32")

            else:
                raise ValueError(f"Unsupported encoding type: {encoding}")

        except Exception as e:
            raise ValueError(f"Encoding failed for {encoding.value}: {str(e)}")

    def decode(self, data: str, encoding: EncodingType) -> str:
        """
        Decode data using the specified encoding type.

        Args:
            data: Encoded string data
            encoding: Type of encoding to decode from

        Returns:
            Decoded string

        Raises:
            ValueError: If decoding fails or encoding type is unsupported
        """
        try:
            if encoding == EncodingType.URL:
                return urllib.parse.unquote(data)

            elif encoding == EncodingType.HTML:
                return html.unescape(data)

            elif encoding == EncodingType.BASE64:
                # Handle padding
                padding = len(data) % 4
                if padding:
                    data += "=" * (4 - padding)
                return base64.b64decode(data).decode("utf-8")

            elif encoding == EncodingType.BASE64_URL:
                # Handle padding
                padding = len(data) % 4
                if padding:
                    data += "=" * (4 - padding)
                return base64.urlsafe_b64decode(data).decode("utf-8")

            elif encoding == EncodingType.HEX:
                return bytes.fromhex(data).decode("utf-8")

            elif encoding == EncodingType.ASCII:
                # Decode ASCII escape sequences
                result = data
                # Handle \xHH sequences
                result = re.sub(
                    r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), result
                )
                return result

            elif encoding == EncodingType.UNICODE:
                # Decode unicode escape sequences
                return data.encode("ascii").decode("unicode-escape")

            elif encoding == EncodingType.UTF8:
                return data.encode("utf-8").decode("utf-8")

            elif encoding == EncodingType.UTF16:
                return data.encode("utf-16").decode("utf-16")

            elif encoding == EncodingType.UTF32:
                return data.encode("utf-32").decode("utf-32")

            else:
                raise ValueError(f"Unsupported encoding type: {encoding}")

        except Exception as e:
            raise ValueError(f"Decoding failed for {encoding.value}: {str(e)}")

    def auto_decode(self, data: Union[str, bytes]) -> List[DecodingResult]:
        """
        Automatically detect and decode data using multiple encoding schemes.

        Attempts to decode the data using various encoding types and returns
        results sorted by confidence level.

        Args:
            data: Data to decode (string or bytes)

        Returns:
            List of DecodingResult objects sorted by confidence (highest first)
        """
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8")
            except UnicodeDecodeError:
                data = data.decode("latin-1")

        results = []

        # Try URL decoding - always try it, even if no % present
        # (some data may be URL-encoded but not change, like alphanumeric chars)
        try:
            decoded = self.decode(data, EncodingType.URL)
            confidence = self._calculate_url_confidence(data, decoded)
            # Only include if there's actual encoding detected or high confidence
            if confidence > 0.2 or "%" in data:
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.URL,
                        decoded_data=decoded,
                        confidence=confidence,
                    )
                )
        except Exception as e:
            results.append(
                DecodingResult(
                    encoding_type=EncodingType.URL,
                    decoded_data="",
                    confidence=0.0,
                    error=str(e),
                )
            )

        # Try HTML decoding
        if "&" in data and ";" in data:
            try:
                decoded = self.decode(data, EncodingType.HTML)
                confidence = self._calculate_html_confidence(data, decoded)
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.HTML,
                        decoded_data=decoded,
                        confidence=confidence,
                    )
                )
            except Exception as e:
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.HTML,
                        decoded_data="",
                        confidence=0.0,
                        error=str(e),
                    )
                )

        # Try Base64 decoding (standard)
        if self._looks_like_base64(data):
            try:
                decoded = self.decode(data, EncodingType.BASE64)
                confidence = self._calculate_base64_confidence(data, decoded)
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.BASE64,
                        decoded_data=decoded,
                        confidence=confidence,
                    )
                )
            except Exception as e:
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.BASE64,
                        decoded_data="",
                        confidence=0.0,
                        error=str(e),
                    )
                )

        # Try Base64 URL-safe decoding
        # URL-safe base64 uses - and _ instead of + and /
        if self._looks_like_base64_url(data):
            try:
                decoded = self.decode(data, EncodingType.BASE64_URL)
                confidence = self._calculate_base64_confidence(data, decoded)
                # Boost confidence if it contains URL-safe chars
                if "-" in data or "_" in data:
                    confidence = min(0.95, confidence + 0.1)
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.BASE64_URL,
                        decoded_data=decoded,
                        confidence=confidence,
                    )
                )
            except Exception as e:
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.BASE64_URL,
                        decoded_data="",
                        confidence=0.0,
                        error=str(e),
                    )
                )

        # Try Hex decoding
        if self._looks_like_hex(data):
            try:
                decoded = self.decode(data, EncodingType.HEX)
                confidence = self._calculate_hex_confidence(data, decoded)
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.HEX,
                        decoded_data=decoded,
                        confidence=confidence,
                    )
                )
            except Exception as e:
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.HEX,
                        decoded_data="",
                        confidence=0.0,
                        error=str(e),
                    )
                )

        # Try Unicode escape decoding
        if "\\u" in data or "\\x" in data:
            try:
                decoded = self.decode(data, EncodingType.UNICODE)
                confidence = self._calculate_unicode_confidence(data, decoded)
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.UNICODE,
                        decoded_data=decoded,
                        confidence=confidence,
                    )
                )
            except Exception as e:
                results.append(
                    DecodingResult(
                        encoding_type=EncodingType.UNICODE,
                        decoded_data="",
                        confidence=0.0,
                        error=str(e),
                    )
                )

        # Sort by confidence (highest first)
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def _looks_like_base64(self, data: str) -> bool:
        """Check if data looks like Base64 encoding."""
        # Remove whitespace
        data = data.strip()
        # Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
        if not re.match(r"^[A-Za-z0-9+/]+=*$", data):
            return False
        # Length should be multiple of 4 (with padding)
        return len(data) % 4 == 0 or "=" in data

    def _looks_like_base64_url(self, data: str) -> bool:
        """Check if data looks like URL-safe Base64 encoding."""
        # Remove whitespace
        data = data.strip()
        # URL-safe Base64 uses A-Z, a-z, 0-9, -, _, and = for padding
        if not re.match(r"^[A-Za-z0-9_-]+=*$", data):
            return False
        # Length should be multiple of 4 (with padding)
        return len(data) % 4 == 0 or "=" in data

    def _looks_like_hex(self, data: str) -> bool:
        """Check if data looks like hexadecimal encoding."""
        # Remove whitespace and common separators
        cleaned = data.replace(" ", "").replace(":", "").replace("-", "")
        # Hex uses only 0-9 and a-f/A-F
        if not re.match(r"^[0-9a-fA-F]+$", cleaned):
            return False
        # Should have even length
        return len(cleaned) % 2 == 0

    def _calculate_url_confidence(self, original: str, decoded: str) -> float:
        """Calculate confidence for URL decoding."""
        if original == decoded:
            # No actual decoding happened - but this is still valid URL encoding
            # (alphanumeric chars don't change when URL encoded)
            # Give it a low but non-zero confidence
            return 0.3
        # Count percent-encoded characters
        percent_count = original.count("%")
        if percent_count == 0:
            return 0.3  # Still valid, just no special chars
        # Higher confidence with more percent-encoded chars
        return min(0.9, 0.5 + (percent_count / len(original)) * 2)

    def _calculate_html_confidence(self, original: str, decoded: str) -> float:
        """Calculate confidence for HTML decoding."""
        if original == decoded:
            return 0.1
        # Count HTML entities
        entity_count = len(re.findall(r"&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;", original))
        if entity_count == 0:
            return 0.1
        return min(0.9, 0.5 + (entity_count / len(original)) * 5)

    def _calculate_base64_confidence(self, original: str, decoded: str) -> float:
        """Calculate confidence for Base64 decoding."""
        # Check if decoded data is printable
        printable_ratio = (
            sum(c.isprintable() for c in decoded) / len(decoded) if decoded else 0
        )
        # Base64 should decode to mostly printable characters
        return printable_ratio * 0.9

    def _calculate_hex_confidence(self, original: str, decoded: str) -> float:
        """Calculate confidence for hex decoding."""
        # Check if decoded data is printable
        printable_ratio = (
            sum(c.isprintable() for c in decoded) / len(decoded) if decoded else 0
        )
        return printable_ratio * 0.85

    def _calculate_unicode_confidence(self, original: str, decoded: str) -> float:
        """Calculate confidence for Unicode escape decoding."""
        if original == decoded:
            return 0.1
        # Count escape sequences
        escape_count = len(re.findall(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", original))
        if escape_count == 0:
            return 0.1
        return min(0.9, 0.5 + (escape_count / len(original)) * 5)


class EncodingChain:
    """
    Manages chained encoding/decoding operations.

    Allows building complex transformation pipelines by chaining multiple
    encoding operations together.
    """

    def __init__(self):
        """Initialize an empty encoding chain."""
        self._steps: List[EncodingType] = []
        self._transformer = DataTransformer()

    def add_step(self, encoding: EncodingType) -> "EncodingChain":
        """
        Add an encoding step to the chain.

        Args:
            encoding: Encoding type to add

        Returns:
            Self for method chaining
        """
        self._steps.append(encoding)
        return self

    def execute(self, data: str) -> str:
        """
        Execute the encoding chain on the input data.

        Applies each encoding step in sequence.

        Args:
            data: Input data to encode

        Returns:
            Encoded data after all steps
        """
        result = data
        for encoding in self._steps:
            result = self._transformer.encode(result, encoding)
        return result

    def reverse(self, data: str) -> str:
        """
        Reverse the encoding chain (decode in reverse order).

        Applies decoding steps in reverse order to undo the encoding chain.

        Args:
            data: Encoded data to decode

        Returns:
            Decoded data after reversing all steps
        """
        result = data
        for encoding in reversed(self._steps):
            result = self._transformer.decode(result, encoding)
        return result

    def clear(self) -> None:
        """Clear all steps from the chain."""
        self._steps.clear()

    def get_steps(self) -> List[EncodingType]:
        """Get the current list of encoding steps."""
        return self._steps.copy()
