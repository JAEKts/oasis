"""
Hash generation and binary analysis utilities.

Provides MD5, SHA1, SHA256, HMAC hash generation and hex dump capabilities
for binary data analysis.
"""

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union


class HashAlgorithm(Enum):
    """Supported hash algorithms."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


@dataclass
class HashResult:
    """Result of a hash operation."""

    algorithm: HashAlgorithm
    hash_hex: str
    hash_bytes: bytes


class Hasher:
    """
    Hash generation utility for security testing.

    Provides common hash algorithms used in web applications including
    MD5, SHA1, SHA256, and HMAC variants.
    """

    def hash_data(
        self, data: Union[str, bytes], algorithm: HashAlgorithm
    ) -> HashResult:
        """
        Generate a hash of the input data.

        Args:
            data: Data to hash (string or bytes)
            algorithm: Hash algorithm to use

        Returns:
            HashResult containing the hash in hex and bytes format

        Raises:
            ValueError: If algorithm is unsupported
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode("utf-8")

        # Get the appropriate hash function
        if algorithm == HashAlgorithm.MD5:
            hasher = hashlib.md5()
        elif algorithm == HashAlgorithm.SHA1:
            hasher = hashlib.sha1()
        elif algorithm == HashAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif algorithm == HashAlgorithm.SHA384:
            hasher = hashlib.sha384()
        elif algorithm == HashAlgorithm.SHA512:
            hasher = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        # Compute the hash
        hasher.update(data)
        hash_bytes = hasher.digest()
        hash_hex = hash_bytes.hex()

        return HashResult(algorithm=algorithm, hash_hex=hash_hex, hash_bytes=hash_bytes)

    def hmac_hash(
        self,
        data: Union[str, bytes],
        key: Union[str, bytes],
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> HashResult:
        """
        Generate an HMAC hash of the input data.

        Args:
            data: Data to hash
            key: Secret key for HMAC
            algorithm: Hash algorithm to use (default: SHA256)

        Returns:
            HashResult containing the HMAC hash

        Raises:
            ValueError: If algorithm is unsupported
        """
        # Convert strings to bytes if needed
        if isinstance(data, str):
            data = data.encode("utf-8")
        if isinstance(key, str):
            key = key.encode("utf-8")

        # Get the appropriate hash function name
        if algorithm == HashAlgorithm.MD5:
            digestmod = hashlib.md5
        elif algorithm == HashAlgorithm.SHA1:
            digestmod = hashlib.sha1
        elif algorithm == HashAlgorithm.SHA256:
            digestmod = hashlib.sha256
        elif algorithm == HashAlgorithm.SHA384:
            digestmod = hashlib.sha384
        elif algorithm == HashAlgorithm.SHA512:
            digestmod = hashlib.sha512
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        # Compute HMAC
        hmac_obj = hmac.new(key, data, digestmod)
        hash_bytes = hmac_obj.digest()
        hash_hex = hash_bytes.hex()

        return HashResult(algorithm=algorithm, hash_hex=hash_hex, hash_bytes=hash_bytes)

    def verify_hash(
        self, data: Union[str, bytes], expected_hash: str, algorithm: HashAlgorithm
    ) -> bool:
        """
        Verify that data matches an expected hash.

        Args:
            data: Data to verify
            expected_hash: Expected hash value (hex string)
            algorithm: Hash algorithm used

        Returns:
            True if hash matches, False otherwise
        """
        result = self.hash_data(data, algorithm)
        return result.hash_hex.lower() == expected_hash.lower()

    def compare_hashes(self, hash1: str, hash2: str) -> bool:
        """
        Compare two hash values (case-insensitive).

        Args:
            hash1: First hash (hex string)
            hash2: Second hash (hex string)

        Returns:
            True if hashes match, False otherwise
        """
        return hash1.lower() == hash2.lower()


@dataclass
class HexDumpLine:
    """A single line of hex dump output."""

    offset: int
    hex_bytes: str
    ascii_repr: str


class BinaryAnalyzer:
    """
    Binary data analysis utility.

    Provides hex dump and binary analysis capabilities for examining
    binary data in HTTP requests/responses.
    """

    def hex_dump(
        self,
        data: bytes,
        bytes_per_line: int = 16,
        show_offset: bool = True,
        show_ascii: bool = True,
    ) -> str:
        """
        Generate a hex dump of binary data.

        Args:
            data: Binary data to dump
            bytes_per_line: Number of bytes per line (default: 16)
            show_offset: Whether to show byte offsets (default: True)
            show_ascii: Whether to show ASCII representation (default: True)

        Returns:
            Formatted hex dump string
        """
        lines = []

        for i in range(0, len(data), bytes_per_line):
            chunk = data[i : i + bytes_per_line]

            # Build the line
            parts = []

            # Offset
            if show_offset:
                parts.append(f"{i:08x}")

            # Hex bytes
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # Pad if last line is short
            if len(chunk) < bytes_per_line:
                hex_part += "   " * (bytes_per_line - len(chunk))
            parts.append(hex_part)

            # ASCII representation
            if show_ascii:
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                parts.append(f"|{ascii_part}|")

            lines.append("  ".join(parts))

        return "\n".join(lines)

    def analyze_binary(self, data: bytes) -> dict:
        """
        Analyze binary data and return statistics.

        Args:
            data: Binary data to analyze

        Returns:
            Dictionary containing analysis results:
            - size: Total size in bytes
            - printable_ratio: Ratio of printable ASCII characters
            - null_bytes: Number of null bytes
            - entropy: Approximate entropy (0.0 to 8.0)
            - has_high_entropy: Whether entropy suggests encryption/compression
        """
        if not data:
            return {
                "size": 0,
                "printable_ratio": 0.0,
                "null_bytes": 0,
                "entropy": 0.0,
                "has_high_entropy": False,
            }

        size = len(data)

        # Count printable characters
        printable_count = sum(1 for b in data if 32 <= b < 127)
        printable_ratio = printable_count / size

        # Count null bytes
        null_bytes = data.count(0)

        # Calculate approximate entropy
        entropy = self._calculate_entropy(data)

        # High entropy suggests encryption or compression (> 7.0 is suspicious)
        has_high_entropy = entropy > 7.0

        return {
            "size": size,
            "printable_ratio": printable_ratio,
            "null_bytes": null_bytes,
            "entropy": entropy,
            "has_high_entropy": has_high_entropy,
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of binary data.

        Args:
            data: Binary data

        Returns:
            Entropy value (0.0 to 8.0 for bytes)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1

        # Calculate Shannon entropy
        import math

        entropy = 0.0
        size = len(data)

        for count in frequencies:
            if count > 0:
                probability = count / size
                entropy -= probability * math.log2(probability)

        return entropy

    def find_strings(
        self, data: bytes, min_length: int = 4, encoding: str = "ascii"
    ) -> list[str]:
        """
        Extract printable strings from binary data.

        Args:
            data: Binary data to search
            min_length: Minimum string length to extract (default: 4)
            encoding: Character encoding to use (default: 'ascii')

        Returns:
            List of extracted strings
        """
        strings = []
        current_string = []

        for byte in data:
            # Check if byte is printable
            if 32 <= byte < 127:
                current_string.append(chr(byte))
            else:
                # End of string
                if len(current_string) >= min_length:
                    strings.append("".join(current_string))
                current_string = []

        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append("".join(current_string))

        return strings

    def compare_binary(self, data1: bytes, data2: bytes) -> dict:
        """
        Compare two binary data blobs and find differences.

        Args:
            data1: First binary data
            data2: Second binary data

        Returns:
            Dictionary containing comparison results:
            - size_diff: Difference in size
            - identical: Whether data is identical
            - diff_positions: List of byte positions that differ
            - similarity_ratio: Ratio of matching bytes (0.0 to 1.0)
        """
        size1 = len(data1)
        size2 = len(data2)
        size_diff = size2 - size1

        # Check if identical
        if data1 == data2:
            return {
                "size_diff": 0,
                "identical": True,
                "diff_positions": [],
                "similarity_ratio": 1.0,
            }

        # Find differing positions
        diff_positions = []
        min_size = min(size1, size2)

        for i in range(min_size):
            if data1[i] != data2[i]:
                diff_positions.append(i)

        # Add positions for size difference
        if size1 != size2:
            for i in range(min_size, max(size1, size2)):
                diff_positions.append(i)

        # Calculate similarity ratio
        matching_bytes = min_size - len([p for p in diff_positions if p < min_size])
        max_size = max(size1, size2)
        similarity_ratio = matching_bytes / max_size if max_size > 0 else 0.0

        return {
            "size_diff": size_diff,
            "identical": False,
            "diff_positions": diff_positions,
            "similarity_ratio": similarity_ratio,
        }
