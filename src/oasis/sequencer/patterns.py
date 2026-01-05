"""
Token Pattern Detection

Detects patterns and weaknesses in token sequences.
"""

import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set


class PatternType(str, Enum):
    """Types of patterns that can be detected."""

    SEQUENTIAL = "sequential"
    REPEATING = "repeating"
    TIMESTAMP = "timestamp"
    PREDICTABLE = "predictable"
    LOW_ENTROPY = "low_entropy"
    CHARSET_LIMITED = "charset_limited"


@dataclass
class Pattern:
    """Detected pattern in token sequence."""

    pattern_type: PatternType
    description: str
    severity: str  # "high", "medium", "low"
    evidence: List[str]
    confidence: float  # 0.0 to 1.0

    def __post_init__(self):
        """Validate pattern."""
        if not 0 <= self.confidence <= 1:
            raise ValueError(
                f"Confidence must be between 0 and 1, got {self.confidence}"
            )
        if self.severity not in ("high", "medium", "low"):
            raise ValueError(
                f"Severity must be high, medium, or low, got {self.severity}"
            )


class PatternDetector:
    """
    Detects patterns and weaknesses in token sequences.

    Analyzes tokens for common weaknesses like sequential values,
    timestamp-based generation, limited character sets, and predictable patterns.
    """

    def __init__(self, min_confidence: float = 0.7):
        """
        Initialize pattern detector.

        Args:
            min_confidence: Minimum confidence threshold for reporting patterns
        """
        if not 0 < min_confidence <= 1:
            raise ValueError("min_confidence must be between 0 and 1")
        self.min_confidence = min_confidence

    def detect_patterns(self, tokens: List[str]) -> List[Pattern]:
        """
        Detect all patterns in token sequence.

        Args:
            tokens: List of token strings

        Returns:
            List of detected patterns
        """
        if not tokens:
            return []

        patterns = []

        # Check for sequential patterns
        sequential = self._detect_sequential(tokens)
        if sequential and sequential.confidence >= self.min_confidence:
            patterns.append(sequential)

        # Check for repeating patterns
        repeating = self._detect_repeating(tokens)
        if repeating and repeating.confidence >= self.min_confidence:
            patterns.append(repeating)

        # Check for timestamp-based tokens
        timestamp = self._detect_timestamp(tokens)
        if timestamp and timestamp.confidence >= self.min_confidence:
            patterns.append(timestamp)

        # Check for limited character set
        charset = self._detect_limited_charset(tokens)
        if charset and charset.confidence >= self.min_confidence:
            patterns.append(charset)

        # Check for low entropy
        low_entropy = self._detect_low_entropy(tokens)
        if low_entropy and low_entropy.confidence >= self.min_confidence:
            patterns.append(low_entropy)

        return patterns

    def _detect_sequential(self, tokens: List[str]) -> Optional[Pattern]:
        """Detect sequential numeric patterns."""
        if len(tokens) < 3:
            return None

        # Try to extract numeric parts
        numeric_parts = []
        for token in tokens:
            # Extract all numbers from token
            numbers = re.findall(r"\d+", token)
            if numbers:
                numeric_parts.append(int(numbers[0]))
            else:
                numeric_parts.append(None)

        # Check for sequential increments
        sequential_count = 0
        total_comparisons = 0

        for i in range(len(numeric_parts) - 1):
            if numeric_parts[i] is not None and numeric_parts[i + 1] is not None:
                total_comparisons += 1
                diff = numeric_parts[i + 1] - numeric_parts[i]
                if diff == 1:
                    sequential_count += 1

        if total_comparisons == 0:
            return None

        confidence = sequential_count / total_comparisons

        if confidence < 0.5:
            return None

        evidence = [
            f"{tokens[i]} -> {tokens[i+1]}" for i in range(min(3, len(tokens) - 1))
        ]

        return Pattern(
            pattern_type=PatternType.SEQUENTIAL,
            description=f"Tokens contain sequential numeric values ({sequential_count}/{total_comparisons} sequential)",
            severity="high",
            evidence=evidence,
            confidence=confidence,
        )

    def _detect_repeating(self, tokens: List[str]) -> Optional[Pattern]:
        """Detect repeating token patterns."""
        if len(tokens) < 4:
            return None

        # Check for exact duplicates
        counter = Counter(tokens)
        duplicates = {token: count for token, count in counter.items() if count > 1}

        if not duplicates:
            return None

        duplicate_ratio = sum(duplicates.values()) / len(tokens)

        if duplicate_ratio < 0.1:
            return None

        evidence = [
            f"'{token}' appears {count} times"
            for token, count in list(duplicates.items())[:3]
        ]

        severity = "high" if duplicate_ratio > 0.3 else "medium"

        return Pattern(
            pattern_type=PatternType.REPEATING,
            description=f"{len(duplicates)} tokens repeat ({duplicate_ratio:.1%} of total)",
            severity=severity,
            evidence=evidence,
            confidence=min(duplicate_ratio * 2, 1.0),
        )

    def _detect_timestamp(self, tokens: List[str]) -> Optional[Pattern]:
        """Detect timestamp-based token generation."""
        if len(tokens) < 3:
            return None

        # Common timestamp patterns
        timestamp_patterns = [
            r"\d{10}",  # Unix timestamp (seconds)
            r"\d{13}",  # Unix timestamp (milliseconds)
            r"\d{4}-\d{2}-\d{2}",  # ISO date
            r"\d{8}",  # YYYYMMDD
        ]

        matches = 0
        for token in tokens:
            for pattern in timestamp_patterns:
                if re.search(pattern, token):
                    matches += 1
                    break

        confidence = matches / len(tokens)

        if confidence < 0.5:
            return None

        evidence = [token for token in tokens[:3]]

        return Pattern(
            pattern_type=PatternType.TIMESTAMP,
            description=f"Tokens appear to contain timestamps ({matches}/{len(tokens)} match patterns)",
            severity="high",
            evidence=evidence,
            confidence=confidence,
        )

    def _detect_limited_charset(self, tokens: List[str]) -> Optional[Pattern]:
        """Detect limited character set usage."""
        if not tokens:
            return None

        # Combine all tokens to analyze character set
        all_chars = "".join(tokens)
        unique_chars = set(all_chars)

        # Expected character sets
        lowercase = set("abcdefghijklmnopqrstuvwxyz")
        uppercase = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        digits = set("0123456789")
        special = set("!@#$%^&*()_+-=[]{}|;:,.<>?/")

        # Calculate coverage
        has_lowercase = bool(unique_chars & lowercase)
        has_uppercase = bool(unique_chars & uppercase)
        has_digits = bool(unique_chars & digits)
        has_special = bool(unique_chars & special)

        charset_diversity = sum([has_lowercase, has_uppercase, has_digits, has_special])

        if charset_diversity >= 3:
            return None

        # Calculate confidence based on how limited the charset is
        confidence = 1.0 - (charset_diversity / 4.0)

        charset_desc = []
        if has_lowercase:
            charset_desc.append("lowercase")
        if has_uppercase:
            charset_desc.append("uppercase")
        if has_digits:
            charset_desc.append("digits")
        if has_special:
            charset_desc.append("special")

        severity = "high" if charset_diversity <= 1 else "medium"

        return Pattern(
            pattern_type=PatternType.CHARSET_LIMITED,
            description=f"Limited character set: only {', '.join(charset_desc)} ({len(unique_chars)} unique chars)",
            severity=severity,
            evidence=[
                f"Unique characters: {len(unique_chars)}",
                f"Character sets: {charset_diversity}/4",
            ],
            confidence=confidence,
        )

    def _detect_low_entropy(self, tokens: List[str]) -> Optional[Pattern]:
        """Detect low entropy in token sequence."""
        if not tokens:
            return None

        # Calculate average token length
        avg_length = sum(len(token) for token in tokens) / len(tokens)

        # Calculate character frequency entropy
        all_chars = "".join(tokens)
        if not all_chars:
            return None

        char_counts = Counter(all_chars)
        total_chars = len(all_chars)

        # Shannon entropy
        import math

        entropy = -sum(
            (count / total_chars) * math.log2(count / total_chars)
            for count in char_counts.values()
        )

        # Maximum possible entropy for the character set
        max_entropy = math.log2(len(char_counts))

        # Normalized entropy (0 to 1)
        if max_entropy == 0:
            normalized_entropy = 0
        else:
            normalized_entropy = entropy / max_entropy

        # Low entropy threshold
        if normalized_entropy > 0.7:
            return None

        confidence = 1.0 - normalized_entropy
        severity = "high" if normalized_entropy < 0.5 else "medium"

        return Pattern(
            pattern_type=PatternType.LOW_ENTROPY,
            description=f"Low entropy detected: {entropy:.2f} bits/char (normalized: {normalized_entropy:.2f})",
            severity=severity,
            evidence=[
                f"Average token length: {avg_length:.1f}",
                f"Unique characters: {len(char_counts)}",
                f"Entropy: {entropy:.2f} bits/char",
            ],
            confidence=confidence,
        )
