"""
Token Analyzer

Main interface for session token analysis and randomness testing.
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from .tests import RandomnessTest, TestResult, RandomnessTestType
from .patterns import PatternDetector, Pattern


@dataclass
class EntropyMetrics:
    """Entropy and randomness metrics for token analysis."""

    shannon_entropy: float
    min_entropy: float
    normalized_entropy: float
    bits_per_character: float
    unique_tokens: int
    total_tokens: int
    uniqueness_ratio: float

    def __post_init__(self):
        """Validate entropy metrics."""
        if self.shannon_entropy < 0:
            raise ValueError("Shannon entropy cannot be negative")
        if not 0 <= self.normalized_entropy <= 1:
            raise ValueError("Normalized entropy must be between 0 and 1")
        if not 0 <= self.uniqueness_ratio <= 1:
            raise ValueError("Uniqueness ratio must be between 0 and 1")


@dataclass
class RandomnessReport:
    """
    Comprehensive randomness analysis report.

    Contains all test results, patterns, entropy metrics, and recommendations
    for token security assessment.
    """

    tokens_analyzed: int
    entropy_metrics: EntropyMetrics
    test_results: List[TestResult]
    patterns: List[Pattern]
    overall_quality: str  # "excellent", "good", "fair", "poor", "critical"
    prediction_probability: Optional[float] = None
    recommendations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate report."""
        valid_qualities = {"excellent", "good", "fair", "poor", "critical"}
        if self.overall_quality not in valid_qualities:
            raise ValueError(f"overall_quality must be one of {valid_qualities}")

        if self.prediction_probability is not None:
            if not 0 <= self.prediction_probability <= 1:
                raise ValueError("prediction_probability must be between 0 and 1")

    @property
    def passed_tests(self) -> int:
        """Number of tests that passed."""
        return sum(1 for result in self.test_results if result.passed)

    @property
    def failed_tests(self) -> int:
        """Number of tests that failed."""
        return sum(1 for result in self.test_results if not result.passed)

    @property
    def high_severity_patterns(self) -> int:
        """Number of high severity patterns detected."""
        return sum(1 for pattern in self.patterns if pattern.severity == "high")


class TokenAnalyzer:
    """
    Main token analysis engine.

    Performs comprehensive analysis of session tokens including:
    - Statistical randomness testing (NIST SP 800-22)
    - Pattern detection
    - Entropy analysis
    - Prediction probability calculation
    """

    def __init__(
        self, significance_level: float = 0.01, min_pattern_confidence: float = 0.7
    ):
        """
        Initialize token analyzer.

        Args:
            significance_level: Significance level for statistical tests
            min_pattern_confidence: Minimum confidence for pattern detection
        """
        self.randomness_test = RandomnessTest(significance_level=significance_level)
        self.pattern_detector = PatternDetector(min_confidence=min_pattern_confidence)

    def analyze_randomness(self, tokens: List[str]) -> RandomnessReport:
        """
        Perform comprehensive randomness analysis on token sequence.

        Args:
            tokens: List of token strings to analyze

        Returns:
            RandomnessReport with complete analysis results
        """
        if not tokens:
            raise ValueError("Token list cannot be empty")

        # Calculate entropy metrics
        entropy_metrics = self.calculate_entropy(tokens)

        # Convert tokens to bits for statistical tests
        bits = self._tokens_to_bits(tokens)

        # Run statistical tests
        test_results = []

        try:
            test_results.append(self.randomness_test.frequency_test(bits))
        except Exception as e:
            # Log but continue with other tests
            pass

        try:
            test_results.append(self.randomness_test.runs_test(bits))
        except Exception as e:
            pass

        try:
            test_results.append(self.randomness_test.longest_run_test(bits))
        except Exception as e:
            pass

        try:
            test_results.append(self.randomness_test.spectral_test(bits))
        except Exception as e:
            pass

        try:
            test_results.append(self.randomness_test.autocorrelation_test(bits, lag=1))
        except Exception as e:
            pass

        # Detect patterns
        patterns = self.detect_patterns(tokens)

        # Calculate overall quality
        overall_quality = self._calculate_overall_quality(
            entropy_metrics, test_results, patterns
        )

        # Calculate prediction probability
        prediction_prob = self._calculate_prediction_probability(
            entropy_metrics, test_results, patterns
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            entropy_metrics, test_results, patterns
        )

        return RandomnessReport(
            tokens_analyzed=len(tokens),
            entropy_metrics=entropy_metrics,
            test_results=test_results,
            patterns=patterns,
            overall_quality=overall_quality,
            prediction_probability=prediction_prob,
            recommendations=recommendations,
            details={
                "bit_length": len(bits),
                "avg_token_length": sum(len(t) for t in tokens) / len(tokens),
            },
        )

    def calculate_entropy(self, tokens: List[str]) -> EntropyMetrics:
        """
        Calculate entropy metrics for token sequence.

        Args:
            tokens: List of token strings

        Returns:
            EntropyMetrics with calculated values
        """
        if not tokens:
            raise ValueError("Token list cannot be empty")

        # Token-level uniqueness
        unique_tokens = len(set(tokens))
        uniqueness_ratio = unique_tokens / len(tokens)

        # Character-level entropy
        all_chars = "".join(tokens)
        if not all_chars:
            raise ValueError("Tokens contain no characters")

        char_counts = Counter(all_chars)
        total_chars = len(all_chars)

        # Shannon entropy
        shannon_entropy = -sum(
            (count / total_chars) * math.log2(count / total_chars)
            for count in char_counts.values()
        )

        # Min entropy (based on most common character)
        max_prob = max(char_counts.values()) / total_chars
        min_entropy = -math.log2(max_prob) if max_prob > 0 else 0

        # Maximum possible entropy
        max_possible_entropy = (
            math.log2(len(char_counts)) if len(char_counts) > 0 else 0
        )

        # Normalized entropy
        normalized_entropy = (
            shannon_entropy / max_possible_entropy if max_possible_entropy > 0 else 0
        )

        # Bits per character
        bits_per_char = shannon_entropy

        return EntropyMetrics(
            shannon_entropy=shannon_entropy,
            min_entropy=min_entropy,
            normalized_entropy=normalized_entropy,
            bits_per_character=bits_per_char,
            unique_tokens=unique_tokens,
            total_tokens=len(tokens),
            uniqueness_ratio=uniqueness_ratio,
        )

    def detect_patterns(self, tokens: List[str]) -> List[Pattern]:
        """
        Detect patterns in token sequence.

        Args:
            tokens: List of token strings

        Returns:
            List of detected patterns
        """
        return self.pattern_detector.detect_patterns(tokens)

    def _tokens_to_bits(self, tokens: List[str]) -> List[int]:
        """
        Convert tokens to binary representation for statistical tests.

        Args:
            tokens: List of token strings

        Returns:
            List of binary values (0 or 1)
        """
        bits = []
        for token in tokens:
            # Convert each character to bits
            for char in token:
                byte_val = ord(char)
                # Take lower 8 bits
                for i in range(8):
                    bits.append((byte_val >> i) & 1)
        return bits

    def _calculate_overall_quality(
        self, entropy: EntropyMetrics, tests: List[TestResult], patterns: List[Pattern]
    ) -> str:
        """Calculate overall quality rating."""
        # Count failures
        failed_tests = sum(1 for t in tests if not t.passed)
        high_severity_patterns = sum(1 for p in patterns if p.severity == "high")

        # Critical: Multiple test failures or high severity patterns
        if failed_tests >= 3 or high_severity_patterns >= 2:
            return "critical"

        # Poor: Some test failures or high severity patterns
        if failed_tests >= 2 or high_severity_patterns >= 1:
            return "poor"

        # Fair: Low entropy or medium severity patterns
        if entropy.normalized_entropy < 0.7 or len(patterns) > 0:
            return "fair"

        # Good: High entropy, most tests pass
        if entropy.normalized_entropy >= 0.8 and failed_tests <= 1:
            return "good"

        # Excellent: High entropy, all tests pass, no patterns
        if (
            entropy.normalized_entropy >= 0.9
            and failed_tests == 0
            and len(patterns) == 0
        ):
            return "excellent"

        return "fair"

    def _calculate_prediction_probability(
        self, entropy: EntropyMetrics, tests: List[TestResult], patterns: List[Pattern]
    ) -> Optional[float]:
        """
        Calculate probability of successfully predicting next token.

        Based on entropy, test results, and detected patterns.
        """
        # Base probability from entropy
        if entropy.normalized_entropy >= 0.9:
            base_prob = 0.001  # Very low
        elif entropy.normalized_entropy >= 0.7:
            base_prob = 0.01
        elif entropy.normalized_entropy >= 0.5:
            base_prob = 0.1
        else:
            base_prob = 0.5

        # Adjust for test failures
        failed_tests = sum(1 for t in tests if not t.passed)
        test_multiplier = 1.0 + (failed_tests * 0.2)

        # Adjust for patterns
        pattern_multiplier = 1.0
        for pattern in patterns:
            if pattern.severity == "high":
                pattern_multiplier *= 2.0
            elif pattern.severity == "medium":
                pattern_multiplier *= 1.5

        # Calculate final probability
        prediction_prob = min(base_prob * test_multiplier * pattern_multiplier, 1.0)

        return prediction_prob

    def _generate_recommendations(
        self, entropy: EntropyMetrics, tests: List[TestResult], patterns: List[Pattern]
    ) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        # Entropy-based recommendations
        if entropy.normalized_entropy < 0.7:
            recommendations.append(
                "Low entropy detected. Use a cryptographically secure random number generator (CSPRNG)."
            )

        if entropy.uniqueness_ratio < 0.95:
            recommendations.append(
                f"Token uniqueness is low ({entropy.uniqueness_ratio:.1%}). "
                "Ensure tokens are generated with sufficient randomness."
            )

        # Test-based recommendations
        failed_tests = [t for t in tests if not t.passed]
        if failed_tests:
            test_names = ", ".join(t.test_type.value for t in failed_tests)
            recommendations.append(
                f"Failed randomness tests: {test_names}. "
                "Review token generation algorithm for statistical weaknesses."
            )

        # Pattern-based recommendations
        for pattern in patterns:
            if pattern.pattern_type.value == "sequential":
                recommendations.append(
                    "Sequential patterns detected. Avoid using counters or timestamps in token generation."
                )
            elif pattern.pattern_type.value == "timestamp":
                recommendations.append(
                    "Timestamp-based tokens detected. Timestamps are predictable and should not be used."
                )
            elif pattern.pattern_type.value == "charset_limited":
                recommendations.append(
                    "Limited character set detected. Use full alphanumeric + special characters for tokens."
                )
            elif pattern.pattern_type.value == "repeating":
                recommendations.append(
                    "Repeating tokens detected. Ensure each token is generated independently."
                )

        # General recommendations
        if not recommendations:
            recommendations.append(
                "Token randomness appears adequate. Continue monitoring for any changes in generation patterns."
            )

        return recommendations
