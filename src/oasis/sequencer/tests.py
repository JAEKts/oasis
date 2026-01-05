"""
Statistical Randomness Tests

Implements NIST SP 800-22 randomness test suite and other statistical tests.
"""

import math
from collections import Counter
from enum import Enum
from typing import List, Tuple
from dataclasses import dataclass

import numpy as np
from scipy import stats, special


class RandomnessTestType(str, Enum):
    """Types of randomness tests."""

    FREQUENCY = "frequency"
    RUNS = "runs"
    LONGEST_RUN = "longest_run"
    SPECTRAL = "spectral"
    CHI_SQUARE = "chi_square"
    AUTOCORRELATION = "autocorrelation"


@dataclass
class TestResult:
    """Result of a randomness test."""

    test_type: RandomnessTestType
    p_value: float
    passed: bool
    statistic: float
    details: dict

    def __post_init__(self):
        """Validate test result."""
        if not 0 <= self.p_value <= 1:
            raise ValueError(f"p_value must be between 0 and 1, got {self.p_value}")


class RandomnessTest:
    """
    Statistical randomness testing framework.

    Implements tests from NIST SP 800-22 and additional statistical tests
    for analyzing token randomness and cryptographic quality.
    """

    def __init__(self, significance_level: float = 0.01):
        """
        Initialize randomness test framework.

        Args:
            significance_level: Significance level for hypothesis testing (default 0.01)
        """
        if not 0 < significance_level < 1:
            raise ValueError("Significance level must be between 0 and 1")
        self.significance_level = significance_level

    def frequency_test(self, bits: List[int]) -> TestResult:
        """
        Frequency (Monobit) Test.

        Tests whether the number of ones and zeros in a sequence are approximately equal.

        Args:
            bits: List of binary values (0 or 1)

        Returns:
            TestResult with p-value and pass/fail status
        """
        if not bits:
            raise ValueError("Bit sequence cannot be empty")

        if not all(b in (0, 1) for b in bits):
            raise ValueError("Bits must be 0 or 1")

        n = len(bits)
        # Sum of bits (number of 1s)
        s = sum(bits)
        # Test statistic
        s_obs = abs(s - n / 2) / math.sqrt(n / 4)
        # P-value using complementary error function
        p_value = special.erfc(s_obs / math.sqrt(2))

        return TestResult(
            test_type=RandomnessTestType.FREQUENCY,
            p_value=p_value,
            passed=p_value >= self.significance_level,
            statistic=s_obs,
            details={"ones": s, "zeros": n - s, "expected_ones": n / 2, "n": n},
        )

    def runs_test(self, bits: List[int]) -> TestResult:
        """
        Runs Test.

        Tests whether the number of runs (uninterrupted sequences of identical bits)
        is as expected for a random sequence.

        Args:
            bits: List of binary values (0 or 1)

        Returns:
            TestResult with p-value and pass/fail status
        """
        if not bits:
            raise ValueError("Bit sequence cannot be empty")

        if not all(b in (0, 1) for b in bits):
            raise ValueError("Bits must be 0 or 1")

        n = len(bits)

        # Pre-test: proportion of ones
        pi = sum(bits) / n
        tau = 2 / math.sqrt(n)

        if abs(pi - 0.5) >= tau:
            # Sequence is not random enough for runs test
            return TestResult(
                test_type=RandomnessTestType.RUNS,
                p_value=0.0,
                passed=False,
                statistic=float("inf"),
                details={
                    "pi": pi,
                    "tau": tau,
                    "reason": "Failed pre-test: proportion of ones too far from 0.5",
                },
            )

        # Count runs
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i - 1]:
                runs += 1

        # Expected number of runs
        expected_runs = (2 * n * pi * (1 - pi)) + 1

        # Test statistic
        numerator = abs(runs - expected_runs)
        denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)

        if denominator == 0:
            statistic = float("inf")
            p_value = 0.0
        else:
            statistic = numerator / denominator
            p_value = special.erfc(statistic / math.sqrt(2))

        return TestResult(
            test_type=RandomnessTestType.RUNS,
            p_value=p_value,
            passed=p_value >= self.significance_level,
            statistic=statistic,
            details={"runs": runs, "expected_runs": expected_runs, "pi": pi, "n": n},
        )

    def longest_run_test(self, bits: List[int]) -> TestResult:
        """
        Longest Run of Ones Test.

        Tests whether the length of the longest run of ones is consistent
        with that of a random sequence.

        Args:
            bits: List of binary values (0 or 1)

        Returns:
            TestResult with p-value and pass/fail status
        """
        if not bits:
            raise ValueError("Bit sequence cannot be empty")

        if not all(b in (0, 1) for b in bits):
            raise ValueError("Bits must be 0 or 1")

        n = len(bits)

        # Determine block size and parameters based on sequence length
        if n < 128:
            return TestResult(
                test_type=RandomnessTestType.LONGEST_RUN,
                p_value=0.0,
                passed=False,
                statistic=0.0,
                details={"reason": "Sequence too short (minimum 128 bits)"},
            )
        elif n < 6272:
            m = 8
            k = 3
            v = [1, 2, 3, 4]
            pi = [0.2148, 0.3672, 0.2305, 0.1875]
        elif n < 750000:
            m = 128
            k = 5
            v = [4, 5, 6, 7, 8, 9]
            pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
        else:
            m = 10000
            k = 6
            v = [10, 11, 12, 13, 14, 15, 16]
            pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]

        # Divide sequence into blocks
        num_blocks = n // m
        blocks = [bits[i * m : (i + 1) * m] for i in range(num_blocks)]

        # Find longest run in each block
        longest_runs = []
        for block in blocks:
            max_run = 0
            current_run = 0
            for bit in block:
                if bit == 1:
                    current_run += 1
                    max_run = max(max_run, current_run)
                else:
                    current_run = 0
            longest_runs.append(max_run)

        # Count frequencies
        frequencies = [0] * (k + 1)
        for run_length in longest_runs:
            if run_length <= v[0]:
                frequencies[0] += 1
            elif run_length >= v[-1]:
                frequencies[k] += 1
            else:
                for i in range(len(v) - 1):
                    if v[i] < run_length <= v[i + 1]:
                        frequencies[i + 1] += 1
                        break

        # Chi-square statistic
        chi_square = sum(
            (frequencies[i] - num_blocks * pi[i]) ** 2 / (num_blocks * pi[i])
            for i in range(k + 1)
        )

        # P-value
        p_value = stats.chi2.sf(chi_square, k)

        return TestResult(
            test_type=RandomnessTestType.LONGEST_RUN,
            p_value=p_value,
            passed=p_value >= self.significance_level,
            statistic=chi_square,
            details={
                "num_blocks": num_blocks,
                "block_size": m,
                "frequencies": frequencies,
                "expected_pi": pi,
                "longest_runs": longest_runs[:10],  # First 10 for inspection
            },
        )

    def spectral_test(self, bits: List[int]) -> TestResult:
        """
        Discrete Fourier Transform (Spectral) Test.

        Tests whether the sequence has periodic features that would indicate
        a deviation from randomness.

        Args:
            bits: List of binary values (0 or 1)

        Returns:
            TestResult with p-value and pass/fail status
        """
        if not bits:
            raise ValueError("Bit sequence cannot be empty")

        if not all(b in (0, 1) for b in bits):
            raise ValueError("Bits must be 0 or 1")

        n = len(bits)

        # Convert bits to +1/-1
        x = np.array([2 * b - 1 for b in bits])

        # Apply DFT
        s = np.fft.fft(x)

        # Take first half (due to symmetry)
        m = n // 2
        modulus = np.abs(s[:m])

        # Threshold
        tau = math.sqrt(math.log(1 / 0.05) * n)

        # Count peaks below threshold
        n0 = 0.95 * m / 2
        n1 = sum(1 for mod in modulus if mod < tau)

        # Test statistic
        d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4)

        # P-value
        p_value = special.erfc(abs(d) / math.sqrt(2))

        return TestResult(
            test_type=RandomnessTestType.SPECTRAL,
            p_value=p_value,
            passed=p_value >= self.significance_level,
            statistic=d,
            details={
                "n0": n0,
                "n1": n1,
                "tau": tau,
                "peaks_below_threshold": n1,
                "expected_peaks": n0,
            },
        )

    def chi_square_test(
        self, values: List[int], num_categories: int = None
    ) -> TestResult:
        """
        Chi-Square Test for uniformity.

        Tests whether values are uniformly distributed across categories.

        Args:
            values: List of integer values
            num_categories: Number of expected categories (auto-detected if None)

        Returns:
            TestResult with p-value and pass/fail status
        """
        if not values:
            raise ValueError("Values list cannot be empty")

        # Count frequencies
        counter = Counter(values)

        if num_categories is None:
            num_categories = len(counter)

        n = len(values)
        expected_freq = n / num_categories

        # Chi-square statistic
        chi_square = sum(
            (count - expected_freq) ** 2 / expected_freq for count in counter.values()
        )

        # Degrees of freedom
        df = num_categories - 1

        # P-value
        p_value = stats.chi2.sf(chi_square, df)

        return TestResult(
            test_type=RandomnessTestType.CHI_SQUARE,
            p_value=p_value,
            passed=p_value >= self.significance_level,
            statistic=chi_square,
            details={
                "observed_frequencies": dict(counter),
                "expected_frequency": expected_freq,
                "num_categories": num_categories,
                "degrees_of_freedom": df,
                "n": n,
            },
        )

    def autocorrelation_test(self, bits: List[int], lag: int = 1) -> TestResult:
        """
        Autocorrelation Test.

        Tests for correlation between the sequence and a shifted version of itself.

        Args:
            bits: List of binary values (0 or 1)
            lag: Lag value for autocorrelation (default 1)

        Returns:
            TestResult with p-value and pass/fail status
        """
        if not bits:
            raise ValueError("Bit sequence cannot be empty")

        if not all(b in (0, 1) for b in bits):
            raise ValueError("Bits must be 0 or 1")

        if lag < 1 or lag >= len(bits):
            raise ValueError(f"Lag must be between 1 and {len(bits)-1}")

        n = len(bits)

        # Calculate autocorrelation
        agreements = sum(1 for i in range(n - lag) if bits[i] == bits[i + lag])

        # Expected value and variance under null hypothesis
        expected = (n - lag) / 2
        variance = (n - lag) / 4

        # Test statistic
        statistic = (agreements - expected) / math.sqrt(variance)

        # P-value (two-tailed test)
        p_value = 2 * (1 - stats.norm.cdf(abs(statistic)))

        return TestResult(
            test_type=RandomnessTestType.AUTOCORRELATION,
            p_value=p_value,
            passed=p_value >= self.significance_level,
            statistic=statistic,
            details={
                "lag": lag,
                "agreements": agreements,
                "expected_agreements": expected,
                "n": n,
            },
        )
