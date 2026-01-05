# OASIS Sequencer Module

Session token analysis and randomness testing capabilities for the OASIS penetration testing suite.

## Overview

The Sequencer module provides comprehensive analysis of session tokens and random values to identify cryptographic weaknesses and predictability issues. It implements statistical randomness tests from NIST SP 800-22 and pattern detection algorithms to assess token security.

## Features

- **Statistical Randomness Testing**: NIST SP 800-22 test suite implementation
  - Frequency (Monobit) Test
  - Runs Test
  - Longest Run of Ones Test
  - Discrete Fourier Transform (Spectral) Test
  - Chi-Square Test
  - Autocorrelation Test

- **Pattern Detection**: Identifies common token generation weaknesses
  - Sequential numeric patterns
  - Repeating tokens
  - Timestamp-based generation
  - Limited character sets
  - Low entropy

- **Entropy Analysis**: Comprehensive entropy metrics
  - Shannon entropy
  - Min entropy
  - Normalized entropy
  - Character-level and token-level analysis

- **Security Assessment**: Automated quality rating and recommendations
  - Overall quality rating (excellent/good/fair/poor/critical)
  - Prediction probability calculation
  - Actionable security recommendations

## Usage

### Basic Token Analysis

```python
from oasis.sequencer import TokenAnalyzer

# Initialize analyzer
analyzer = TokenAnalyzer()

# Analyze tokens
tokens = [
    "a3f5b2c1d4e6",
    "b4g6c2e5f7h8",
    "c5h7d3f6g8i9",
    # ... more tokens
]

report = analyzer.analyze_randomness(tokens)

# Check results
print(f"Overall Quality: {report.overall_quality}")
print(f"Entropy: {report.entropy_metrics.shannon_entropy:.2f} bits/char")
print(f"Prediction Probability: {report.prediction_probability:.2%}")
print(f"Tests Passed: {report.passed_tests}/{len(report.test_results)}")

# Review recommendations
for recommendation in report.recommendations:
    print(f"- {recommendation}")
```

### Entropy Calculation

```python
from oasis.sequencer import TokenAnalyzer

analyzer = TokenAnalyzer()
tokens = ["token1", "token2", "token3"]

entropy_metrics = analyzer.calculate_entropy(tokens)

print(f"Shannon Entropy: {entropy_metrics.shannon_entropy:.2f}")
print(f"Normalized Entropy: {entropy_metrics.normalized_entropy:.2f}")
print(f"Uniqueness Ratio: {entropy_metrics.uniqueness_ratio:.2%}")
```

### Pattern Detection

```python
from oasis.sequencer import PatternDetector

detector = PatternDetector(min_confidence=0.7)
tokens = ["token001", "token002", "token003"]

patterns = detector.detect_patterns(tokens)

for pattern in patterns:
    print(f"Pattern: {pattern.pattern_type.value}")
    print(f"Severity: {pattern.severity}")
    print(f"Description: {pattern.description}")
    print(f"Confidence: {pattern.confidence:.2%}")
```

### Statistical Tests

```python
from oasis.sequencer import RandomnessTest

tester = RandomnessTest(significance_level=0.01)

# Convert tokens to bits
bits = [0, 1, 1, 0, 1, 0, 1, 1, ...]  # Binary sequence

# Run individual tests
freq_result = tester.frequency_test(bits)
runs_result = tester.runs_test(bits)
spectral_result = tester.spectral_test(bits)

print(f"Frequency Test: {'PASS' if freq_result.passed else 'FAIL'}")
print(f"P-value: {freq_result.p_value:.4f}")
```

## Architecture

### Components

1. **TokenAnalyzer** (`analyzer.py`): Main analysis engine
   - Orchestrates all analysis components
   - Generates comprehensive reports
   - Calculates prediction probabilities

2. **RandomnessTest** (`tests.py`): Statistical testing framework
   - Implements NIST SP 800-22 tests
   - Provides p-values and test statistics
   - Configurable significance levels

3. **PatternDetector** (`patterns.py`): Pattern detection engine
   - Identifies common weaknesses
   - Calculates confidence scores
   - Provides evidence for detected patterns

### Data Models

- **RandomnessReport**: Complete analysis results
- **EntropyMetrics**: Entropy and uniqueness measurements
- **TestResult**: Individual test outcomes
- **Pattern**: Detected pattern information

## Requirements

- Python 3.11+
- numpy
- scipy

## Integration

The Sequencer module integrates with other OASIS components:

- **Proxy**: Capture session tokens from HTTP traffic
- **Storage**: Persist analysis results
- **Reporting**: Generate detailed security reports

## Security Considerations

The Sequencer module helps identify:

- Weak random number generators
- Predictable token generation
- Insufficient entropy
- Pattern-based vulnerabilities
- Session fixation risks

## References

- NIST SP 800-22: A Statistical Test Suite for Random and Pseudorandom Number Generators
- OWASP Session Management Cheat Sheet
- Cryptographic randomness testing standards
