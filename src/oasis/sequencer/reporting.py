"""
Token Analysis Reporting and Visualization

Generates detailed reports and visualizations for token randomness analysis.
"""

import json
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional
from dataclasses import asdict

from .analyzer import RandomnessReport, EntropyMetrics
from .tests import TestResult
from .patterns import Pattern


class ReportGenerator:
    """
    Generates detailed randomness quality reports.

    Produces human-readable and machine-readable reports of token analysis
    results including test outcomes, patterns, and recommendations.
    """

    def __init__(self):
        """Initialize report generator."""
        pass

    def generate_text_report(self, report: RandomnessReport) -> str:
        """
        Generate a human-readable text report.

        Args:
            report: RandomnessReport to format

        Returns:
            Formatted text report
        """
        lines = []
        lines.append("=" * 80)
        lines.append("TOKEN RANDOMNESS ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(
            f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        lines.append(f"Tokens Analyzed: {report.tokens_analyzed}")
        lines.append("")

        # Overall Assessment
        lines.append("-" * 80)
        lines.append("OVERALL ASSESSMENT")
        lines.append("-" * 80)
        lines.append(f"Quality Rating: {report.overall_quality.upper()}")

        if report.prediction_probability is not None:
            lines.append(f"Prediction Probability: {report.prediction_probability:.2%}")
            lines.append(self._get_prediction_risk_level(report.prediction_probability))

        lines.append("")

        # Entropy Metrics
        lines.append("-" * 80)
        lines.append("ENTROPY METRICS")
        lines.append("-" * 80)
        lines.append(
            f"Shannon Entropy: {report.entropy_metrics.shannon_entropy:.4f} bits/char"
        )
        lines.append(f"Min Entropy: {report.entropy_metrics.min_entropy:.4f} bits")
        lines.append(
            f"Normalized Entropy: {report.entropy_metrics.normalized_entropy:.4f} (0-1 scale)"
        )
        lines.append(
            f"Bits per Character: {report.entropy_metrics.bits_per_character:.4f}"
        )
        lines.append(
            f"Unique Tokens: {report.entropy_metrics.unique_tokens}/{report.entropy_metrics.total_tokens}"
        )
        lines.append(f"Uniqueness Ratio: {report.entropy_metrics.uniqueness_ratio:.2%}")
        lines.append("")

        # Statistical Tests
        lines.append("-" * 80)
        lines.append("STATISTICAL TESTS")
        lines.append("-" * 80)
        lines.append(f"Tests Passed: {report.passed_tests}/{len(report.test_results)}")
        lines.append("")

        for test in report.test_results:
            status = "PASS" if test.passed else "FAIL"
            lines.append(
                f"  [{status}] {test.test_type.value.replace('_', ' ').title()}"
            )
            lines.append(f"         P-value: {test.p_value:.6f}")
            lines.append(f"         Statistic: {test.statistic:.4f}")

        lines.append("")

        # Patterns Detected
        lines.append("-" * 80)
        lines.append("PATTERNS DETECTED")
        lines.append("-" * 80)

        if report.patterns:
            lines.append(f"Total Patterns: {len(report.patterns)}")
            lines.append(f"High Severity: {report.high_severity_patterns}")
            lines.append("")

            for i, pattern in enumerate(report.patterns, 1):
                lines.append(
                    f"  Pattern {i}: {pattern.pattern_type.value.replace('_', ' ').title()}"
                )
                lines.append(f"    Severity: {pattern.severity.upper()}")
                lines.append(f"    Confidence: {pattern.confidence:.2%}")
                lines.append(f"    Description: {pattern.description}")
                if pattern.evidence:
                    lines.append(f"    Evidence:")
                    for evidence in pattern.evidence[:3]:  # Show first 3
                        lines.append(f"      - {evidence}")
                lines.append("")
        else:
            lines.append("No patterns detected.")
            lines.append("")

        # Recommendations
        lines.append("-" * 80)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 80)

        for i, recommendation in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {recommendation}")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)

    def generate_json_report(self, report: RandomnessReport) -> str:
        """
        Generate a machine-readable JSON report.

        Args:
            report: RandomnessReport to format

        Returns:
            JSON string
        """
        report_dict = {
            "generated_at": datetime.now(UTC).isoformat(),
            "tokens_analyzed": report.tokens_analyzed,
            "overall_quality": report.overall_quality,
            "prediction_probability": report.prediction_probability,
            "entropy_metrics": {
                "shannon_entropy": report.entropy_metrics.shannon_entropy,
                "min_entropy": report.entropy_metrics.min_entropy,
                "normalized_entropy": report.entropy_metrics.normalized_entropy,
                "bits_per_character": report.entropy_metrics.bits_per_character,
                "unique_tokens": report.entropy_metrics.unique_tokens,
                "total_tokens": report.entropy_metrics.total_tokens,
                "uniqueness_ratio": report.entropy_metrics.uniqueness_ratio,
            },
            "test_results": [
                {
                    "test_type": test.test_type.value,
                    "p_value": float(test.p_value),
                    "passed": bool(test.passed),
                    "statistic": float(test.statistic),
                    "details": self._serialize_details(test.details),
                }
                for test in report.test_results
            ],
            "patterns": [
                {
                    "pattern_type": pattern.pattern_type.value,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "confidence": pattern.confidence,
                    "evidence": pattern.evidence,
                }
                for pattern in report.patterns
            ],
            "recommendations": report.recommendations,
            "summary": {
                "tests_passed": report.passed_tests,
                "tests_failed": report.failed_tests,
                "high_severity_patterns": report.high_severity_patterns,
            },
        }

        return json.dumps(report_dict, indent=2)

    def generate_html_report(self, report: RandomnessReport) -> str:
        """
        Generate an HTML report with basic styling.

        Args:
            report: RandomnessReport to format

        Returns:
            HTML string
        """
        quality_color = self._get_quality_color(report.overall_quality)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Token Randomness Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px 10px 0;
        }}
        .metric-label {{
            font-weight: bold;
            color: #666;
        }}
        .metric-value {{
            color: #333;
            font-size: 1.1em;
        }}
        .quality-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 1.2em;
            background-color: {quality_color};
            color: white;
        }}
        .test-result {{
            margin: 10px 0;
            padding: 10px;
            border-left: 4px solid #ddd;
            background-color: #f9f9f9;
        }}
        .test-pass {{
            border-left-color: #4CAF50;
        }}
        .test-fail {{
            border-left-color: #f44336;
        }}
        .pattern {{
            margin: 15px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #fff9e6;
        }}
        .pattern-high {{
            background-color: #ffebee;
            border-color: #f44336;
        }}
        .pattern-medium {{
            background-color: #fff3e0;
            border-color: #ff9800;
        }}
        .pattern-low {{
            background-color: #e8f5e9;
            border-color: #4CAF50;
        }}
        .recommendation {{
            margin: 10px 0;
            padding: 10px;
            background-color: #e3f2fd;
            border-left: 4px solid #2196F3;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        .timestamp {{
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Token Randomness Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        
        <h2>Overall Assessment</h2>
        <div class="metric">
            <span class="metric-label">Quality Rating:</span>
            <span class="quality-badge">{report.overall_quality.upper()}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Tokens Analyzed:</span>
            <span class="metric-value">{report.tokens_analyzed}</span>
        </div>
        """

        if report.prediction_probability is not None:
            html += f"""
        <div class="metric">
            <span class="metric-label">Prediction Probability:</span>
            <span class="metric-value">{report.prediction_probability:.2%}</span>
        </div>
            """

        html += f"""
        
        <h2>Entropy Metrics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Shannon Entropy</td>
                <td>{report.entropy_metrics.shannon_entropy:.4f} bits/char</td>
            </tr>
            <tr>
                <td>Min Entropy</td>
                <td>{report.entropy_metrics.min_entropy:.4f} bits</td>
            </tr>
            <tr>
                <td>Normalized Entropy</td>
                <td>{report.entropy_metrics.normalized_entropy:.4f}</td>
            </tr>
            <tr>
                <td>Bits per Character</td>
                <td>{report.entropy_metrics.bits_per_character:.4f}</td>
            </tr>
            <tr>
                <td>Unique Tokens</td>
                <td>{report.entropy_metrics.unique_tokens}/{report.entropy_metrics.total_tokens}</td>
            </tr>
            <tr>
                <td>Uniqueness Ratio</td>
                <td>{report.entropy_metrics.uniqueness_ratio:.2%}</td>
            </tr>
        </table>
        
        <h2>Statistical Tests</h2>
        <p><strong>Tests Passed:</strong> {report.passed_tests}/{len(report.test_results)}</p>
        """

        for test in report.test_results:
            status_class = "test-pass" if test.passed else "test-fail"
            status_text = "PASS" if test.passed else "FAIL"
            html += f"""
        <div class="test-result {status_class}">
            <strong>[{status_text}] {test.test_type.value.replace('_', ' ').title()}</strong><br>
            P-value: {test.p_value:.6f} | Statistic: {test.statistic:.4f}
        </div>
            """

        html += "<h2>Patterns Detected</h2>"

        if report.patterns:
            html += f"<p><strong>Total Patterns:</strong> {len(report.patterns)} (High Severity: {report.high_severity_patterns})</p>"

            for pattern in report.patterns:
                pattern_class = f"pattern-{pattern.severity}"
                html += f"""
        <div class="pattern {pattern_class}">
            <strong>{pattern.pattern_type.value.replace('_', ' ').title()}</strong>
            <span style="float: right;">Severity: {pattern.severity.upper()} | Confidence: {pattern.confidence:.2%}</span><br>
            <p>{pattern.description}</p>
                """
                if pattern.evidence:
                    html += "<p><strong>Evidence:</strong></p><ul>"
                    for evidence in pattern.evidence[:3]:
                        html += f"<li>{evidence}</li>"
                    html += "</ul>"
                html += "</div>"
        else:
            html += "<p>No patterns detected.</p>"

        html += "<h2>Recommendations</h2>"

        for i, recommendation in enumerate(report.recommendations, 1):
            html += f"""
        <div class="recommendation">
            <strong>{i}.</strong> {recommendation}
        </div>
            """

        html += """
    </div>
</body>
</html>
        """

        return html

    def _get_quality_color(self, quality: str) -> str:
        """Get color code for quality rating."""
        colors = {
            "excellent": "#4CAF50",
            "good": "#8BC34A",
            "fair": "#FFC107",
            "poor": "#FF9800",
            "critical": "#f44336",
        }
        return colors.get(quality, "#999")

    def _get_prediction_risk_level(self, probability: float) -> str:
        """Get risk level description for prediction probability."""
        if probability < 0.01:
            return "Risk Level: VERY LOW - Tokens are highly unpredictable"
        elif probability < 0.1:
            return "Risk Level: LOW - Tokens have good randomness"
        elif probability < 0.3:
            return "Risk Level: MEDIUM - Some predictability concerns"
        elif probability < 0.5:
            return "Risk Level: HIGH - Tokens are somewhat predictable"
        else:
            return "Risk Level: CRITICAL - Tokens are highly predictable"

    def _serialize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize test details for JSON output."""
        serialized = {}
        for key, value in details.items():
            if isinstance(value, (int, float, str, bool, type(None))):
                serialized[key] = value
            elif isinstance(value, dict):
                serialized[key] = self._serialize_details(value)
            elif isinstance(value, list):
                serialized[key] = [
                    v if isinstance(v, (int, float, str, bool, type(None))) else str(v)
                    for v in value
                ]
            else:
                serialized[key] = str(value)
        return serialized


class PredictionCalculator:
    """
    Calculates prediction probabilities for weak tokens.

    Estimates the probability of successfully predicting the next token
    based on entropy, patterns, and statistical test results.
    """

    def __init__(self):
        """Initialize prediction calculator."""
        pass

    def calculate_prediction_probability(
        self,
        entropy: EntropyMetrics,
        test_results: List[TestResult],
        patterns: List[Pattern],
    ) -> float:
        """
        Calculate probability of predicting next token.

        Args:
            entropy: Entropy metrics
            test_results: Statistical test results
            patterns: Detected patterns

        Returns:
            Probability between 0 and 1
        """
        # Base probability from entropy
        base_prob = self._entropy_to_probability(entropy)

        # Adjust for test failures
        test_multiplier = self._calculate_test_multiplier(test_results)

        # Adjust for patterns
        pattern_multiplier = self._calculate_pattern_multiplier(patterns)

        # Calculate final probability
        prediction_prob = min(base_prob * test_multiplier * pattern_multiplier, 1.0)

        return prediction_prob

    def calculate_attack_feasibility(
        self, prediction_probability: float, token_space_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Calculate attack feasibility metrics.

        Args:
            prediction_probability: Probability of predicting next token
            token_space_size: Size of token space (if known)

        Returns:
            Dictionary with attack feasibility metrics
        """
        # Expected attempts to guess token
        if prediction_probability > 0:
            expected_attempts = 1 / prediction_probability
        else:
            expected_attempts = float("inf")

        # Time estimates (assuming 1000 attempts per second)
        attempts_per_second = 1000
        expected_seconds = expected_attempts / attempts_per_second

        # Feasibility rating
        if prediction_probability >= 0.5:
            feasibility = "CRITICAL - Attack is trivial"
        elif prediction_probability >= 0.1:
            feasibility = "HIGH - Attack is practical"
        elif prediction_probability >= 0.01:
            feasibility = "MEDIUM - Attack requires resources"
        elif prediction_probability >= 0.001:
            feasibility = "LOW - Attack is difficult"
        else:
            feasibility = "VERY LOW - Attack is infeasible"

        return {
            "prediction_probability": prediction_probability,
            "expected_attempts": expected_attempts,
            "expected_time_seconds": expected_seconds,
            "expected_time_human": self._format_time(expected_seconds),
            "feasibility": feasibility,
            "token_space_size": token_space_size,
        }

    def _entropy_to_probability(self, entropy: EntropyMetrics) -> float:
        """Convert entropy metrics to base prediction probability."""
        if entropy.normalized_entropy >= 0.9:
            return 0.001
        elif entropy.normalized_entropy >= 0.8:
            return 0.005
        elif entropy.normalized_entropy >= 0.7:
            return 0.01
        elif entropy.normalized_entropy >= 0.6:
            return 0.05
        elif entropy.normalized_entropy >= 0.5:
            return 0.1
        elif entropy.normalized_entropy >= 0.4:
            return 0.2
        else:
            return 0.5

    def _calculate_test_multiplier(self, test_results: List[TestResult]) -> float:
        """Calculate multiplier based on test failures."""
        if not test_results:
            return 1.0

        failed_tests = sum(1 for t in test_results if not t.passed)
        return 1.0 + (failed_tests * 0.2)

    def _calculate_pattern_multiplier(self, patterns: List[Pattern]) -> float:
        """Calculate multiplier based on detected patterns."""
        multiplier = 1.0

        for pattern in patterns:
            if pattern.severity == "high":
                multiplier *= 2.0
            elif pattern.severity == "medium":
                multiplier *= 1.5
            elif pattern.severity == "low":
                multiplier *= 1.2

        return multiplier

    def _format_time(self, seconds: float) -> str:
        """Format time duration in human-readable format."""
        if seconds == float("inf"):
            return "Infinite"
        elif seconds < 1:
            return f"{seconds*1000:.2f} milliseconds"
        elif seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        else:
            return f"{seconds/31536000:.2f} years"


class VisualizationData:
    """
    Prepares data for visualization of token analysis results.

    Generates data structures suitable for plotting and visualization
    of entropy, test results, and token distributions.
    """

    def __init__(self):
        """Initialize visualization data generator."""
        pass

    def prepare_entropy_chart_data(self, report: RandomnessReport) -> Dict[str, Any]:
        """
        Prepare data for entropy metrics chart.

        Args:
            report: RandomnessReport

        Returns:
            Dictionary with chart data
        """
        return {
            "labels": [
                "Shannon Entropy",
                "Min Entropy",
                "Normalized Entropy",
                "Uniqueness Ratio",
            ],
            "values": [
                report.entropy_metrics.shannon_entropy / 8.0,  # Normalize to 0-1
                report.entropy_metrics.min_entropy / 8.0,
                report.entropy_metrics.normalized_entropy,
                report.entropy_metrics.uniqueness_ratio,
            ],
            "chart_type": "bar",
            "title": "Entropy Metrics",
            "y_label": "Score (0-1)",
        }

    def prepare_test_results_chart_data(
        self, report: RandomnessReport
    ) -> Dict[str, Any]:
        """
        Prepare data for test results chart.

        Args:
            report: RandomnessReport

        Returns:
            Dictionary with chart data
        """
        return {
            "labels": [
                test.test_type.value.replace("_", " ").title()
                for test in report.test_results
            ],
            "p_values": [float(test.p_value) for test in report.test_results],
            "passed": [bool(test.passed) for test in report.test_results],
            "chart_type": "bar",
            "title": "Statistical Test Results",
            "y_label": "P-value",
            "threshold": 0.01,  # Significance level
        }

    def prepare_pattern_distribution_data(
        self, report: RandomnessReport
    ) -> Dict[str, Any]:
        """
        Prepare data for pattern distribution chart.

        Args:
            report: RandomnessReport

        Returns:
            Dictionary with chart data
        """
        from collections import Counter

        pattern_counts = Counter(p.pattern_type.value for p in report.patterns)
        severity_counts = Counter(p.severity for p in report.patterns)

        return {
            "pattern_types": {
                "labels": list(pattern_counts.keys()),
                "values": list(pattern_counts.values()),
            },
            "severity_distribution": {
                "labels": list(severity_counts.keys()),
                "values": list(severity_counts.values()),
            },
            "chart_type": "pie",
            "title": "Pattern Distribution",
        }

    def prepare_quality_summary_data(self, report: RandomnessReport) -> Dict[str, Any]:
        """
        Prepare summary data for quality overview.

        Args:
            report: RandomnessReport

        Returns:
            Dictionary with summary data
        """
        return {
            "overall_quality": report.overall_quality,
            "quality_score": self._quality_to_score(report.overall_quality),
            "tests_passed": report.passed_tests,
            "tests_total": len(report.test_results),
            "tests_pass_rate": (
                report.passed_tests / len(report.test_results)
                if report.test_results
                else 0
            ),
            "patterns_detected": len(report.patterns),
            "high_severity_patterns": report.high_severity_patterns,
            "prediction_probability": report.prediction_probability,
            "entropy_score": report.entropy_metrics.normalized_entropy,
        }

    def _quality_to_score(self, quality: str) -> float:
        """Convert quality rating to numeric score (0-1)."""
        scores = {
            "excellent": 1.0,
            "good": 0.8,
            "fair": 0.6,
            "poor": 0.4,
            "critical": 0.2,
        }
        return scores.get(quality, 0.5)
