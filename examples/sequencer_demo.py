#!/usr/bin/env python3
"""
OASIS Sequencer Demo

Demonstrates token analysis and randomness testing capabilities.
"""

import secrets
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oasis.sequencer import (
    TokenAnalyzer,
    ReportGenerator,
    PredictionCalculator,
    VisualizationData
)


def demo_strong_tokens():
    """Demonstrate analysis of cryptographically strong tokens."""
    print("=" * 80)
    print("DEMO 1: Analyzing Cryptographically Strong Tokens")
    print("=" * 80)
    print()
    
    # Generate strong tokens using secrets module
    tokens = [secrets.token_hex(16) for _ in range(50)]
    
    print(f"Generated {len(tokens)} tokens using secrets.token_hex(16)")
    print(f"Sample tokens: {tokens[:3]}")
    print()
    
    # Analyze tokens
    analyzer = TokenAnalyzer()
    report = analyzer.analyze_randomness(tokens)
    
    # Generate text report
    report_gen = ReportGenerator()
    text_report = report_gen.generate_text_report(report)
    print(text_report)
    
    # Calculate attack feasibility
    pred_calc = PredictionCalculator()
    feasibility = pred_calc.calculate_attack_feasibility(
        report.prediction_probability or 0.001
    )
    
    print("\nATTACK FEASIBILITY ANALYSIS")
    print("-" * 80)
    print(f"Prediction Probability: {feasibility['prediction_probability']:.6f}")
    print(f"Expected Attempts: {feasibility['expected_attempts']:.2f}")
    print(f"Expected Time: {feasibility['expected_time_human']}")
    print(f"Feasibility: {feasibility['feasibility']}")
    print()


def demo_weak_tokens():
    """Demonstrate analysis of weak tokens."""
    print("=" * 80)
    print("DEMO 2: Analyzing Weak Sequential Tokens")
    print("=" * 80)
    print()
    
    # Generate weak sequential tokens
    tokens = [f"session_{i:06d}" for i in range(50)]
    
    print(f"Generated {len(tokens)} sequential tokens")
    print(f"Sample tokens: {tokens[:3]}")
    print()
    
    # Analyze tokens
    analyzer = TokenAnalyzer()
    report = analyzer.analyze_randomness(tokens)
    
    # Generate text report
    report_gen = ReportGenerator()
    text_report = report_gen.generate_text_report(report)
    print(text_report)
    
    # Calculate attack feasibility
    pred_calc = PredictionCalculator()
    feasibility = pred_calc.calculate_attack_feasibility(
        report.prediction_probability or 0.5
    )
    
    print("\nATTACK FEASIBILITY ANALYSIS")
    print("-" * 80)
    print(f"Prediction Probability: {feasibility['prediction_probability']:.6f}")
    print(f"Expected Attempts: {feasibility['expected_attempts']:.2f}")
    print(f"Expected Time: {feasibility['expected_time_human']}")
    print(f"Feasibility: {feasibility['feasibility']}")
    print()


def demo_timestamp_tokens():
    """Demonstrate analysis of timestamp-based tokens."""
    print("=" * 80)
    print("DEMO 3: Analyzing Timestamp-Based Tokens")
    print("=" * 80)
    print()
    
    # Generate timestamp-based tokens
    import time
    base_time = int(time.time())
    tokens = [f"token_{base_time + i}" for i in range(50)]
    
    print(f"Generated {len(tokens)} timestamp-based tokens")
    print(f"Sample tokens: {tokens[:3]}")
    print()
    
    # Analyze tokens
    analyzer = TokenAnalyzer()
    report = analyzer.analyze_randomness(tokens)
    
    # Generate text report
    report_gen = ReportGenerator()
    text_report = report_gen.generate_text_report(report)
    print(text_report)


def demo_report_formats():
    """Demonstrate different report formats."""
    print("=" * 80)
    print("DEMO 4: Different Report Formats")
    print("=" * 80)
    print()
    
    # Generate some tokens
    tokens = [secrets.token_urlsafe(12) for _ in range(30)]
    
    # Analyze
    analyzer = TokenAnalyzer()
    report = analyzer.analyze_randomness(tokens)
    
    # Generate different formats
    report_gen = ReportGenerator()
    
    # JSON format
    print("JSON Report:")
    print("-" * 80)
    json_report = report_gen.generate_json_report(report)
    print(json_report[:500] + "..." if len(json_report) > 500 else json_report)
    print()
    
    # HTML format (save to file)
    html_report = report_gen.generate_html_report(report)
    output_file = Path(__file__).parent / "sequencer_report.html"
    output_file.write_text(html_report)
    print(f"HTML report saved to: {output_file}")
    print()


def demo_visualization_data():
    """Demonstrate visualization data preparation."""
    print("=" * 80)
    print("DEMO 5: Visualization Data Preparation")
    print("=" * 80)
    print()
    
    # Generate tokens
    tokens = [secrets.token_hex(16) for _ in range(40)]
    
    # Analyze
    analyzer = TokenAnalyzer()
    report = analyzer.analyze_randomness(tokens)
    
    # Prepare visualization data
    viz = VisualizationData()
    
    # Entropy chart data
    entropy_data = viz.prepare_entropy_chart_data(report)
    print("Entropy Chart Data:")
    print(f"  Labels: {entropy_data['labels']}")
    print(f"  Values: {[f'{v:.3f}' for v in entropy_data['values']]}")
    print()
    
    # Test results chart data
    test_data = viz.prepare_test_results_chart_data(report)
    print("Test Results Chart Data:")
    print(f"  Tests: {test_data['labels']}")
    print(f"  P-values: {[f'{v:.4f}' for v in test_data['p_values']]}")
    print(f"  Passed: {test_data['passed']}")
    print()
    
    # Quality summary
    summary = viz.prepare_quality_summary_data(report)
    print("Quality Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print()


def main():
    """Run all demos."""
    demos = [
        demo_strong_tokens,
        demo_weak_tokens,
        demo_timestamp_tokens,
        demo_report_formats,
        demo_visualization_data
    ]
    
    for i, demo in enumerate(demos, 1):
        try:
            demo()
            if i < len(demos):
                input("\nPress Enter to continue to next demo...")
                print("\n" * 2)
        except KeyboardInterrupt:
            print("\n\nDemo interrupted by user.")
            break
        except Exception as e:
            print(f"\nError in demo: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
