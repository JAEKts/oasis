"""
Attack Result Analysis and Filtering

Provides analysis, filtering, and sorting capabilities for attack results.
"""

from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from pydantic import BaseModel, Field

from .engine import AttackResult, AttackResults


class FilterCriteria(str, Enum):
    """Criteria for filtering attack results."""

    STATUS_CODE = "status_code"
    RESPONSE_LENGTH = "response_length"
    RESPONSE_TIME = "response_time"
    CONTAINS_TEXT = "contains_text"
    REGEX_MATCH = "regex_match"
    ERROR = "error"


class SortCriteria(str, Enum):
    """Criteria for sorting attack results."""

    STATUS_CODE = "status_code"
    RESPONSE_LENGTH = "response_length"
    RESPONSE_TIME = "response_time"
    TIMESTAMP = "timestamp"
    PAYLOAD = "payload"


class FilterRule(BaseModel):
    """Rule for filtering attack results."""

    criteria: FilterCriteria = Field(description="Filter criteria")
    operator: str = Field(
        description="Comparison operator: ==, !=, <, >, <=, >=, contains, matches"
    )
    value: Any = Field(description="Value to compare against")
    enabled: bool = Field(default=True, description="Whether filter is enabled")


class ResultAnalyzer:
    """
    Analyzes attack results to identify interesting responses.
    """

    def __init__(self):
        self.filters: List[FilterRule] = []

    def add_filter(self, rule: FilterRule) -> None:
        """Add a filter rule."""
        self.filters.append(rule)

    def clear_filters(self) -> None:
        """Clear all filter rules."""
        self.filters.clear()

    def filter_results(self, results: List[AttackResult]) -> List[AttackResult]:
        """
        Filter results based on configured rules.

        Args:
            results: List of attack results to filter

        Returns:
            Filtered list of results
        """
        if not self.filters:
            return results

        filtered = []
        for result in results:
            if self._matches_filters(result):
                filtered.append(result)

        return filtered

    def _matches_filters(self, result: AttackResult) -> bool:
        """Check if a result matches all enabled filters."""
        for rule in self.filters:
            if not rule.enabled:
                continue

            if not self._matches_filter(result, rule):
                return False

        return True

    def _matches_filter(self, result: AttackResult, rule: FilterRule) -> bool:
        """Check if a result matches a single filter rule."""
        import re

        # Get the value to compare
        if rule.criteria == FilterCriteria.STATUS_CODE:
            if not result.response:
                return False
            actual_value = result.response.status_code

        elif rule.criteria == FilterCriteria.RESPONSE_LENGTH:
            if not result.response or not result.response.body:
                return False
            actual_value = len(result.response.body)

        elif rule.criteria == FilterCriteria.RESPONSE_TIME:
            if not result.response:
                return False
            actual_value = result.response.duration_ms

        elif rule.criteria == FilterCriteria.CONTAINS_TEXT:
            if not result.response or not result.response.body:
                return False
            try:
                body_text = result.response.body.decode("utf-8", errors="ignore")
                return rule.value in body_text
            except Exception:
                return False

        elif rule.criteria == FilterCriteria.REGEX_MATCH:
            if not result.response or not result.response.body:
                return False
            try:
                body_text = result.response.body.decode("utf-8", errors="ignore")
                return bool(re.search(rule.value, body_text))
            except Exception:
                return False

        elif rule.criteria == FilterCriteria.ERROR:
            return bool(result.error) == bool(rule.value)

        else:
            return True

        # Apply operator
        if rule.operator == "==":
            return actual_value == rule.value
        elif rule.operator == "!=":
            return actual_value != rule.value
        elif rule.operator == "<":
            return actual_value < rule.value
        elif rule.operator == ">":
            return actual_value > rule.value
        elif rule.operator == "<=":
            return actual_value <= rule.value
        elif rule.operator == ">=":
            return actual_value >= rule.value
        else:
            return True

    def sort_results(
        self, results: List[AttackResult], criteria: SortCriteria, reverse: bool = False
    ) -> List[AttackResult]:
        """
        Sort results by specified criteria.

        Args:
            results: List of results to sort
            criteria: Sort criteria
            reverse: Sort in descending order if True

        Returns:
            Sorted list of results
        """

        def get_sort_key(result: AttackResult) -> Any:
            if criteria == SortCriteria.STATUS_CODE:
                return result.response.status_code if result.response else 0

            elif criteria == SortCriteria.RESPONSE_LENGTH:
                if result.response and result.response.body:
                    return len(result.response.body)
                return 0

            elif criteria == SortCriteria.RESPONSE_TIME:
                return result.response.duration_ms if result.response else 0

            elif criteria == SortCriteria.TIMESTAMP:
                return result.timestamp

            elif criteria == SortCriteria.PAYLOAD:
                # Sort by first payload value
                if result.payloads:
                    return list(result.payloads.values())[0]
                return ""

            return 0

        return sorted(results, key=get_sort_key, reverse=reverse)

    def find_anomalies(self, results: List[AttackResult]) -> List[AttackResult]:
        """
        Find anomalous results based on statistical analysis.

        Identifies results with unusual status codes, response lengths, or timing.

        Args:
            results: List of results to analyze

        Returns:
            List of anomalous results
        """
        if len(results) < 3:
            return []

        # Calculate statistics for response length
        lengths = []
        for result in results:
            if result.response and result.response.body:
                lengths.append(len(result.response.body))

        if not lengths:
            return []

        # Calculate mean and standard deviation
        mean_length = sum(lengths) / len(lengths)
        variance = sum((x - mean_length) ** 2 for x in lengths) / len(lengths)
        std_dev = variance**0.5

        # Find results outside 2 standard deviations
        anomalies = []
        for result in results:
            if result.response and result.response.body:
                length = len(result.response.body)
                if abs(length - mean_length) > 2 * std_dev:
                    anomalies.append(result)

        return anomalies

    def group_by_status_code(
        self, results: List[AttackResult]
    ) -> Dict[int, List[AttackResult]]:
        """
        Group results by HTTP status code.

        Args:
            results: List of results to group

        Returns:
            Dictionary mapping status codes to result lists
        """
        groups: Dict[int, List[AttackResult]] = {}

        for result in results:
            if result.response:
                status_code = result.response.status_code
                if status_code not in groups:
                    groups[status_code] = []
                groups[status_code].append(result)

        return groups

    def find_successful_payloads(
        self,
        results: List[AttackResult],
        success_criteria: Optional[Callable[[AttackResult], bool]] = None,
    ) -> List[AttackResult]:
        """
        Find results that indicate successful attacks.

        Args:
            results: List of results to analyze
            success_criteria: Optional custom function to determine success

        Returns:
            List of successful results
        """
        if success_criteria:
            return [r for r in results if success_criteria(r)]

        # Default success criteria: 2xx status codes or anomalous responses
        successful = []
        anomalies = self.find_anomalies(results)
        anomaly_ids = {a.id for a in anomalies}

        for result in results:
            if result.response:
                # 2xx status codes
                if 200 <= result.response.status_code < 300:
                    successful.append(result)
                # Anomalous responses
                elif result.id in anomaly_ids:
                    successful.append(result)

        return successful

    def generate_summary(self, results: AttackResults) -> Dict[str, Any]:
        """
        Generate a summary of attack results.

        Args:
            results: Attack results to summarize

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            "total_requests": results.statistics.total_requests,
            "successful_requests": results.statistics.successful_requests,
            "failed_requests": results.statistics.failed_requests,
            "duration_seconds": results.statistics.duration_seconds,
            "requests_per_second": results.statistics.requests_per_second,
            "status_code_distribution": {},
            "unique_response_lengths": set(),
            "error_count": 0,
        }

        # Analyze results
        for result in results.results:
            if result.error:
                summary["error_count"] += 1

            if result.response:
                status_code = result.response.status_code
                summary["status_code_distribution"][status_code] = (
                    summary["status_code_distribution"].get(status_code, 0) + 1
                )

                if result.response.body:
                    summary["unique_response_lengths"].add(len(result.response.body))

        # Convert set to list for JSON serialization
        summary["unique_response_lengths"] = sorted(
            list(summary["unique_response_lengths"])
        )

        return summary


class ReportGenerator:
    """
    Generates detailed reports from attack results.
    """

    @staticmethod
    def generate_text_report(
        results: AttackResults, analyzer: Optional[ResultAnalyzer] = None
    ) -> str:
        """
        Generate a text-based report of attack results.

        Args:
            results: Attack results to report
            analyzer: Optional analyzer for additional insights

        Returns:
            Formatted text report
        """
        lines = []
        lines.append("=" * 80)
        lines.append("OASIS INTRUDER ATTACK REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Summary statistics
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Requests:      {results.statistics.total_requests}")
        lines.append(f"Successful:          {results.statistics.successful_requests}")
        lines.append(f"Failed:              {results.statistics.failed_requests}")
        lines.append(f"Duration:            {results.statistics.duration_seconds:.2f}s")
        lines.append(
            f"Requests/Second:     {results.statistics.requests_per_second:.2f}"
        )
        lines.append("")

        # Status code distribution
        if analyzer:
            status_groups = analyzer.group_by_status_code(results.results)
            lines.append("STATUS CODE DISTRIBUTION")
            lines.append("-" * 80)
            for status_code in sorted(status_groups.keys()):
                count = len(status_groups[status_code])
                percentage = (count / results.statistics.total_requests) * 100
                lines.append(f"{status_code}: {count} ({percentage:.1f}%)")
            lines.append("")

        # Successful payloads
        if analyzer:
            successful = analyzer.find_successful_payloads(results.results)
            if successful:
                lines.append("SUCCESSFUL PAYLOADS")
                lines.append("-" * 80)
                for i, result in enumerate(successful[:10], 1):  # Show top 10
                    payloads_str = ", ".join(
                        f"{k}={v}" for k, v in result.payloads.items()
                    )
                    status = result.response.status_code if result.response else "N/A"
                    lines.append(f"{i}. {payloads_str} (Status: {status})")
                lines.append("")

        # Anomalies
        if analyzer:
            anomalies = analyzer.find_anomalies(results.results)
            if anomalies:
                lines.append("ANOMALOUS RESPONSES")
                lines.append("-" * 80)
                for i, result in enumerate(anomalies[:10], 1):  # Show top 10
                    payloads_str = ", ".join(
                        f"{k}={v}" for k, v in result.payloads.items()
                    )
                    length = (
                        len(result.response.body)
                        if result.response and result.response.body
                        else 0
                    )
                    lines.append(f"{i}. {payloads_str} (Length: {length} bytes)")
                lines.append("")

        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(
        results: AttackResults, analyzer: Optional[ResultAnalyzer] = None
    ) -> Dict[str, Any]:
        """
        Generate a JSON-serializable report of attack results.

        Args:
            results: Attack results to report
            analyzer: Optional analyzer for additional insights

        Returns:
            Dictionary suitable for JSON serialization
        """
        report = {
            "attack_id": str(results.id),
            "attack_config_id": str(results.attack_config_id),
            "status": results.status,
            "created_at": results.created_at.isoformat(),
            "statistics": {
                "total_requests": results.statistics.total_requests,
                "successful_requests": results.statistics.successful_requests,
                "failed_requests": results.statistics.failed_requests,
                "duration_seconds": results.statistics.duration_seconds,
                "requests_per_second": results.statistics.requests_per_second,
            },
            "results": [],
        }

        # Add individual results
        for result in results.results:
            result_dict = {
                "id": str(result.id),
                "payloads": result.payloads,
                "timestamp": result.timestamp.isoformat(),
                "error": result.error,
            }

            if result.response:
                result_dict["response"] = {
                    "status_code": result.response.status_code,
                    "headers": result.response.headers,
                    "body_length": (
                        len(result.response.body) if result.response.body else 0
                    ),
                    "duration_ms": result.response.duration_ms,
                }

            report["results"].append(result_dict)

        # Add analysis if analyzer provided
        if analyzer:
            report["analysis"] = {
                "status_code_distribution": {},
                "successful_payloads": [],
                "anomalies": [],
            }

            # Status code distribution
            status_groups = analyzer.group_by_status_code(results.results)
            for status_code, group_results in status_groups.items():
                report["analysis"]["status_code_distribution"][status_code] = len(
                    group_results
                )

            # Successful payloads
            successful = analyzer.find_successful_payloads(results.results)
            for result in successful[:20]:  # Top 20
                report["analysis"]["successful_payloads"].append(
                    {
                        "payloads": result.payloads,
                        "status_code": (
                            result.response.status_code if result.response else None
                        ),
                    }
                )

            # Anomalies
            anomalies = analyzer.find_anomalies(results.results)
            for result in anomalies[:20]:  # Top 20
                report["analysis"]["anomalies"].append(
                    {
                        "payloads": result.payloads,
                        "response_length": (
                            len(result.response.body)
                            if result.response and result.response.body
                            else 0
                        ),
                    }
                )

        return report
