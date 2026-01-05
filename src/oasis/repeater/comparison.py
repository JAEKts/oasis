"""
Response Comparison Utilities

Provides functionality to compare HTTP responses and analyze differences.
"""

import difflib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from ..core.models import HTTPResponse


@dataclass
class ComparisonResult:
    """Result of comparing two HTTP responses."""

    status_match: bool
    headers_match: bool
    body_match: bool

    status_diff: Optional[Tuple[int, int]]
    headers_added: Dict[str, str]
    headers_removed: Dict[str, str]
    headers_modified: Dict[str, Tuple[str, str]]

    body_diff_lines: List[str]
    body_similarity: float

    size_diff: int
    timing_diff: Optional[int]

    def __bool__(self) -> bool:
        """Returns True if responses are identical."""
        return self.status_match and self.headers_match and self.body_match

    def summary(self) -> str:
        """Get a summary of the comparison."""
        if self:
            return "Responses are identical"

        parts = []
        if not self.status_match:
            parts.append(f"Status: {self.status_diff[0]} → {self.status_diff[1]}")
        if not self.headers_match:
            parts.append(
                f"Headers: {len(self.headers_added)} added, {len(self.headers_removed)} removed, {len(self.headers_modified)} modified"
            )
        if not self.body_match:
            parts.append(
                f"Body: {self.body_similarity:.1%} similar, {self.size_diff:+d} bytes"
            )

        return " | ".join(parts)


class ResponseComparator:
    """Utility for comparing HTTP responses."""

    @staticmethod
    def compare_responses(
        response1: HTTPResponse, response2: HTTPResponse
    ) -> ComparisonResult:
        """
        Compare two HTTP responses and return detailed differences.

        Args:
            response1: First response
            response2: Second response

        Returns:
            ComparisonResult with detailed comparison information
        """
        # Compare status codes
        status_match = response1.status_code == response2.status_code
        status_diff = (
            None if status_match else (response1.status_code, response2.status_code)
        )

        # Compare headers
        headers_result = ResponseComparator._compare_headers(
            response1.headers, response2.headers
        )
        headers_match = (
            not headers_result["added"]
            and not headers_result["removed"]
            and not headers_result["modified"]
        )

        # Compare bodies
        body_result = ResponseComparator._compare_bodies(response1.body, response2.body)
        body_match = body_result["match"]

        # Calculate size difference
        size1 = len(response1.body) if response1.body else 0
        size2 = len(response2.body) if response2.body else 0
        size_diff = size2 - size1

        # Calculate timing difference
        timing_diff = response2.duration_ms - response1.duration_ms

        return ComparisonResult(
            status_match=status_match,
            headers_match=headers_match,
            body_match=body_match,
            status_diff=status_diff,
            headers_added=headers_result["added"],
            headers_removed=headers_result["removed"],
            headers_modified=headers_result["modified"],
            body_diff_lines=body_result["diff_lines"],
            body_similarity=body_result["similarity"],
            size_diff=size_diff,
            timing_diff=timing_diff,
        )

    @staticmethod
    def _compare_headers(headers1: Dict[str, str], headers2: Dict[str, str]) -> Dict:
        """Compare two header dictionaries."""
        keys1 = set(headers1.keys())
        keys2 = set(headers2.keys())

        added = {k: headers2[k] for k in keys2 - keys1}
        removed = {k: headers1[k] for k in keys1 - keys2}
        modified = {
            k: (headers1[k], headers2[k])
            for k in keys1 & keys2
            if headers1[k] != headers2[k]
        }

        return {"added": added, "removed": removed, "modified": modified}

    @staticmethod
    def _compare_bodies(body1: Optional[bytes], body2: Optional[bytes]) -> Dict:
        """Compare two response bodies."""
        # Handle None cases
        if body1 is None and body2 is None:
            return {"match": True, "diff_lines": [], "similarity": 1.0}

        if body1 is None or body2 is None:
            return {
                "match": False,
                "diff_lines": ["One body is None, the other is not"],
                "similarity": 0.0,
            }

        # Exact match check
        if body1 == body2:
            return {"match": True, "diff_lines": [], "similarity": 1.0}

        # Try to decode as text for detailed comparison
        try:
            text1 = body1.decode("utf-8")
            text2 = body2.decode("utf-8")

            lines1 = text1.splitlines(keepends=True)
            lines2 = text2.splitlines(keepends=True)

            # Generate unified diff
            diff_lines = list(
                difflib.unified_diff(
                    lines1,
                    lines2,
                    fromfile="Response 1",
                    tofile="Response 2",
                    lineterm="",
                )
            )

            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(None, text1, text2).ratio()

            return {"match": False, "diff_lines": diff_lines, "similarity": similarity}

        except UnicodeDecodeError:
            # Binary data - just compare sizes
            size1 = len(body1)
            size2 = len(body2)

            # Calculate similarity based on size difference
            max_size = max(size1, size2)
            similarity = 1.0 - abs(size1 - size2) / max_size if max_size > 0 else 1.0

            return {
                "match": False,
                "diff_lines": [f"Binary data: {size1} bytes vs {size2} bytes"],
                "similarity": similarity,
            }

    @staticmethod
    def compare_multiple_responses(
        responses: List[HTTPResponse],
    ) -> List[ComparisonResult]:
        """
        Compare multiple responses pairwise.

        Args:
            responses: List of HTTPResponse objects

        Returns:
            List of ComparisonResult objects for each pair
        """
        if len(responses) < 2:
            return []

        results = []
        for i in range(len(responses) - 1):
            result = ResponseComparator.compare_responses(
                responses[i], responses[i + 1]
            )
            results.append(result)

        return results

    @staticmethod
    def find_unique_responses(responses: List[HTTPResponse]) -> List[int]:
        """
        Find indices of unique responses in a list.

        Args:
            responses: List of HTTPResponse objects

        Returns:
            List of indices for unique responses
        """
        if not responses:
            return []

        unique_indices = [0]  # First response is always unique

        for i in range(1, len(responses)):
            is_unique = True

            for j in unique_indices:
                result = ResponseComparator.compare_responses(
                    responses[j], responses[i]
                )
                if result:  # Identical
                    is_unique = False
                    break

            if is_unique:
                unique_indices.append(i)

        return unique_indices
