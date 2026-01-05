"""
OASIS Traffic Filtering Engine

Provides configurable traffic filtering with pattern matching and real-time application.
"""

import re
import logging
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from ..core.models import (
    HTTPRequest,
    HTTPResponse,
    HTTPFlow,
    TrafficFilter,
    FilterSet,
    FilterAction,
    FilterType,
)


logger = logging.getLogger(__name__)


class FilterEngine:
    """
    Traffic filtering engine with configurable rules and real-time application.

    Supports include/exclude logic with pattern matching for hosts, paths,
    file types, and other HTTP attributes.
    """

    def __init__(self, filter_set: Optional[FilterSet] = None):
        """
        Initialize the filter engine.

        Args:
            filter_set: Optional FilterSet to use for filtering
        """
        self.filter_set = filter_set or FilterSet(
            name="Default", description="Default filter set"
        )
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def set_filter_set(self, filter_set: FilterSet) -> None:
        """
        Set the active filter set.

        Args:
            filter_set: FilterSet to use for filtering
        """
        self.filter_set = filter_set
        self._compile_patterns()

    def add_filter(self, traffic_filter: TrafficFilter) -> None:
        """
        Add a filter to the current filter set.

        Args:
            traffic_filter: TrafficFilter to add
        """
        self.filter_set.filters.append(traffic_filter)
        self._compile_pattern(traffic_filter)

    def remove_filter(self, filter_id: str) -> bool:
        """
        Remove a filter from the current filter set.

        Args:
            filter_id: ID of the filter to remove

        Returns:
            True if filter was removed, False if not found
        """
        for i, f in enumerate(self.filter_set.filters):
            if str(f.id) == filter_id:
                del self.filter_set.filters[i]
                # Remove compiled pattern
                if filter_id in self._compiled_patterns:
                    del self._compiled_patterns[filter_id]
                return True
        return False

    def should_include_request(self, request: HTTPRequest) -> bool:
        """
        Determine if a request should be included based on filter rules.

        Args:
            request: HTTPRequest to evaluate

        Returns:
            True if request should be included, False otherwise
        """
        return self._evaluate_filters(request, None)

    def should_include_response(
        self, request: HTTPRequest, response: HTTPResponse
    ) -> bool:
        """
        Determine if a response should be included based on filter rules.

        Args:
            request: Associated HTTPRequest
            response: HTTPResponse to evaluate

        Returns:
            True if response should be included, False otherwise
        """
        return self._evaluate_filters(request, response)

    def should_include_flow(self, flow: HTTPFlow) -> bool:
        """
        Determine if a complete flow should be included based on filter rules.

        Args:
            flow: HTTPFlow to evaluate

        Returns:
            True if flow should be included, False otherwise
        """
        return self._evaluate_filters(flow.request, flow.response)

    def _evaluate_filters(
        self, request: HTTPRequest, response: Optional[HTTPResponse]
    ) -> bool:
        """
        Evaluate all filters against a request/response pair.

        Args:
            request: HTTPRequest to evaluate
            response: Optional HTTPResponse to evaluate

        Returns:
            True if should be included, False otherwise
        """
        # If no filters are enabled, use default action
        enabled_filters = [f for f in self.filter_set.filters if f.enabled]
        if not enabled_filters:
            return self.filter_set.default_action == FilterAction.INCLUDE

        # Track if any include/exclude filters matched
        include_matched = False
        exclude_matched = False

        for traffic_filter in enabled_filters:
            if self._filter_matches(traffic_filter, request, response):
                if traffic_filter.action == FilterAction.INCLUDE:
                    include_matched = True
                elif traffic_filter.action == FilterAction.EXCLUDE:
                    exclude_matched = True

        # Logic: If any exclude filter matches, exclude
        # If any include filter matches and no exclude matches, include
        # Otherwise, use default action
        if exclude_matched:
            return False
        elif include_matched:
            return True
        else:
            return self.filter_set.default_action == FilterAction.INCLUDE

    def _filter_matches(
        self,
        traffic_filter: TrafficFilter,
        request: HTTPRequest,
        response: Optional[HTTPResponse],
    ) -> bool:
        """
        Check if a specific filter matches the request/response.

        Args:
            traffic_filter: TrafficFilter to evaluate
            request: HTTPRequest to check
            response: Optional HTTPResponse to check

        Returns:
            True if filter matches, False otherwise
        """
        try:
            if traffic_filter.filter_type == FilterType.HOST:
                return self._match_host(traffic_filter, request)
            elif traffic_filter.filter_type == FilterType.PATH:
                return self._match_path(traffic_filter, request)
            elif traffic_filter.filter_type == FilterType.FILE_TYPE:
                return self._match_file_type(traffic_filter, request)
            elif traffic_filter.filter_type == FilterType.METHOD:
                return self._match_method(traffic_filter, request)
            elif traffic_filter.filter_type == FilterType.STATUS_CODE:
                return self._match_status_code(traffic_filter, response)
            elif traffic_filter.filter_type == FilterType.CONTENT_TYPE:
                return self._match_content_type(traffic_filter, request, response)
            else:
                logger.warning(f"Unknown filter type: {traffic_filter.filter_type}")
                return False

        except Exception as e:
            logger.error(f"Error evaluating filter {traffic_filter.id}: {e}")
            return False

    def _match_host(self, traffic_filter: TrafficFilter, request: HTTPRequest) -> bool:
        """Match against request host."""
        try:
            parsed_url = urlparse(request.url)
            host = (
                parsed_url.netloc.lower()
                if not traffic_filter.case_sensitive
                else parsed_url.netloc
            )
            return self._pattern_matches(traffic_filter, host)
        except Exception:
            return False

    def _match_path(self, traffic_filter: TrafficFilter, request: HTTPRequest) -> bool:
        """Match against request path."""
        try:
            parsed_url = urlparse(request.url)
            path = parsed_url.path
            if not traffic_filter.case_sensitive:
                path = path.lower()
            return self._pattern_matches(traffic_filter, path)
        except Exception:
            return False

    def _match_file_type(
        self, traffic_filter: TrafficFilter, request: HTTPRequest
    ) -> bool:
        """Match against file extension in URL path."""
        try:
            parsed_url = urlparse(request.url)
            path = parsed_url.path

            # Extract file extension
            if "." in path:
                extension = path.split(".")[-1].lower()
                pattern = (
                    traffic_filter.pattern.lower()
                    if not traffic_filter.case_sensitive
                    else traffic_filter.pattern
                )

                # Remove leading dot if present in pattern
                if pattern.startswith("."):
                    pattern = pattern[1:]

                return self._pattern_matches_string(traffic_filter, extension, pattern)
            return False
        except Exception:
            return False

    def _match_method(
        self, traffic_filter: TrafficFilter, request: HTTPRequest
    ) -> bool:
        """Match against HTTP method."""
        method = request.method
        if not traffic_filter.case_sensitive:
            method = method.lower()
        return self._pattern_matches(traffic_filter, method)

    def _match_status_code(
        self, traffic_filter: TrafficFilter, response: Optional[HTTPResponse]
    ) -> bool:
        """Match against response status code."""
        if not response:
            return False

        status_str = str(response.status_code)
        return self._pattern_matches(traffic_filter, status_str)

    def _match_content_type(
        self,
        traffic_filter: TrafficFilter,
        request: HTTPRequest,
        response: Optional[HTTPResponse],
    ) -> bool:
        """Match against content type in request or response headers."""
        # Check request content type
        request_ct = request.headers.get("Content-Type", "").lower()
        if request_ct and self._pattern_matches_string(
            traffic_filter, request_ct, traffic_filter.pattern
        ):
            return True

        # Check response content type
        if response:
            response_ct = response.headers.get("Content-Type", "").lower()
            if response_ct and self._pattern_matches_string(
                traffic_filter, response_ct, traffic_filter.pattern
            ):
                return True

        return False

    def _pattern_matches(self, traffic_filter: TrafficFilter, text: str) -> bool:
        """Check if pattern matches text using the filter's configuration."""
        pattern = traffic_filter.pattern
        if not traffic_filter.case_sensitive:
            pattern = pattern.lower()
            text = text.lower()

        return self._pattern_matches_string(traffic_filter, text, pattern)

    def _pattern_matches_string(
        self, traffic_filter: TrafficFilter, text: str, pattern: str
    ) -> bool:
        """Check if pattern matches text string."""
        if traffic_filter.regex:
            # Use compiled regex pattern
            compiled_pattern = self._get_compiled_pattern(traffic_filter)
            if compiled_pattern:
                return bool(compiled_pattern.search(text))
            return False
        else:
            # Simple string matching (supports wildcards)
            return self._wildcard_match(pattern, text)

    def _wildcard_match(self, pattern: str, text: str) -> bool:
        """
        Simple wildcard matching supporting * and ?.

        Args:
            pattern: Pattern with wildcards
            text: Text to match against

        Returns:
            True if pattern matches text
        """
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        regex_pattern = f"^{regex_pattern}$"

        try:
            return bool(re.match(regex_pattern, text))
        except re.error:
            # If regex is invalid, fall back to exact match
            return pattern == text

    def _compile_patterns(self) -> None:
        """Compile all regex patterns for better performance."""
        self._compiled_patterns.clear()
        for traffic_filter in self.filter_set.filters:
            if traffic_filter.regex:
                self._compile_pattern(traffic_filter)

    def _compile_pattern(self, traffic_filter: TrafficFilter) -> None:
        """Compile a single regex pattern."""
        if not traffic_filter.regex:
            return

        try:
            flags = 0 if traffic_filter.case_sensitive else re.IGNORECASE
            pattern = re.compile(traffic_filter.pattern, flags)
            self._compiled_patterns[str(traffic_filter.id)] = pattern
        except re.error as e:
            logger.error(f"Invalid regex pattern in filter {traffic_filter.id}: {e}")

    def _get_compiled_pattern(
        self, traffic_filter: TrafficFilter
    ) -> Optional[re.Pattern]:
        """Get compiled regex pattern for a filter."""
        return self._compiled_patterns.get(str(traffic_filter.id))

    def get_filter_stats(self) -> Dict[str, Any]:
        """
        Get filtering statistics.

        Returns:
            Dictionary containing filter statistics
        """
        enabled_filters = [f for f in self.filter_set.filters if f.enabled]
        include_filters = [
            f for f in enabled_filters if f.action == FilterAction.INCLUDE
        ]
        exclude_filters = [
            f for f in enabled_filters if f.action == FilterAction.EXCLUDE
        ]

        return {
            "filter_set_name": self.filter_set.name,
            "total_filters": len(self.filter_set.filters),
            "enabled_filters": len(enabled_filters),
            "include_filters": len(include_filters),
            "exclude_filters": len(exclude_filters),
            "default_action": self.filter_set.default_action.value,
            "compiled_patterns": len(self._compiled_patterns),
        }


class FilterManager:
    """
    Manager for multiple filter sets and filtering operations.
    """

    def __init__(self):
        """Initialize the filter manager."""
        self.filter_sets: Dict[str, FilterSet] = {}
        self.active_filter_set_id: Optional[str] = None
        self._filter_engine: Optional[FilterEngine] = None

    def create_filter_set(self, name: str, description: str = "") -> FilterSet:
        """
        Create a new filter set.

        Args:
            name: Name of the filter set
            description: Description of the filter set

        Returns:
            Created FilterSet
        """
        filter_set = FilterSet(name=name, description=description)
        self.filter_sets[str(filter_set.id)] = filter_set
        return filter_set

    def get_filter_set(self, filter_set_id: str) -> Optional[FilterSet]:
        """
        Get a filter set by ID.

        Args:
            filter_set_id: ID of the filter set

        Returns:
            FilterSet if found, None otherwise
        """
        return self.filter_sets.get(filter_set_id)

    def set_active_filter_set(self, filter_set_id: str) -> bool:
        """
        Set the active filter set.

        Args:
            filter_set_id: ID of the filter set to activate

        Returns:
            True if successful, False if filter set not found
        """
        if filter_set_id in self.filter_sets:
            self.active_filter_set_id = filter_set_id
            filter_set = self.filter_sets[filter_set_id]
            self._filter_engine = FilterEngine(filter_set)
            return True
        return False

    def get_active_filter_engine(self) -> Optional[FilterEngine]:
        """
        Get the active filter engine.

        Returns:
            FilterEngine if active filter set exists, None otherwise
        """
        return self._filter_engine

    def list_filter_sets(self) -> List[FilterSet]:
        """
        List all filter sets.

        Returns:
            List of all FilterSets
        """
        return list(self.filter_sets.values())

    def delete_filter_set(self, filter_set_id: str) -> bool:
        """
        Delete a filter set.

        Args:
            filter_set_id: ID of the filter set to delete

        Returns:
            True if deleted, False if not found
        """
        if filter_set_id in self.filter_sets:
            del self.filter_sets[filter_set_id]

            # Clear active filter set if it was deleted
            if self.active_filter_set_id == filter_set_id:
                self.active_filter_set_id = None
                self._filter_engine = None

            return True
        return False


# Predefined filter sets for common use cases
def create_web_app_filter_set() -> FilterSet:
    """Create a filter set optimized for web application testing."""
    filter_set = FilterSet(
        name="Web Application Testing",
        description="Filters for typical web application penetration testing",
    )

    # Include common web paths
    filter_set.filters.extend(
        [
            TrafficFilter(
                name="Include API endpoints",
                filter_type=FilterType.PATH,
                action=FilterAction.INCLUDE,
                pattern="/api/*",
                regex=False,
            ),
            TrafficFilter(
                name="Include admin paths",
                filter_type=FilterType.PATH,
                action=FilterAction.INCLUDE,
                pattern="/admin/*",
                regex=False,
            ),
            TrafficFilter(
                name="Exclude static assets",
                filter_type=FilterType.FILE_TYPE,
                action=FilterAction.EXCLUDE,
                pattern="css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf",
                regex=True,
            ),
            TrafficFilter(
                name="Exclude OPTIONS requests",
                filter_type=FilterType.METHOD,
                action=FilterAction.EXCLUDE,
                pattern="OPTIONS",
                regex=False,
            ),
        ]
    )

    return filter_set


def create_api_testing_filter_set() -> FilterSet:
    """Create a filter set optimized for API testing."""
    filter_set = FilterSet(
        name="API Testing", description="Filters for API penetration testing"
    )

    filter_set.filters.extend(
        [
            TrafficFilter(
                name="Include JSON content",
                filter_type=FilterType.CONTENT_TYPE,
                action=FilterAction.INCLUDE,
                pattern="application/json",
                regex=False,
            ),
            TrafficFilter(
                name="Include XML content",
                filter_type=FilterType.CONTENT_TYPE,
                action=FilterAction.INCLUDE,
                pattern="application/xml",
                regex=False,
            ),
            TrafficFilter(
                name="Include API methods",
                filter_type=FilterType.METHOD,
                action=FilterAction.INCLUDE,
                pattern="GET|POST|PUT|DELETE|PATCH",
                regex=True,
            ),
            TrafficFilter(
                name="Exclude static content",
                filter_type=FilterType.CONTENT_TYPE,
                action=FilterAction.EXCLUDE,
                pattern="image/.*|text/css|application/javascript",
                regex=True,
            ),
        ]
    )

    return filter_set
