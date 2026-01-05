"""
OASIS mitmproxy Addon

Custom mitmproxy addon for traffic interception and logging.
"""

import logging
from typing import Optional, Callable, List, Dict, Any, TYPE_CHECKING
from datetime import datetime, UTC

from mitmproxy import http
from mitmproxy.addons import core

from ..core.models import (
    HTTPFlow,
    HTTPRequest,
    HTTPResponse,
    RequestSource,
    FlowMetadata,
)
from .filtering import FilterEngine, FilterManager

if TYPE_CHECKING:
    from ..core.performance import PerformanceManager


logger = logging.getLogger(__name__)


class TrafficModifier:
    """
    Traffic modification handler for real-time request/response modification.
    """

    def __init__(self):
        self.request_modifiers: List[Callable[[http.Request], None]] = []
        self.response_modifiers: List[Callable[[http.Response], None]] = []
        self.header_modifications: Dict[str, str] = {}
        self.parameter_modifications: Dict[str, str] = {}
        self.body_modifications: Dict[str, bytes] = {}

    def add_request_modifier(self, modifier: Callable[[http.Request], None]) -> None:
        """Add a request modification function."""
        self.request_modifiers.append(modifier)

    def add_response_modifier(self, modifier: Callable[[http.Response], None]) -> None:
        """Add a response modification function."""
        self.response_modifiers.append(modifier)

    def set_header_modification(self, header_name: str, header_value: str) -> None:
        """Set a header to be modified in all requests."""
        self.header_modifications[header_name] = header_value

    def set_parameter_modification(self, param_name: str, param_value: str) -> None:
        """Set a parameter to be modified in all requests."""
        self.parameter_modifications[param_name] = param_value

    def set_body_modification(self, url_pattern: str, new_body: bytes) -> None:
        """Set body modification for requests matching URL pattern."""
        self.body_modifications[url_pattern] = new_body

    def modify_request(self, request: http.Request) -> None:
        """Apply all request modifications."""
        try:
            # Apply header modifications
            for header_name, header_value in self.header_modifications.items():
                request.headers[header_name] = header_value

            # Apply parameter modifications (for query parameters)
            if self.parameter_modifications:
                # Ensure query exists
                if not hasattr(request, "query") or request.query is None:
                    from mitmproxy.net.http import multidict

                    request.query = multidict.MultiDict()

                for param_name, param_value in self.parameter_modifications.items():
                    request.query[param_name] = param_value

            # Apply body modifications
            for url_pattern, new_body in self.body_modifications.items():
                if url_pattern in request.pretty_url:
                    request.content = new_body
                    # Update Content-Length header
                    request.headers["Content-Length"] = str(len(new_body))

            # Apply custom modifiers
            for modifier in self.request_modifiers:
                modifier(request)

        except Exception as e:
            logger.error(f"Error modifying request: {e}")

    def modify_response(self, response: http.Response) -> None:
        """Apply all response modifications."""
        try:
            # Apply custom modifiers
            for modifier in self.response_modifiers:
                modifier(response)

        except Exception as e:
            logger.error(f"Error modifying response: {e}")

    def clear_modifications(self) -> None:
        """Clear all modifications."""
        self.request_modifiers.clear()
        self.response_modifiers.clear()
        self.header_modifications.clear()
        self.parameter_modifications.clear()
        self.body_modifications.clear()


class OASISAddon:
    """
    Custom mitmproxy addon for OASIS traffic interception.

    Handles HTTP/HTTPS request and response interception,
    converts mitmproxy flows to OASIS data models, and
    provides callback mechanisms for real-time processing.
    """

    def __init__(
        self,
        flow_callback: Optional[Callable[[HTTPFlow], None]] = None,
        performance_manager: Optional["PerformanceManager"] = None,
    ):
        """
        Initialize the addon.

        Args:
            flow_callback: Optional callback function for intercepted flows
            performance_manager: Optional performance manager for optimized operations
        """
        self.flow_callback = flow_callback
        self.performance_manager = performance_manager
        self._flows: List[HTTPFlow] = []
        self._request_count = 0
        self._response_count = 0
        self._filtered_count = 0
        self.traffic_modifier = TrafficModifier()
        self.filter_manager = FilterManager()

        # Create default filter set
        default_filter_set = self.filter_manager.create_filter_set(
            "Default", "Default filter set for all traffic"
        )
        self.filter_manager.set_active_filter_set(str(default_filter_set.id))

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Handle intercepted HTTP requests.

        Args:
            flow: mitmproxy HTTPFlow object
        """
        try:
            self._request_count += 1

            # Convert mitmproxy request to OASIS model first for filtering
            oasis_request = self._convert_request(flow.request)

            # Apply traffic filtering
            filter_engine = self.filter_manager.get_active_filter_engine()
            if filter_engine and not filter_engine.should_include_request(
                oasis_request
            ):
                self._filtered_count += 1
                logger.debug(
                    f"Filtered out request: {flow.request.method} {flow.request.pretty_url}"
                )
                return

            # Apply traffic modifications before processing
            self.traffic_modifier.modify_request(flow.request)

            # Create OASIS flow
            oasis_flow = HTTPFlow(
                request=oasis_request, response=None, metadata=FlowMetadata()
            )

            # Store flow (will be updated when response arrives)
            self._flows.append(oasis_flow)

            logger.debug(
                f"Intercepted request: {flow.request.method} {flow.request.pretty_url}"
            )

        except Exception as e:
            logger.error(f"Error processing request: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Handle intercepted HTTP responses.

        Args:
            flow: mitmproxy HTTPFlow object
        """
        try:
            self._response_count += 1

            # Apply traffic modifications before processing
            self.traffic_modifier.modify_response(flow.response)

            # Convert mitmproxy response to OASIS model
            oasis_response = self._convert_response(flow.response)

            # Find corresponding flow and update with response
            request_url = flow.request.pretty_url
            request_method = flow.request.method

            # Find the most recent matching flow without a response
            for oasis_flow in reversed(self._flows):
                if (
                    oasis_flow.request.url == request_url
                    and oasis_flow.request.method == request_method
                    and oasis_flow.response is None
                ):

                    oasis_flow.response = oasis_response

                    # Apply response filtering
                    filter_engine = self.filter_manager.get_active_filter_engine()
                    if filter_engine and not filter_engine.should_include_response(
                        oasis_flow.request, oasis_response
                    ):
                        # Remove the flow if response filtering excludes it
                        self._flows.remove(oasis_flow)
                        self._filtered_count += 1
                        logger.debug(
                            f"Filtered out response: {flow.response.status_code} for {request_method} {request_url}"
                        )
                        return

                    # Call callback if provided
                    if self.flow_callback:
                        try:
                            self.flow_callback(oasis_flow)
                        except Exception as e:
                            logger.error(f"Error in flow callback: {e}")

                    break

            logger.debug(
                f"Intercepted response: {flow.response.status_code} for {request_method} {request_url}"
            )

        except Exception as e:
            logger.error(f"Error processing response: {e}")

    def _convert_request(self, request: http.Request) -> HTTPRequest:
        """
        Convert mitmproxy request to OASIS HTTPRequest.

        Args:
            request: mitmproxy Request object

        Returns:
            OASIS HTTPRequest object
        """
        # Convert headers to dict
        headers = dict(request.headers)

        # Get request body
        body = request.content if request.content else None

        return HTTPRequest(
            method=request.method,
            url=request.pretty_url,
            headers=headers,
            body=body,
            timestamp=datetime.now(UTC),
            source=RequestSource.PROXY,
        )

    def _convert_response(self, response: http.Response) -> HTTPResponse:
        """
        Convert mitmproxy response to OASIS HTTPResponse.

        Args:
            response: mitmproxy Response object

        Returns:
            OASIS HTTPResponse object
        """
        # Convert headers to dict
        headers = dict(response.headers)

        # Get response body
        body = response.content if response.content else None

        # Calculate duration (mitmproxy doesn't provide this directly)
        # We'll use 0 for now, can be enhanced later
        duration_ms = 0

        return HTTPResponse(
            status_code=response.status_code,
            headers=headers,
            body=body,
            timestamp=datetime.now(UTC),
            duration_ms=duration_ms,
        )

    def get_flows(self) -> List[HTTPFlow]:
        """
        Get all captured flows.

        Returns:
            List of captured HTTP flows
        """
        return self._flows.copy()

    def get_flow_count(self) -> int:
        """
        Get total number of captured flows.

        Returns:
            Number of flows
        """
        return len(self._flows)

    def get_request_count(self) -> int:
        """
        Get total number of intercepted requests.

        Returns:
            Number of requests
        """
        return self._request_count

    def get_response_count(self) -> int:
        """
        Get total number of intercepted responses.

        Returns:
            Number of responses
        """
        return self._response_count

    def clear_flows(self) -> None:
        """Clear all captured flows and reset counters."""
        self._flows.clear()
        self._request_count = 0
        self._response_count = 0
        self._filtered_count = 0

    def get_stats(self) -> Dict[str, Any]:
        """
        Get addon statistics.

        Returns:
            Dictionary containing addon statistics
        """
        stats = {
            "flows_captured": len(self._flows),
            "requests_intercepted": self._request_count,
            "responses_intercepted": self._response_count,
            "flows_filtered": self._filtered_count,
        }

        # Add filter statistics
        filter_engine = self.filter_manager.get_active_filter_engine()
        if filter_engine:
            stats["filter_stats"] = filter_engine.get_filter_stats()

        return stats

    def get_traffic_modifier(self) -> TrafficModifier:
        """
        Get the traffic modifier instance.

        Returns:
            TrafficModifier instance for configuring modifications
        """
        return self.traffic_modifier

    def get_filter_manager(self) -> FilterManager:
        """
        Get the filter manager instance.

        Returns:
            FilterManager instance for configuring traffic filtering
        """
        return self.filter_manager
