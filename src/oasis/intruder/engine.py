"""
Attack Engine

Executes intruder attacks with rate limiting and result analysis.
"""

import asyncio
import uuid
import time
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field
import itertools

from ..core.models import HTTPRequest, HTTPResponse, RequestSource
from ..core.exceptions import OASISException
from .config import AttackConfig, AttackType, InjectionPoint, PayloadSet
from .payloads import PayloadGenerator, create_generator


class IntruderError(OASISException):
    """Exception raised for intruder-related errors."""

    pass


class AttackResult(BaseModel):
    """Result from a single attack request."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique result ID")
    request: HTTPRequest = Field(description="Request sent")
    response: Optional[HTTPResponse] = Field(
        default=None, description="Response received"
    )
    payloads: Dict[str, str] = Field(
        description="Payloads used for each injection point"
    )
    error: Optional[str] = Field(
        default=None, description="Error message if request failed"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Result timestamp"
    )


class AttackStatistics(BaseModel):
    """Statistics for an attack session."""

    total_requests: int = Field(default=0, description="Total requests sent")
    successful_requests: int = Field(
        default=0, description="Successful requests (2xx, 3xx)"
    )
    failed_requests: int = Field(
        default=0, description="Failed requests (4xx, 5xx, errors)"
    )
    total_payloads: int = Field(default=0, description="Total payloads generated")
    start_time: Optional[datetime] = Field(
        default=None, description="Attack start time"
    )
    end_time: Optional[datetime] = Field(default=None, description="Attack end time")
    duration_seconds: float = Field(default=0.0, description="Attack duration")
    requests_per_second: float = Field(
        default=0.0, description="Average requests per second"
    )


class AttackResults(BaseModel):
    """Complete results from an attack session."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique results ID")
    attack_config_id: uuid.UUID = Field(
        description="Associated attack configuration ID"
    )
    results: List[AttackResult] = Field(
        default_factory=list, description="Individual attack results"
    )
    statistics: AttackStatistics = Field(
        default_factory=AttackStatistics, description="Attack statistics"
    )
    status: str = Field(
        default="pending",
        description="Attack status: pending, running, completed, failed",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Creation timestamp"
    )


class AttackEngine:
    """
    Attack engine that executes intruder attacks.

    Supports multiple attack types with rate limiting and concurrent execution.
    """

    def __init__(self):
        self._active_attacks: Dict[uuid.UUID, AttackResults] = {}

    async def execute_attack(self, attack_config: AttackConfig) -> AttackResults:
        """
        Execute an attack based on the configuration.

        Args:
            attack_config: Attack configuration

        Returns:
            AttackResults with all results and statistics

        Raises:
            IntruderError: If attack execution fails
        """
        # Validate attack configuration
        try:
            attack_config.validate_attack_configuration()
        except ValueError as e:
            raise IntruderError(f"Invalid attack configuration: {e}")

        # Create results object
        results = AttackResults(attack_config_id=attack_config.id, status="running")
        results.statistics.start_time = datetime.now(UTC)

        # Store active attack
        self._active_attacks[results.id] = results

        try:
            # Generate payload combinations based on attack type
            payload_combinations = await self._generate_payload_combinations(
                attack_config
            )
            results.statistics.total_payloads = len(payload_combinations)

            # Execute requests with rate limiting
            await self._execute_requests(attack_config, payload_combinations, results)

            # Mark as completed
            results.status = "completed"
            results.statistics.end_time = datetime.now(UTC)

            # Calculate statistics
            if results.statistics.start_time:
                duration = results.statistics.end_time - results.statistics.start_time
                results.statistics.duration_seconds = duration.total_seconds()

                if results.statistics.duration_seconds > 0:
                    results.statistics.requests_per_second = (
                        results.statistics.total_requests
                        / results.statistics.duration_seconds
                    )

        except Exception as e:
            results.status = "failed"
            raise IntruderError(f"Attack execution failed: {e}")

        return results

    async def _generate_payload_combinations(
        self, attack_config: AttackConfig
    ) -> List[Dict[str, str]]:
        """
        Generate all payload combinations based on attack type.

        Args:
            attack_config: Attack configuration

        Returns:
            List of payload dictionaries mapping injection point IDs to payloads
        """
        # Create generators for each payload set
        generators: List[PayloadGenerator] = []
        for payload_set in attack_config.payload_sets:
            generator = create_generator(
                payload_set.generator_type, payload_set.generator_config
            )
            generators.append(generator)

        # Collect all payloads from generators
        all_payloads: List[List[str]] = []
        for generator in generators:
            payloads = []
            async for payload in generator.generate():
                payloads.append(payload)
            all_payloads.append(payloads)

        # Apply processors to payloads
        for i, payload_set in enumerate(attack_config.payload_sets):
            if payload_set.processors:
                processed_payloads = []
                for payload in all_payloads[i]:
                    processed = payload
                    for processor in payload_set.processors:
                        processed = processor.process(processed)
                    processed_payloads.append(processed)
                all_payloads[i] = processed_payloads

        # Generate combinations based on attack type
        combinations: List[Dict[str, str]] = []

        if attack_config.attack_type == AttackType.SNIPER:
            # One injection point at a time, cycling through all injection points
            payloads = all_payloads[0]
            for injection_point in attack_config.injection_points:
                for payload in payloads:
                    combo = {injection_point.marker: payload}
                    combinations.append(combo)

        elif attack_config.attack_type == AttackType.BATTERING_RAM:
            # All injection points get the same payload simultaneously
            payloads = all_payloads[0]
            for payload in payloads:
                combo = {ip.marker: payload for ip in attack_config.injection_points}
                combinations.append(combo)

        elif attack_config.attack_type == AttackType.PITCHFORK:
            # Synchronized iteration across all payload sets
            for payload_tuple in zip(*all_payloads):
                combo = {}
                for i, injection_point in enumerate(attack_config.injection_points):
                    combo[injection_point.marker] = payload_tuple[i]
                combinations.append(combo)

        elif attack_config.attack_type == AttackType.CLUSTER_BOMB:
            # Cartesian product of all payload sets
            for payload_tuple in itertools.product(*all_payloads):
                combo = {}
                for i, injection_point in enumerate(attack_config.injection_points):
                    combo[injection_point.marker] = payload_tuple[i]
                combinations.append(combo)

        return combinations

    async def _execute_requests(
        self,
        attack_config: AttackConfig,
        payload_combinations: List[Dict[str, str]],
        results: AttackResults,
    ) -> None:
        """
        Execute requests with rate limiting.

        Args:
            attack_config: Attack configuration
            payload_combinations: List of payload combinations to test
            results: Results object to populate
        """
        # Create semaphore for concurrent request limiting
        semaphore = asyncio.Semaphore(attack_config.rate_limiting.concurrent_requests)

        # Calculate delay between requests
        delay = attack_config.rate_limiting.delay_ms / 1000.0

        # Execute requests
        tasks = []
        for combo in payload_combinations:
            task = self._execute_single_request(
                attack_config, combo, results, semaphore, delay
            )
            tasks.append(task)

        # Wait for all requests to complete
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _execute_single_request(
        self,
        attack_config: AttackConfig,
        payload_combo: Dict[str, str],
        results: AttackResults,
        semaphore: asyncio.Semaphore,
        delay: float,
    ) -> None:
        """
        Execute a single request with payload injection.

        Args:
            attack_config: Attack configuration
            payload_combo: Payload combination to inject
            results: Results object to update
            semaphore: Semaphore for concurrency control
            delay: Delay before request in seconds
        """
        async with semaphore:
            # Apply delay if configured
            if delay > 0:
                await asyncio.sleep(delay)

            try:
                # Create request with injected payloads
                request = self._inject_payloads(
                    attack_config.base_request, payload_combo
                )

                # Send request (placeholder - would use actual HTTP client)
                response = await self._send_request(
                    request, attack_config.timeout_seconds
                )

                # Create result
                result = AttackResult(
                    request=request, response=response, payloads=payload_combo
                )

                # Update statistics
                results.results.append(result)
                results.statistics.total_requests += 1

                if response and 200 <= response.status_code < 400:
                    results.statistics.successful_requests += 1
                else:
                    results.statistics.failed_requests += 1

            except Exception as e:
                # Create error result
                result = AttackResult(
                    request=attack_config.base_request,
                    payloads=payload_combo,
                    error=str(e),
                )
                results.results.append(result)
                results.statistics.total_requests += 1
                results.statistics.failed_requests += 1

    def _inject_payloads(
        self, base_request: HTTPRequest, payload_combo: Dict[str, str]
    ) -> HTTPRequest:
        """
        Inject payloads into the base request.

        Args:
            base_request: Base request template
            payload_combo: Payload combination mapping markers to payloads

        Returns:
            New HTTPRequest with payloads injected
        """
        # Create a copy of the request
        request_dict = base_request.model_dump()

        # Inject into URL
        url = request_dict["url"]
        for marker, payload in payload_combo.items():
            url = url.replace(marker, payload)
        request_dict["url"] = url

        # Inject into headers
        headers = dict(request_dict.get("headers", {}))
        for key, value in headers.items():
            for marker, payload in payload_combo.items():
                value = value.replace(marker, payload)
            headers[key] = value
        request_dict["headers"] = headers

        # Inject into body
        if request_dict.get("body"):
            body = request_dict["body"]
            if isinstance(body, bytes):
                body_str = body.decode("utf-8", errors="ignore")
                for marker, payload in payload_combo.items():
                    body_str = body_str.replace(marker, payload)
                request_dict["body"] = body_str.encode("utf-8")

        # Set source to intruder
        request_dict["source"] = RequestSource.INTRUDER

        return HTTPRequest(**request_dict)

    async def _send_request(
        self, request: HTTPRequest, timeout: int
    ) -> Optional[HTTPResponse]:
        """
        Send HTTP request and return response.

        This is a placeholder implementation. In production, this would use
        an actual HTTP client like aiohttp.

        Args:
            request: HTTP request to send
            timeout: Request timeout in seconds

        Returns:
            HTTPResponse or None if request failed
        """
        # Placeholder - would implement actual HTTP request here
        # For now, return a mock response
        await asyncio.sleep(0.01)  # Simulate network delay

        return HTTPResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"<html><body>Mock response</body></html>",
            duration_ms=10,
        )

    def get_attack_results(self, results_id: uuid.UUID) -> Optional[AttackResults]:
        """Get attack results by ID."""
        return self._active_attacks.get(results_id)

    def list_active_attacks(self) -> List[AttackResults]:
        """List all active attack sessions."""
        return list(self._active_attacks.values())
