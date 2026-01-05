"""
OASIS Load Testing Module

Provides comprehensive load testing capabilities for 1000+ concurrent connections,
memory profiling, and performance regression testing.
"""

import asyncio
import logging
import time
import statistics
from typing import Optional, Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, UTC
import psutil
import tracemalloc


logger = logging.getLogger(__name__)


@dataclass
class LoadTestConfig:
    """Configuration for load testing."""

    num_connections: int = 100
    duration_seconds: float = 10.0
    ramp_up_seconds: float = 1.0
    target_url: str = "http://localhost:8080"
    request_timeout: float = 30.0
    enable_memory_profiling: bool = True
    enable_response_time_tracking: bool = True


@dataclass
class ConnectionMetrics:
    """Metrics for a single connection."""

    connection_id: int
    start_time: float
    end_time: float
    duration_ms: float
    success: bool
    error: Optional[str] = None
    response_code: Optional[int] = None
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class LoadTestResults:
    """Results from a load test."""

    config: LoadTestConfig
    start_time: datetime
    end_time: datetime
    total_duration_seconds: float

    # Connection metrics
    total_connections: int = 0
    successful_connections: int = 0
    failed_connections: int = 0

    # Response time metrics (milliseconds)
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    avg_response_time_ms: float = 0.0
    median_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0

    # Throughput metrics
    requests_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # Memory metrics
    peak_memory_mb: float = 0.0
    avg_memory_mb: float = 0.0
    memory_leaked_mb: float = 0.0

    # Error tracking
    errors: List[str] = field(default_factory=list)

    # Detailed connection metrics
    connection_metrics: List[ConnectionMetrics] = field(default_factory=list)


class LoadTester:
    """
    Comprehensive load testing for OASIS system.

    Supports testing with 1000+ concurrent connections, memory profiling,
    and detailed performance metrics collection.
    """

    def __init__(self, config: Optional[LoadTestConfig] = None):
        """
        Initialize load tester.

        Args:
            config: Load test configuration
        """
        self.config = config or LoadTestConfig()
        self._memory_samples: List[float] = []
        self._start_memory: float = 0.0
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None

    async def run_load_test(
        self, target_function: Callable[[int], Awaitable[Any]]
    ) -> LoadTestResults:
        """
        Run a load test with specified target function.

        Args:
            target_function: Async function to test (receives connection_id)

        Returns:
            Load test results
        """
        logger.info(
            f"Starting load test: {self.config.num_connections} connections, "
            f"{self.config.duration_seconds}s duration"
        )

        # Initialize results
        start_time = datetime.now(UTC)
        results = LoadTestResults(
            config=self.config,
            start_time=start_time,
            end_time=start_time,  # Will be updated
            total_duration_seconds=0.0,
        )

        # Start memory monitoring if enabled
        if self.config.enable_memory_profiling:
            self._start_memory_monitoring()

        # Record start memory
        process = psutil.Process()
        start_memory_mb = process.memory_info().rss / (1024 * 1024)
        self._start_memory = start_memory_mb

        # Run load test
        test_start = time.time()

        try:
            # Create connection tasks with ramp-up
            tasks = []
            ramp_up_delay = (
                self.config.ramp_up_seconds / self.config.num_connections
                if self.config.num_connections > 0
                else 0
            )

            for conn_id in range(self.config.num_connections):
                # Add ramp-up delay
                if ramp_up_delay > 0:
                    await asyncio.sleep(ramp_up_delay)

                # Create connection task
                task = asyncio.create_task(
                    self._run_connection(conn_id, target_function)
                )
                tasks.append(task)

            # Wait for all connections to complete or timeout
            connection_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for result in connection_results:
                if isinstance(result, Exception):
                    results.failed_connections += 1
                    results.errors.append(str(result))
                elif isinstance(result, ConnectionMetrics):
                    results.connection_metrics.append(result)
                    results.total_connections += 1

                    if result.success:
                        results.successful_connections += 1
                    else:
                        results.failed_connections += 1
                        if result.error:
                            results.errors.append(result.error)

        finally:
            # Stop memory monitoring
            if self.config.enable_memory_profiling:
                self._stop_memory_monitoring()

        # Calculate test duration
        test_end = time.time()
        results.total_duration_seconds = test_end - test_start
        results.end_time = datetime.now(UTC)

        # Calculate response time metrics
        if results.connection_metrics:
            response_times = [
                m.duration_ms for m in results.connection_metrics if m.success
            ]

            if response_times:
                results.min_response_time_ms = min(response_times)
                results.max_response_time_ms = max(response_times)
                results.avg_response_time_ms = statistics.mean(response_times)
                results.median_response_time_ms = statistics.median(response_times)

                # Calculate percentiles
                sorted_times = sorted(response_times)
                p95_idx = int(len(sorted_times) * 0.95)
                p99_idx = int(len(sorted_times) * 0.99)
                results.p95_response_time_ms = (
                    sorted_times[p95_idx]
                    if p95_idx < len(sorted_times)
                    else sorted_times[-1]
                )
                results.p99_response_time_ms = (
                    sorted_times[p99_idx]
                    if p99_idx < len(sorted_times)
                    else sorted_times[-1]
                )

        # Calculate throughput metrics
        if results.total_duration_seconds > 0:
            results.requests_per_second = (
                results.successful_connections / results.total_duration_seconds
            )

            total_bytes = sum(
                m.bytes_sent + m.bytes_received for m in results.connection_metrics
            )
            results.bytes_per_second = total_bytes / results.total_duration_seconds

        # Calculate memory metrics
        if self._memory_samples:
            results.peak_memory_mb = max(self._memory_samples)
            results.avg_memory_mb = statistics.mean(self._memory_samples)

        # Calculate memory leak
        end_memory_mb = process.memory_info().rss / (1024 * 1024)
        results.memory_leaked_mb = end_memory_mb - start_memory_mb

        logger.info(
            f"Load test complete: {results.successful_connections}/{results.total_connections} "
            f"successful, avg response time: {results.avg_response_time_ms:.2f}ms"
        )

        return results

    async def _run_connection(
        self, connection_id: int, target_function: Callable[[int], Awaitable[Any]]
    ) -> ConnectionMetrics:
        """
        Run a single connection test.

        Args:
            connection_id: Connection identifier
            target_function: Function to execute

        Returns:
            Connection metrics
        """
        start_time = time.time()

        metrics = ConnectionMetrics(
            connection_id=connection_id,
            start_time=start_time,
            end_time=0.0,
            duration_ms=0.0,
            success=False,
        )

        try:
            # Execute target function with timeout
            await asyncio.wait_for(
                target_function(connection_id), timeout=self.config.request_timeout
            )

            metrics.success = True

        except asyncio.TimeoutError:
            metrics.error = "Timeout"
        except Exception as e:
            metrics.error = str(e)

        finally:
            end_time = time.time()
            metrics.end_time = end_time
            metrics.duration_ms = (end_time - start_time) * 1000

        return metrics

    def _start_memory_monitoring(self) -> None:
        """Start memory monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._memory_samples = []
        self._monitor_task = asyncio.create_task(self._memory_monitor_loop())

    def _stop_memory_monitoring(self) -> None:
        """Stop memory monitoring."""
        if not self._monitoring:
            return

        self._monitoring = False

        if self._monitor_task:
            self._monitor_task.cancel()
            self._monitor_task = None

    async def _memory_monitor_loop(self) -> None:
        """Memory monitoring loop."""
        process = psutil.Process()

        while self._monitoring:
            try:
                memory_mb = process.memory_info().rss / (1024 * 1024)
                self._memory_samples.append(memory_mb)
                await asyncio.sleep(0.1)  # Sample every 100ms
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in memory monitoring: {e}")


class MemoryProfiler:
    """
    Memory profiling and leak detection.

    Uses tracemalloc to track memory allocations and detect leaks.
    """

    def __init__(self):
        """Initialize memory profiler."""
        self._profiling = False
        self._snapshot_before: Optional[Any] = None
        self._snapshot_after: Optional[Any] = None

    def start_profiling(self) -> None:
        """Start memory profiling."""
        if self._profiling:
            logger.warning("Memory profiling already started")
            return

        tracemalloc.start()
        self._snapshot_before = tracemalloc.take_snapshot()
        self._profiling = True
        logger.info("Memory profiling started")

    def stop_profiling(self) -> Dict[str, Any]:
        """
        Stop memory profiling and return results.

        Returns:
            Dictionary with profiling results
        """
        if not self._profiling:
            logger.warning("Memory profiling not started")
            return {}

        self._snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()
        self._profiling = False

        # Calculate statistics
        top_stats = self._snapshot_after.compare_to(self._snapshot_before, "lineno")

        # Get top memory allocations
        top_allocations = []
        for stat in top_stats[:10]:  # Top 10
            top_allocations.append(
                {
                    "file": stat.traceback.format()[0] if stat.traceback else "unknown",
                    "size_mb": stat.size / (1024 * 1024),
                    "size_diff_mb": stat.size_diff / (1024 * 1024),
                    "count": stat.count,
                    "count_diff": stat.count_diff,
                }
            )

        # Calculate total memory change
        total_size_diff = sum(stat.size_diff for stat in top_stats)

        results = {
            "total_memory_change_mb": total_size_diff / (1024 * 1024),
            "top_allocations": top_allocations,
            "total_allocations": len(top_stats),
        }

        logger.info(
            f"Memory profiling complete: "
            f"{results['total_memory_change_mb']:.2f}MB change"
        )

        return results

    def __enter__(self):
        """Context manager entry."""
        self.start_profiling()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_profiling()


class PerformanceRegression:
    """
    Performance regression testing.

    Tracks performance metrics over time and detects regressions.
    """

    def __init__(self, baseline_file: Optional[str] = None):
        """
        Initialize performance regression tester.

        Args:
            baseline_file: Path to baseline metrics file
        """
        self.baseline_file = baseline_file
        self._baselines: Dict[str, Dict[str, float]] = {}

    def record_baseline(self, test_name: str, metrics: Dict[str, float]) -> None:
        """
        Record baseline metrics for a test.

        Args:
            test_name: Name of the test
            metrics: Performance metrics
        """
        self._baselines[test_name] = metrics.copy()
        logger.info(f"Recorded baseline for {test_name}: {metrics}")

    def check_regression(
        self,
        test_name: str,
        current_metrics: Dict[str, float],
        threshold_percent: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Check for performance regression.

        Args:
            test_name: Name of the test
            current_metrics: Current performance metrics
            threshold_percent: Regression threshold percentage

        Returns:
            Dictionary with regression analysis
        """
        if test_name not in self._baselines:
            logger.warning(f"No baseline found for {test_name}")
            return {
                "has_regression": False,
                "reason": "No baseline available",
            }

        baseline = self._baselines[test_name]
        regressions = []

        for metric_name, current_value in current_metrics.items():
            if metric_name not in baseline:
                continue

            baseline_value = baseline[metric_name]

            # Calculate percentage change
            if baseline_value > 0:
                percent_change = (current_value - baseline_value) / baseline_value * 100

                # Check if regression (higher is worse for time/memory metrics)
                if percent_change > threshold_percent:
                    regressions.append(
                        {
                            "metric": metric_name,
                            "baseline": baseline_value,
                            "current": current_value,
                            "percent_change": percent_change,
                        }
                    )

        result = {
            "has_regression": len(regressions) > 0,
            "regressions": regressions,
            "test_name": test_name,
            "threshold_percent": threshold_percent,
        }

        if regressions:
            logger.warning(
                f"Performance regression detected in {test_name}: "
                f"{len(regressions)} metrics regressed"
            )
        else:
            logger.info(f"No regression detected in {test_name}")

        return result
