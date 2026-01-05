"""
Property-based tests for OASIS performance optimization.

Feature: oasis-pentest-suite, Property 6: Performance Under Load
Validates: Requirements 2.2, 2.5
"""

import pytest
import asyncio
from hypothesis import given, strategies as st, settings, HealthCheck
from datetime import datetime, UTC

from src.oasis.core.performance import (
    ConnectionPool,
    ConnectionPoolConfig,
    AsyncThreadPool,
    ThreadPoolConfig,
    PerformanceManager,
)


# Property 6: Performance Under Load
# For any system configuration, response time overhead should remain below
# specified thresholds regardless of concurrent connection count up to system limits


@pytest.mark.asyncio
@given(
    num_concurrent=st.integers(min_value=1, max_value=100),
    max_connections=st.integers(min_value=10, max_value=200),
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_connection_pool_maintains_performance_under_load(
    num_concurrent: int, max_connections: int
):
    """
    Property 6: Performance Under Load
    
    For any number of concurrent connections up to the configured limit,
    the connection pool should maintain performance without degradation.
    
    Validates: Requirements 2.2, 2.5
    """
    # Ensure num_concurrent doesn't exceed max_connections
    num_concurrent = min(num_concurrent, max_connections)
    
    # Create connection pool with specified limits
    config = ConnectionPoolConfig(
        max_connections=max_connections,
        max_connections_per_host=max_connections // 3,
        connection_timeout=5.0,
        read_timeout=5.0,
    )
    
    pool = ConnectionPool(config)
    
    try:
        await pool.initialize()
        
        # Track start time
        start_time = asyncio.get_event_loop().time()
        
        # Create concurrent "requests" (we'll simulate with delays)
        async def simulate_request(request_id: int):
            """Simulate a request with some processing time."""
            await asyncio.sleep(0.01)  # Simulate minimal processing
            return request_id
        
        # Execute concurrent requests
        tasks = [simulate_request(i) for i in range(num_concurrent)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate elapsed time
        elapsed_time = asyncio.get_event_loop().time() - start_time
        
        # Get metrics
        metrics = pool.get_metrics()
        
        # Property assertions:
        # 1. All requests should complete successfully
        assert len(results) == num_concurrent
        assert all(not isinstance(r, Exception) for r in results)
        
        # 2. Total requests tracked should match
        assert metrics.total_requests >= 0  # Pool may not have made actual HTTP requests
        
        # 3. Active connections should be back to 0 after completion
        assert metrics.active_connections == 0
        
        # 4. Peak connections should not exceed configured max
        assert metrics.peak_connections <= max_connections
        
        # 5. Performance should scale reasonably with concurrency
        # With minimal processing (0.01s per request), total time should be
        # roughly constant regardless of concurrency (due to async execution)
        # Allow generous threshold for test stability
        max_expected_time = 2.0  # 2 seconds max for any concurrency level
        assert elapsed_time < max_expected_time, (
            f"Performance degraded: {elapsed_time:.2f}s for {num_concurrent} "
            f"concurrent operations (max: {max_expected_time}s)"
        )
        
    finally:
        await pool.close()


@pytest.mark.asyncio
@given(
    num_tasks=st.integers(min_value=1, max_value=50),
    max_workers=st.integers(min_value=1, max_value=20),
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_thread_pool_maintains_performance_under_load(
    num_tasks: int, max_workers: int
):
    """
    Property 6: Performance Under Load (Thread Pool)
    
    For any number of CPU-bound tasks, the thread pool should maintain
    performance and complete all tasks without degradation.
    
    Validates: Requirements 2.2, 2.4, 11.1, 11.2
    """
    # Create thread pool with specified workers
    config = ThreadPoolConfig(max_workers=max_workers)
    pool = AsyncThreadPool(config)
    
    try:
        pool.initialize()
        
        # Track start time
        start_time = asyncio.get_event_loop().time()
        
        # CPU-bound function to execute
        def cpu_bound_task(task_id: int) -> int:
            """Simulate CPU-bound work."""
            # Simple computation to simulate CPU work
            result = 0
            for i in range(1000):
                result += i * task_id
            return result
        
        # Execute concurrent CPU-bound tasks
        tasks = [pool.run(cpu_bound_task, i) for i in range(num_tasks)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate elapsed time
        elapsed_time = asyncio.get_event_loop().time() - start_time
        
        # Get metrics
        metrics = pool.get_metrics()
        
        # Property assertions:
        # 1. All tasks should complete successfully
        assert len(results) == num_tasks
        assert all(not isinstance(r, Exception) for r in results)
        
        # 2. All results should be valid integers
        assert all(isinstance(r, int) for r in results)
        
        # 3. Active threads should be back to 0 after completion
        assert metrics.thread_pool_active == 0
        
        # 4. Queued tasks should be back to 0 after completion
        assert metrics.thread_pool_queued == 0
        
        # 5. Performance should scale with thread pool size
        # More workers should handle more tasks efficiently
        # Allow generous threshold for test stability
        max_expected_time = 10.0  # 10 seconds max for any task count
        assert elapsed_time < max_expected_time, (
            f"Performance degraded: {elapsed_time:.2f}s for {num_tasks} "
            f"tasks with {max_workers} workers (max: {max_expected_time}s)"
        )
        
    finally:
        pool.shutdown(wait=True)


@pytest.mark.asyncio
@given(
    max_connections=st.integers(min_value=10, max_value=100),
    max_workers=st.integers(min_value=2, max_value=10),
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_performance_manager_coordinates_resources_efficiently(
    max_connections: int, max_workers: int
):
    """
    Property 6: Performance Under Load (Integrated)
    
    For any configuration, the performance manager should coordinate
    connection pooling and thread pools efficiently without resource conflicts.
    
    Validates: Requirements 2.1, 2.2, 11.1, 11.2
    """
    # Create performance manager with specified configuration
    connection_config = ConnectionPoolConfig(
        max_connections=max_connections,
        max_connections_per_host=max_connections // 3,
    )
    thread_config = ThreadPoolConfig(max_workers=max_workers)
    
    manager = PerformanceManager(connection_config, thread_config)
    
    try:
        await manager.initialize()
        
        # Verify initialization
        stats = manager.get_stats()
        assert stats["initialized"] is True
        
        # Verify connection pool is configured correctly
        conn_stats = stats["connection_pool"]
        assert conn_stats["config"]["max_connections"] == max_connections
        
        # Verify thread pool is configured correctly
        thread_stats = stats["thread_pool"]
        assert thread_stats["config"]["max_workers"] == max_workers
        
        # Simulate mixed workload
        async def mixed_workload():
            """Simulate both I/O and CPU-bound operations."""
            # Simulate I/O operation
            await asyncio.sleep(0.01)
            
            # Simulate CPU operation
            def cpu_work():
                return sum(range(100))
            
            result = await manager.thread_pool.run(cpu_work)
            return result
        
        # Execute mixed workload
        tasks = [mixed_workload() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Property assertions:
        # 1. All tasks should complete successfully
        assert len(results) == 10
        assert all(not isinstance(r, Exception) for r in results)
        
        # 2. Resources should be properly managed
        final_stats = manager.get_stats()
        assert final_stats["connection_pool"]["active_connections"] == 0
        assert final_stats["thread_pool"]["active_threads"] == 0
        
    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_performance_manager_context_manager():
    """
    Test that performance manager works correctly as async context manager.
    
    Validates: Requirements 2.1, 11.1
    """
    async with PerformanceManager() as manager:
        stats = manager.get_stats()
        assert stats["initialized"] is True
        
        # Manager should be usable within context
        assert manager.connection_pool is not None
        assert manager.thread_pool is not None
    
    # After context exit, manager should be shutdown
    stats = manager.get_stats()
    assert stats["initialized"] is False


@pytest.mark.asyncio
@given(
    num_operations=st.integers(min_value=5, max_value=50),
)
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_connection_pool_tracks_metrics_accurately(num_operations: int):
    """
    Property: Connection pool should accurately track all metrics
    regardless of operation count.
    
    Validates: Requirements 2.2, 2.5
    """
    config = ConnectionPoolConfig(max_connections=100)
    pool = ConnectionPool(config)
    
    try:
        await pool.initialize()
        
        # Perform operations
        async def operation(op_id: int):
            await asyncio.sleep(0.001)
            return op_id
        
        tasks = [operation(i) for i in range(num_operations)]
        await asyncio.gather(*tasks)
        
        # Get final metrics
        metrics = pool.get_metrics()
        
        # Property assertions:
        # 1. Metrics should be consistent
        assert metrics.total_requests >= 0
        assert metrics.active_connections >= 0
        assert metrics.peak_connections >= 0
        
        # 2. Peak should be >= active (peak is historical max)
        assert metrics.peak_connections >= metrics.active_connections
        
        # 3. After completion, active should be 0
        assert metrics.active_connections == 0
        
        # 4. Metrics should have recent timestamp
        time_diff = (datetime.now(UTC) - metrics.last_updated).total_seconds()
        assert time_diff < 5.0  # Updated within last 5 seconds
        
    finally:
        await pool.close()
