"""
Tests for OASIS load testing module.

Validates load testing, memory profiling, and performance regression capabilities.
"""

import pytest
import asyncio
from src.oasis.core.load_testing import (
    LoadTester,
    LoadTestConfig,
    MemoryProfiler,
    PerformanceRegression,
)


@pytest.mark.asyncio
async def test_load_tester_basic_functionality():
    """Test basic load testing functionality."""
    config = LoadTestConfig(
        num_connections=10,
        duration_seconds=1.0,
        ramp_up_seconds=0.1,
        enable_memory_profiling=True,
    )
    
    tester = LoadTester(config)
    
    # Simple target function
    async def target(conn_id: int):
        await asyncio.sleep(0.01)
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.total_connections == 10
    assert results.successful_connections == 10
    assert results.failed_connections == 0
    assert results.avg_response_time_ms > 0
    assert results.requests_per_second > 0


@pytest.mark.asyncio
async def test_load_tester_handles_failures():
    """Test that load tester properly handles connection failures."""
    config = LoadTestConfig(
        num_connections=5,
        duration_seconds=1.0,
        ramp_up_seconds=0.0,
    )
    
    tester = LoadTester(config)
    
    # Target function that fails sometimes
    async def target(conn_id: int):
        if conn_id % 2 == 0:
            raise ValueError(f"Connection {conn_id} failed")
        await asyncio.sleep(0.01)
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.total_connections == 5
    assert results.failed_connections > 0
    assert results.successful_connections > 0
    assert len(results.errors) > 0


@pytest.mark.asyncio
async def test_load_tester_concurrent_connections():
    """Test load tester with higher concurrency."""
    config = LoadTestConfig(
        num_connections=100,
        duration_seconds=2.0,
        ramp_up_seconds=0.5,
        enable_memory_profiling=True,
    )
    
    tester = LoadTester(config)
    
    # Track concurrent executions
    concurrent_count = 0
    max_concurrent = 0
    lock = asyncio.Lock()
    
    async def target(conn_id: int):
        nonlocal concurrent_count, max_concurrent
        
        async with lock:
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)
        
        await asyncio.sleep(0.05)
        
        async with lock:
            concurrent_count -= 1
        
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.total_connections == 100
    assert results.successful_connections == 100
    assert max_concurrent > 1  # Should have concurrent execution
    assert results.peak_memory_mb > 0
    assert results.avg_memory_mb > 0


@pytest.mark.asyncio
async def test_load_tester_response_time_metrics():
    """Test that response time metrics are calculated correctly."""
    config = LoadTestConfig(
        num_connections=20,
        duration_seconds=1.0,
        ramp_up_seconds=0.0,
        enable_response_time_tracking=True,
    )
    
    tester = LoadTester(config)
    
    # Variable response times
    async def target(conn_id: int):
        delay = 0.01 + (conn_id % 5) * 0.01
        await asyncio.sleep(delay)
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.min_response_time_ms > 0
    assert results.max_response_time_ms > results.min_response_time_ms
    assert results.avg_response_time_ms > results.min_response_time_ms
    assert results.avg_response_time_ms < results.max_response_time_ms
    assert results.median_response_time_ms > 0
    assert results.p95_response_time_ms >= results.median_response_time_ms
    assert results.p99_response_time_ms >= results.p95_response_time_ms


@pytest.mark.asyncio
async def test_load_tester_timeout_handling():
    """Test that load tester handles timeouts correctly."""
    config = LoadTestConfig(
        num_connections=5,
        duration_seconds=1.0,
        request_timeout=0.1,  # Short timeout
    )
    
    tester = LoadTester(config)
    
    # Target function that times out
    async def target(conn_id: int):
        await asyncio.sleep(1.0)  # Longer than timeout
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.total_connections == 5
    assert results.failed_connections == 5  # All should timeout
    assert any("Timeout" in error for error in results.errors)


def test_memory_profiler_basic():
    """Test basic memory profiler functionality."""
    profiler = MemoryProfiler()
    
    # Start profiling
    profiler.start_profiling()
    
    # Allocate some memory
    data = [bytearray(1024 * 1024) for _ in range(10)]  # 10MB
    
    # Stop profiling
    results = profiler.stop_profiling()
    
    # Assertions
    assert "total_memory_change_mb" in results
    assert "top_allocations" in results
    assert results["total_memory_change_mb"] > 0
    
    # Clean up
    del data


def test_memory_profiler_context_manager():
    """Test memory profiler as context manager."""
    with MemoryProfiler() as profiler:
        # Allocate memory
        data = bytearray(5 * 1024 * 1024)  # 5MB
    
    # Profiler should have stopped automatically
    assert not profiler._profiling


def test_performance_regression_baseline():
    """Test recording and checking performance baselines."""
    regression = PerformanceRegression()
    
    # Record baseline
    baseline_metrics = {
        "response_time_ms": 100.0,
        "memory_mb": 50.0,
        "requests_per_second": 1000.0,
    }
    regression.record_baseline("test_api", baseline_metrics)
    
    # Check with similar metrics (no regression)
    current_metrics = {
        "response_time_ms": 105.0,  # 5% increase
        "memory_mb": 52.0,  # 4% increase
        "requests_per_second": 980.0,  # 2% decrease
    }
    result = regression.check_regression("test_api", current_metrics, threshold_percent=10.0)
    
    # Assertions
    assert result["has_regression"] is False


def test_performance_regression_detection():
    """Test that performance regression is detected."""
    regression = PerformanceRegression()
    
    # Record baseline
    baseline_metrics = {
        "response_time_ms": 100.0,
        "memory_mb": 50.0,
    }
    regression.record_baseline("test_api", baseline_metrics)
    
    # Check with regressed metrics
    current_metrics = {
        "response_time_ms": 150.0,  # 50% increase - regression!
        "memory_mb": 52.0,  # 4% increase - OK
    }
    result = regression.check_regression("test_api", current_metrics, threshold_percent=10.0)
    
    # Assertions
    assert result["has_regression"] is True
    assert len(result["regressions"]) > 0
    assert any(r["metric"] == "response_time_ms" for r in result["regressions"])


def test_performance_regression_no_baseline():
    """Test regression check with no baseline."""
    regression = PerformanceRegression()
    
    # Check without baseline
    current_metrics = {"response_time_ms": 100.0}
    result = regression.check_regression("unknown_test", current_metrics)
    
    # Assertions
    assert result["has_regression"] is False
    assert "No baseline" in result["reason"]


@pytest.mark.asyncio
async def test_load_tester_memory_leak_detection():
    """Test that load tester can detect memory leaks."""
    config = LoadTestConfig(
        num_connections=50,
        duration_seconds=1.0,
        enable_memory_profiling=True,
    )
    
    tester = LoadTester(config)
    
    # Target function that "leaks" memory
    leaked_data = []
    
    async def target(conn_id: int):
        # Simulate memory leak
        leaked_data.append(bytearray(1024 * 100))  # 100KB per connection
        await asyncio.sleep(0.01)
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.memory_leaked_mb > 0  # Should detect memory increase
    
    # Clean up
    leaked_data.clear()


@pytest.mark.asyncio
async def test_load_tester_throughput_calculation():
    """Test that throughput metrics are calculated correctly."""
    config = LoadTestConfig(
        num_connections=100,
        duration_seconds=2.0,
        ramp_up_seconds=0.1,
    )
    
    tester = LoadTester(config)
    
    async def target(conn_id: int):
        await asyncio.sleep(0.01)
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.requests_per_second > 0
    assert results.total_duration_seconds > 0
    
    # Verify calculation
    expected_rps = results.successful_connections / results.total_duration_seconds
    assert abs(results.requests_per_second - expected_rps) < 0.01


@pytest.mark.asyncio
async def test_load_tester_with_zero_connections():
    """Test load tester handles edge case of zero connections."""
    config = LoadTestConfig(
        num_connections=0,
        duration_seconds=1.0,
    )
    
    tester = LoadTester(config)
    
    async def target(conn_id: int):
        return conn_id
    
    # Run load test
    results = await tester.run_load_test(target)
    
    # Assertions
    assert results.total_connections == 0
    assert results.successful_connections == 0
    assert results.failed_connections == 0
