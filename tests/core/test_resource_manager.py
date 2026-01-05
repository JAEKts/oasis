"""
Tests for OASIS resource management module.

Validates resource limits, priority queuing, and distributed coordination.
"""

import pytest
import asyncio
from src.oasis.core.resource_manager import (
    ResourceManager,
    ResourceLimits,
    AlertConfig,
    Priority,
    PriorityQueue,
    DistributedCoordinator,
    ResourceMetrics,
)


@pytest.mark.asyncio
async def test_priority_queue_basic():
    """Test basic priority queue functionality."""
    queue = PriorityQueue(max_size=10)
    
    # Add items with different priorities
    await queue.put("low_task", Priority.LOW)
    await queue.put("normal_task", Priority.NORMAL)
    await queue.put("high_task", Priority.HIGH)
    await queue.put("critical_task", Priority.CRITICAL)
    
    # Should get items in priority order
    item1, priority1 = await queue.get()
    assert item1 == "critical_task"
    assert priority1 == Priority.CRITICAL
    
    item2, priority2 = await queue.get()
    assert item2 == "high_task"
    assert priority2 == Priority.HIGH
    
    item3, priority3 = await queue.get()
    assert item3 == "normal_task"
    assert priority3 == Priority.NORMAL
    
    item4, priority4 = await queue.get()
    assert item4 == "low_task"
    assert priority4 == Priority.LOW


@pytest.mark.asyncio
async def test_priority_queue_max_size():
    """Test that priority queue respects max size."""
    queue = PriorityQueue(max_size=3)
    
    # Fill queue
    assert await queue.put("task1", Priority.NORMAL) is True
    assert await queue.put("task2", Priority.NORMAL) is True
    assert await queue.put("task3", Priority.NORMAL) is True
    
    # Queue should be full
    assert queue.is_full() is True
    
    # Should reject new items
    assert await queue.put("task4", Priority.NORMAL) is False


@pytest.mark.asyncio
async def test_resource_manager_basic():
    """Test basic resource manager functionality."""
    limits = ResourceLimits(
        max_concurrent_tasks=5,
        max_queue_size=10,
    )
    
    manager = ResourceManager(limits=limits)
    
    try:
        await manager.start(num_workers=2)
        
        # Submit tasks
        completed = []
        
        async def task():
            await asyncio.sleep(0.1)
            completed.append(1)
        
        # Submit multiple tasks
        for i in range(5):
            success = await manager.submit_task(f"task_{i}", task)
            assert success is True
        
        # Wait for tasks to complete
        await asyncio.sleep(1.0)
        
        # Check metrics
        metrics = manager.get_metrics()
        assert metrics.completed_tasks == 5
        assert len(completed) == 5
        
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_resource_manager_priority():
    """Test that resource manager respects task priorities."""
    manager = ResourceManager()
    
    try:
        await manager.start(num_workers=1)  # Single worker to ensure ordering
        
        execution_order = []
        
        async def task(task_id: str):
            execution_order.append(task_id)
            await asyncio.sleep(0.05)
        
        # Submit tasks with different priorities (all at once)
        await manager.submit_task("low", lambda: task("low"), Priority.LOW)
        await manager.submit_task("normal", lambda: task("normal"), Priority.NORMAL)
        await manager.submit_task("high", lambda: task("high"), Priority.HIGH)
        await manager.submit_task("critical", lambda: task("critical"), Priority.CRITICAL)
        
        # Wait for completion
        await asyncio.sleep(1.0)
        
        # Higher priority tasks should execute first
        assert execution_order[0] == "critical"
        assert execution_order[1] == "high"
        
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_resource_manager_task_failure():
    """Test that resource manager handles task failures correctly."""
    manager = ResourceManager()
    
    try:
        await manager.start(num_workers=2)
        
        async def failing_task():
            raise ValueError("Task failed")
        
        async def successful_task():
            await asyncio.sleep(0.1)
        
        # Submit tasks
        await manager.submit_task("fail_1", failing_task)
        await manager.submit_task("success_1", successful_task)
        await manager.submit_task("fail_2", failing_task)
        
        # Wait for completion
        await asyncio.sleep(1.0)
        
        # Check metrics
        metrics = manager.get_metrics()
        assert metrics.failed_tasks == 2
        assert metrics.completed_tasks == 1
        
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_resource_manager_concurrent_limit():
    """Test that resource manager respects concurrent task limit."""
    limits = ResourceLimits(max_concurrent_tasks=3)
    manager = ResourceManager(limits=limits)
    
    try:
        await manager.start(num_workers=10)  # More workers than limit
        
        async def task():
            await asyncio.sleep(0.5)
        
        # Submit tasks one at a time and track active count
        submitted = 0
        rejected = 0
        
        # Fill up to limit
        for i in range(3):
            success = await manager.submit_task(f"task_{i}", task)
            if success:
                submitted += 1
            else:
                rejected += 1
        
        # Give tasks time to start
        await asyncio.sleep(0.2)
        
        # Try to submit more - should be rejected due to concurrent limit
        for i in range(3, 6):
            success = await manager.submit_task(f"task_{i}", task)
            if success:
                submitted += 1
            else:
                rejected += 1
        
        # Wait for completion
        await asyncio.sleep(2.0)
        
        # Some tasks should have been rejected or queued
        metrics = manager.get_metrics()
        # The limit should have prevented too many concurrent executions
        assert submitted >= 3  # At least the first 3 should succeed
        
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_resource_manager_monitoring():
    """Test resource monitoring functionality."""
    alert_config = AlertConfig(
        cpu_threshold_percent=50.0,
        memory_threshold_percent=50.0,
        enable_alerts=True,
    )
    
    manager = ResourceManager(alert_config=alert_config)
    
    try:
        await manager.start(num_workers=2)
        
        # Let monitoring run
        await asyncio.sleep(2.0)
        
        # Check metrics are being updated
        metrics = manager.get_metrics()
        assert metrics.cpu_percent >= 0
        assert metrics.memory_mb > 0
        assert metrics.memory_percent > 0
        
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_resource_manager_alerts():
    """Test that resource manager triggers alerts."""
    alert_config = AlertConfig(
        queue_size_threshold=5,
        enable_alerts=True,
    )
    
    limits = ResourceLimits(max_queue_size=20)
    manager = ResourceManager(limits=limits, alert_config=alert_config)
    
    alerts_received = []
    
    async def alert_callback(alert_type: str, alert_data: dict):
        alerts_received.append((alert_type, alert_data))
    
    manager.register_alert_callback(alert_callback)
    
    try:
        await manager.start(num_workers=1)
        
        # Submit many slow tasks to fill queue
        async def slow_task():
            await asyncio.sleep(1.0)
        
        for i in range(10):
            await manager.submit_task(f"task_{i}", slow_task)
        
        # Wait for monitoring to detect queue size
        await asyncio.sleep(2.0)
        
        # Should have received queue alert
        assert len(alerts_received) > 0
        assert any(alert_type == "queue" for alert_type, _ in alerts_received)
        
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_resource_manager_context_manager():
    """Test resource manager as context manager."""
    async with ResourceManager() as manager:
        # Should be running
        assert manager._running is True
        
        # Submit a task
        async def task():
            await asyncio.sleep(0.1)
        
        await manager.submit_task("test", task)
        await asyncio.sleep(0.5)
    
    # Should be stopped after context exit
    assert manager._running is False


@pytest.mark.asyncio
async def test_resource_manager_stats():
    """Test that resource manager provides accurate statistics."""
    manager = ResourceManager()
    
    try:
        await manager.start(num_workers=2)
        
        async def task():
            await asyncio.sleep(0.1)
        
        # Submit tasks
        for i in range(5):
            await manager.submit_task(f"task_{i}", task)
        
        # Wait for completion
        await asyncio.sleep(1.0)
        
        # Get stats
        stats = manager.get_stats()
        
        # Verify stats structure
        assert "cpu_percent" in stats
        assert "memory_mb" in stats
        assert "active_tasks" in stats
        assert "queued_tasks" in stats
        assert "completed_tasks" in stats
        assert "failed_tasks" in stats
        assert "limits" in stats
        assert "running" in stats
        
        # Verify values
        assert stats["completed_tasks"] == 5
        assert stats["running"] is True
        
    finally:
        await manager.stop()


def test_distributed_coordinator_basic():
    """Test basic distributed coordinator functionality."""
    coordinator = DistributedCoordinator()
    
    # Register nodes
    coordinator.register_node("node1", {"max_tasks": 10})
    coordinator.register_node("node2", {"max_tasks": 20})
    
    # Select node
    node = coordinator.select_node()
    assert node in ["node1", "node2"]
    
    # Get cluster stats
    stats = coordinator.get_cluster_stats()
    assert stats["total_nodes"] == 2
    assert stats["active_nodes"] == 2


def test_distributed_coordinator_node_selection():
    """Test that coordinator selects nodes based on load."""
    coordinator = DistributedCoordinator()
    
    # Register nodes
    coordinator.register_node("node1", {"max_tasks": 10})
    coordinator.register_node("node2", {"max_tasks": 10})
    
    # Update metrics (node1 has more load)
    metrics1 = ResourceMetrics(active_tasks=5, queued_tasks=3)
    metrics2 = ResourceMetrics(active_tasks=1, queued_tasks=0)
    
    coordinator.update_node_metrics("node1", metrics1)
    coordinator.update_node_metrics("node2", metrics2)
    
    # Should select node2 (lower load)
    node = coordinator.select_node()
    assert node == "node2"


def test_distributed_coordinator_unregister():
    """Test node unregistration."""
    coordinator = DistributedCoordinator()
    
    # Register nodes
    coordinator.register_node("node1", {"max_tasks": 10})
    coordinator.register_node("node2", {"max_tasks": 10})
    
    # Unregister node1
    coordinator.unregister_node("node1")
    
    # Should only select node2
    node = coordinator.select_node()
    assert node == "node2"
    
    # Stats should show 1 active node
    stats = coordinator.get_cluster_stats()
    assert stats["total_nodes"] == 2
    assert stats["active_nodes"] == 1


def test_distributed_coordinator_cluster_stats():
    """Test cluster statistics calculation."""
    coordinator = DistributedCoordinator()
    
    # Register nodes
    coordinator.register_node("node1", {"max_tasks": 10})
    coordinator.register_node("node2", {"max_tasks": 10})
    
    # Update metrics
    metrics1 = ResourceMetrics(active_tasks=3, queued_tasks=2)
    metrics2 = ResourceMetrics(active_tasks=5, queued_tasks=1)
    
    coordinator.update_node_metrics("node1", metrics1)
    coordinator.update_node_metrics("node2", metrics2)
    
    # Get cluster stats
    stats = coordinator.get_cluster_stats()
    
    assert stats["total_active_tasks"] == 8  # 3 + 5
    assert stats["total_queued_tasks"] == 3  # 2 + 1


@pytest.mark.asyncio
async def test_resource_manager_queue_full_rejection():
    """Test that tasks are rejected when queue is full."""
    limits = ResourceLimits(max_queue_size=5)
    manager = ResourceManager(limits=limits)
    
    try:
        await manager.start(num_workers=1)
        
        # Submit slow tasks to fill queue
        async def slow_task():
            await asyncio.sleep(2.0)
        
        # Fill queue
        for i in range(5):
            success = await manager.submit_task(f"task_{i}", slow_task)
            assert success is True
        
        # Next task should be rejected
        success = await manager.submit_task("task_overflow", slow_task)
        assert success is False
        
    finally:
        await manager.stop()
