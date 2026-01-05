"""
OASIS Resource Management Module

Provides configurable resource limits, priority queuing, horizontal scaling support,
and performance monitoring with alerting.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List, Callable, Awaitable, Set
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum
import psutil
from collections import deque


logger = logging.getLogger(__name__)


class Priority(Enum):
    """Task priority levels."""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ResourceLimits:
    """Resource limit configuration."""

    max_memory_mb: Optional[float] = None
    max_cpu_percent: Optional[float] = None
    max_concurrent_tasks: Optional[int] = None
    max_queue_size: Optional[int] = None
    enable_auto_scaling: bool = False


@dataclass
class TaskMetrics:
    """Metrics for a queued task."""

    task_id: str
    priority: Priority
    queued_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: float = 0.0
    success: bool = False
    error: Optional[str] = None


@dataclass
class ResourceMetrics:
    """Current resource usage metrics."""

    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    memory_percent: float = 0.0
    active_tasks: int = 0
    queued_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class AlertConfig:
    """Configuration for performance alerts."""

    cpu_threshold_percent: float = 80.0
    memory_threshold_percent: float = 80.0
    queue_size_threshold: int = 100
    response_time_threshold_ms: float = 1000.0
    enable_alerts: bool = True


class PriorityQueue:
    """
    Priority-based task queue.

    Tasks are executed based on priority, with higher priority tasks
    executed first.
    """

    def __init__(self, max_size: Optional[int] = None):
        """
        Initialize priority queue.

        Args:
            max_size: Maximum queue size (None for unlimited)
        """
        self.max_size = max_size
        self._queues: Dict[Priority, deque] = {
            Priority.CRITICAL: deque(),
            Priority.HIGH: deque(),
            Priority.NORMAL: deque(),
            Priority.LOW: deque(),
        }
        self._size = 0
        self._lock = asyncio.Lock()

    async def put(self, item: Any, priority: Priority = Priority.NORMAL) -> bool:
        """
        Add item to queue with specified priority.

        Args:
            item: Item to queue
            priority: Task priority

        Returns:
            True if item was queued, False if queue is full
        """
        async with self._lock:
            if self.max_size and self._size >= self.max_size:
                return False

            self._queues[priority].append(item)
            self._size += 1
            return True

    async def get(self) -> tuple[Any, Priority]:
        """
        Get highest priority item from queue.

        Returns:
            Tuple of (item, priority)

        Raises:
            asyncio.QueueEmpty: If queue is empty
        """
        async with self._lock:
            # Check queues in priority order
            for priority in [
                Priority.CRITICAL,
                Priority.HIGH,
                Priority.NORMAL,
                Priority.LOW,
            ]:
                if self._queues[priority]:
                    item = self._queues[priority].popleft()
                    self._size -= 1
                    return item, priority

            raise asyncio.QueueEmpty("Queue is empty")

    def size(self) -> int:
        """Get current queue size."""
        return self._size

    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return self._size == 0

    def is_full(self) -> bool:
        """Check if queue is full."""
        return self.max_size is not None and self._size >= self.max_size


class ResourceManager:
    """
    Comprehensive resource management for OASIS.

    Provides configurable resource limits, priority queuing, and automatic
    resource monitoring with alerts.
    """

    def __init__(
        self,
        limits: Optional[ResourceLimits] = None,
        alert_config: Optional[AlertConfig] = None,
    ):
        """
        Initialize resource manager.

        Args:
            limits: Resource limit configuration
            alert_config: Alert configuration
        """
        self.limits = limits or ResourceLimits()
        self.alert_config = alert_config or AlertConfig()

        self._queue = PriorityQueue(max_size=self.limits.max_queue_size)
        self._active_tasks: Set[str] = set()
        self._metrics = ResourceMetrics()
        self._task_metrics: Dict[str, TaskMetrics] = {}

        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._alert_callbacks: List[
            Callable[[str, Dict[str, Any]], Awaitable[None]]
        ] = []

        self._worker_tasks: List[asyncio.Task] = []
        self._running = False

    async def start(self, num_workers: int = 10) -> None:
        """
        Start resource manager with worker pool.

        Args:
            num_workers: Number of worker tasks
        """
        if self._running:
            logger.warning("Resource manager already running")
            return

        self._running = True

        # Start worker tasks
        for i in range(num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self._worker_tasks.append(task)

        # Start monitoring
        await self.start_monitoring()

        logger.info(f"Resource manager started with {num_workers} workers")

    async def stop(self) -> None:
        """Stop resource manager and cleanup."""
        if not self._running:
            return

        self._running = False

        # Stop monitoring
        await self.stop_monitoring()

        # Cancel worker tasks
        for task in self._worker_tasks:
            task.cancel()

        # Wait for workers to finish
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()

        logger.info("Resource manager stopped")

    async def submit_task(
        self,
        task_id: str,
        task_func: Callable[[], Awaitable[Any]],
        priority: Priority = Priority.NORMAL,
    ) -> bool:
        """
        Submit a task for execution.

        Args:
            task_id: Unique task identifier
            task_func: Async function to execute
            priority: Task priority

        Returns:
            True if task was queued, False if rejected
        """
        # Check resource limits
        if not await self._check_resource_limits():
            logger.warning(f"Task {task_id} rejected: resource limits exceeded")
            return False

        # Create task metrics
        metrics = TaskMetrics(
            task_id=task_id,
            priority=priority,
            queued_at=datetime.now(UTC),
        )
        self._task_metrics[task_id] = metrics

        # Queue task
        queued = await self._queue.put((task_id, task_func), priority)

        if queued:
            self._metrics.queued_tasks += 1
            logger.debug(f"Task {task_id} queued with priority {priority.name}")
        else:
            logger.warning(f"Task {task_id} rejected: queue full")
            del self._task_metrics[task_id]

        return queued

    async def _worker_loop(self, worker_id: int) -> None:
        """
        Worker loop that processes tasks from queue.

        Args:
            worker_id: Worker identifier
        """
        logger.debug(f"Worker {worker_id} started")

        while self._running:
            try:
                # Get task from queue (with timeout)
                try:
                    await asyncio.sleep(0.1)  # Prevent tight loop

                    if self._queue.is_empty():
                        continue

                    # Check if we can execute more tasks (respect concurrent limit)
                    if self.limits.max_concurrent_tasks:
                        if len(self._active_tasks) >= self.limits.max_concurrent_tasks:
                            # Wait for active tasks to complete
                            continue

                    item, priority = await self._queue.get()
                    task_id, task_func = item

                except asyncio.QueueEmpty:
                    continue

                # Execute task
                await self._execute_task(task_id, task_func)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")

        logger.debug(f"Worker {worker_id} stopped")

    async def _execute_task(
        self, task_id: str, task_func: Callable[[], Awaitable[Any]]
    ) -> None:
        """
        Execute a task and track metrics.

        Args:
            task_id: Task identifier
            task_func: Task function to execute
        """
        metrics = self._task_metrics.get(task_id)
        if not metrics:
            return

        # Mark task as active
        self._active_tasks.add(task_id)
        self._metrics.active_tasks = len(self._active_tasks)
        self._metrics.queued_tasks = self._queue.size()

        metrics.started_at = datetime.now(UTC)
        start_time = asyncio.get_event_loop().time()

        try:
            # Execute task
            await task_func()

            metrics.success = True
            self._metrics.completed_tasks += 1

        except Exception as e:
            metrics.error = str(e)
            metrics.success = False
            self._metrics.failed_tasks += 1
            logger.error(f"Task {task_id} failed: {e}")

        finally:
            # Update metrics
            end_time = asyncio.get_event_loop().time()
            metrics.completed_at = datetime.now(UTC)
            metrics.duration_ms = (end_time - start_time) * 1000

            # Remove from active tasks
            self._active_tasks.discard(task_id)
            self._metrics.active_tasks = len(self._active_tasks)
            self._metrics.queued_tasks = self._queue.size()

    async def _check_resource_limits(self) -> bool:
        """
        Check if resource limits allow new task submission.

        Returns:
            True if resources available, False otherwise
        """
        # Check concurrent task limit
        if self.limits.max_concurrent_tasks:
            if len(self._active_tasks) >= self.limits.max_concurrent_tasks:
                return False

        # Check memory limit
        if self.limits.max_memory_mb:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            if memory_mb >= self.limits.max_memory_mb:
                return False

        # Check CPU limit
        if self.limits.max_cpu_percent:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            if cpu_percent >= self.limits.max_cpu_percent:
                return False

        return True

    async def start_monitoring(self, interval: float = 1.0) -> None:
        """
        Start resource monitoring.

        Args:
            interval: Monitoring interval in seconds
        """
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop(interval))
        logger.info("Resource monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        if not self._monitoring:
            return

        self._monitoring = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        logger.info("Resource monitoring stopped")

    async def _monitor_loop(self, interval: float) -> None:
        """Resource monitoring loop."""
        process = psutil.Process()

        while self._monitoring:
            try:
                # Update metrics
                memory_info = process.memory_info()
                self._metrics.memory_mb = memory_info.rss / (1024 * 1024)
                self._metrics.memory_percent = process.memory_percent()
                self._metrics.cpu_percent = process.cpu_percent(interval=0.1)
                self._metrics.last_updated = datetime.now(UTC)

                # Check for alerts
                if self.alert_config.enable_alerts:
                    await self._check_alerts()

                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                await asyncio.sleep(interval)

    async def _check_alerts(self) -> None:
        """Check for alert conditions and trigger callbacks."""
        alerts = []

        # CPU alert
        if self._metrics.cpu_percent >= self.alert_config.cpu_threshold_percent:
            alerts.append(
                {
                    "type": "cpu",
                    "message": f"CPU usage {self._metrics.cpu_percent:.1f}% exceeds threshold",
                    "value": self._metrics.cpu_percent,
                    "threshold": self.alert_config.cpu_threshold_percent,
                }
            )

        # Memory alert
        if self._metrics.memory_percent >= self.alert_config.memory_threshold_percent:
            alerts.append(
                {
                    "type": "memory",
                    "message": f"Memory usage {self._metrics.memory_percent:.1f}% exceeds threshold",
                    "value": self._metrics.memory_percent,
                    "threshold": self.alert_config.memory_threshold_percent,
                }
            )

        # Queue size alert
        if self._metrics.queued_tasks >= self.alert_config.queue_size_threshold:
            alerts.append(
                {
                    "type": "queue",
                    "message": f"Queue size {self._metrics.queued_tasks} exceeds threshold",
                    "value": self._metrics.queued_tasks,
                    "threshold": self.alert_config.queue_size_threshold,
                }
            )

        # Trigger alert callbacks
        for alert in alerts:
            for callback in self._alert_callbacks:
                try:
                    await callback(alert["type"], alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")

    def register_alert_callback(
        self, callback: Callable[[str, Dict[str, Any]], Awaitable[None]]
    ) -> None:
        """
        Register callback for performance alerts.

        Args:
            callback: Async function to call on alerts
        """
        self._alert_callbacks.append(callback)

    def get_metrics(self) -> ResourceMetrics:
        """
        Get current resource metrics.

        Returns:
            Current resource metrics
        """
        return self._metrics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive resource statistics.

        Returns:
            Dictionary with resource statistics
        """
        return {
            "cpu_percent": round(self._metrics.cpu_percent, 2),
            "memory_mb": round(self._metrics.memory_mb, 2),
            "memory_percent": round(self._metrics.memory_percent, 2),
            "active_tasks": self._metrics.active_tasks,
            "queued_tasks": self._metrics.queued_tasks,
            "completed_tasks": self._metrics.completed_tasks,
            "failed_tasks": self._metrics.failed_tasks,
            "limits": {
                "max_memory_mb": self.limits.max_memory_mb,
                "max_cpu_percent": self.limits.max_cpu_percent,
                "max_concurrent_tasks": self.limits.max_concurrent_tasks,
                "max_queue_size": self.limits.max_queue_size,
            },
            "running": self._running,
            "monitoring": self._monitoring,
            "last_updated": self._metrics.last_updated.isoformat(),
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()


class DistributedCoordinator:
    """
    Coordinator for distributed processing and horizontal scaling.

    Manages task distribution across multiple worker nodes for
    horizontal scaling support.
    """

    def __init__(self):
        """Initialize distributed coordinator."""
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._node_metrics: Dict[str, ResourceMetrics] = {}

    def register_node(self, node_id: str, capacity: Dict[str, Any]) -> None:
        """
        Register a worker node.

        Args:
            node_id: Unique node identifier
            capacity: Node capacity information
        """
        self._nodes[node_id] = {
            "capacity": capacity,
            "registered_at": datetime.now(UTC),
            "active": True,
        }
        logger.info(f"Node {node_id} registered with capacity: {capacity}")

    def unregister_node(self, node_id: str) -> None:
        """
        Unregister a worker node.

        Args:
            node_id: Node identifier
        """
        if node_id in self._nodes:
            self._nodes[node_id]["active"] = False
            logger.info(f"Node {node_id} unregistered")

    def select_node(self) -> Optional[str]:
        """
        Select best available node for task assignment.

        Returns:
            Node ID or None if no nodes available
        """
        # Simple round-robin selection
        active_nodes = [
            node_id for node_id, info in self._nodes.items() if info["active"]
        ]

        if not active_nodes:
            return None

        # Select node with lowest load
        best_node = None
        min_load = float("inf")

        for node_id in active_nodes:
            metrics = self._node_metrics.get(node_id)
            if metrics:
                load = metrics.active_tasks + metrics.queued_tasks
                if load < min_load:
                    min_load = load
                    best_node = node_id
            else:
                # No metrics yet, prefer this node
                best_node = node_id
                break

        return best_node or active_nodes[0]

    def update_node_metrics(self, node_id: str, metrics: ResourceMetrics) -> None:
        """
        Update metrics for a node.

        Args:
            node_id: Node identifier
            metrics: Current node metrics
        """
        self._node_metrics[node_id] = metrics

    def get_cluster_stats(self) -> Dict[str, Any]:
        """
        Get cluster-wide statistics.

        Returns:
            Dictionary with cluster statistics
        """
        active_nodes = sum(1 for info in self._nodes.values() if info["active"])

        total_active_tasks = sum(m.active_tasks for m in self._node_metrics.values())
        total_queued_tasks = sum(m.queued_tasks for m in self._node_metrics.values())

        return {
            "total_nodes": len(self._nodes),
            "active_nodes": active_nodes,
            "total_active_tasks": total_active_tasks,
            "total_queued_tasks": total_queued_tasks,
            "nodes": {
                node_id: {
                    "active": info["active"],
                    "metrics": self._node_metrics.get(node_id),
                }
                for node_id, info in self._nodes.items()
            },
        }
