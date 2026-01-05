"""
OASIS Performance Optimization Module

Provides high-performance async I/O processing, connection pooling,
and resource management for optimal throughput.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, Callable, Awaitable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, UTC
import aiohttp
from aiohttp import ClientSession, TCPConnector, ClientTimeout


logger = logging.getLogger(__name__)


@dataclass
class ConnectionPoolConfig:
    """Configuration for HTTP connection pooling."""

    max_connections: int = 100
    max_connections_per_host: int = 30
    connection_timeout: float = 30.0
    read_timeout: float = 30.0
    keepalive_timeout: float = 30.0
    enable_cleanup_closed: bool = True


@dataclass
class ThreadPoolConfig:
    """Configuration for CPU-bound operation thread pools."""

    max_workers: int = 10
    thread_name_prefix: str = "oasis-worker"


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""

    total_requests: int = 0
    active_connections: int = 0
    pooled_connections: int = 0
    thread_pool_active: int = 0
    thread_pool_queued: int = 0
    avg_response_time_ms: float = 0.0
    peak_connections: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))


class ConnectionPool:
    """
    High-performance HTTP connection pool using aiohttp.

    Provides connection pooling, keepalive, and automatic connection management
    for optimal throughput in HTTP operations.
    """

    def __init__(self, config: Optional[ConnectionPoolConfig] = None):
        """
        Initialize connection pool.

        Args:
            config: Connection pool configuration
        """
        self.config = config or ConnectionPoolConfig()
        self._session: Optional[ClientSession] = None
        self._connector: Optional[TCPConnector] = None
        self._metrics = PerformanceMetrics()
        self._response_times: list[float] = []

    async def initialize(self) -> None:
        """Initialize the connection pool."""
        if self._session is not None:
            logger.warning("Connection pool already initialized")
            return

        # Create TCP connector with connection pooling
        self._connector = TCPConnector(
            limit=self.config.max_connections,
            limit_per_host=self.config.max_connections_per_host,
            ttl_dns_cache=300,  # DNS cache TTL
            enable_cleanup_closed=self.config.enable_cleanup_closed,
            force_close=False,  # Keep connections alive
        )

        # Create timeout configuration
        timeout = ClientTimeout(
            total=self.config.connection_timeout,
            connect=self.config.connection_timeout,
            sock_read=self.config.read_timeout,
        )

        # Create session with connector
        self._session = ClientSession(
            connector=self._connector,
            timeout=timeout,
            connector_owner=True,
        )

        logger.info(
            f"Connection pool initialized: max={self.config.max_connections}, "
            f"per_host={self.config.max_connections_per_host}"
        )

    async def close(self) -> None:
        """Close the connection pool and cleanup resources."""
        if self._session:
            await self._session.close()
            self._session = None
            self._connector = None
            logger.info("Connection pool closed")

    async def request(
        self, method: str, url: str, **kwargs: Any
    ) -> aiohttp.ClientResponse:
        """
        Make an HTTP request using the connection pool.

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters

        Returns:
            aiohttp ClientResponse

        Raises:
            RuntimeError: If connection pool not initialized
        """
        if self._session is None:
            raise RuntimeError(
                "Connection pool not initialized. Call initialize() first."
            )

        start_time = asyncio.get_event_loop().time()

        try:
            self._metrics.total_requests += 1
            self._metrics.active_connections += 1

            # Update peak connections
            if self._metrics.active_connections > self._metrics.peak_connections:
                self._metrics.peak_connections = self._metrics.active_connections

            response = await self._session.request(method, url, **kwargs)

            # Track response time
            elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            self._response_times.append(elapsed_ms)

            # Keep only last 1000 response times for average calculation
            if len(self._response_times) > 1000:
                self._response_times = self._response_times[-1000:]

            # Update average response time
            self._metrics.avg_response_time_ms = sum(self._response_times) / len(
                self._response_times
            )

            return response

        finally:
            self._metrics.active_connections -= 1
            self._metrics.last_updated = datetime.now(UTC)

    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    def get_metrics(self) -> PerformanceMetrics:
        """
        Get current performance metrics.

        Returns:
            Current performance metrics
        """
        # Update pooled connections count from connector
        if self._connector:
            self._metrics.pooled_connections = len(self._connector._conns)

        return self._metrics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get connection pool statistics.

        Returns:
            Dictionary with pool statistics
        """
        metrics = self.get_metrics()

        stats = {
            "total_requests": metrics.total_requests,
            "active_connections": metrics.active_connections,
            "pooled_connections": metrics.pooled_connections,
            "peak_connections": metrics.peak_connections,
            "avg_response_time_ms": round(metrics.avg_response_time_ms, 2),
            "config": {
                "max_connections": self.config.max_connections,
                "max_connections_per_host": self.config.max_connections_per_host,
            },
            "last_updated": metrics.last_updated.isoformat(),
        }

        return stats


class AsyncThreadPool:
    """
    Thread pool for CPU-bound operations with async interface.

    Provides a way to offload CPU-intensive tasks to a thread pool
    while maintaining async/await patterns.
    """

    def __init__(self, config: Optional[ThreadPoolConfig] = None):
        """
        Initialize thread pool.

        Args:
            config: Thread pool configuration
        """
        self.config = config or ThreadPoolConfig()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._metrics = PerformanceMetrics()

    def initialize(self) -> None:
        """Initialize the thread pool."""
        if self._executor is not None:
            logger.warning("Thread pool already initialized")
            return

        self._executor = ThreadPoolExecutor(
            max_workers=self.config.max_workers,
            thread_name_prefix=self.config.thread_name_prefix,
        )

        logger.info(f"Thread pool initialized: max_workers={self.config.max_workers}")

    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the thread pool.

        Args:
            wait: Wait for pending tasks to complete
        """
        if self._executor:
            self._executor.shutdown(wait=wait)
            self._executor = None
            logger.info("Thread pool shutdown")

    async def run(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Run a CPU-bound function in the thread pool.

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            RuntimeError: If thread pool not initialized
        """
        if self._executor is None:
            raise RuntimeError("Thread pool not initialized. Call initialize() first.")

        self._metrics.thread_pool_queued += 1

        try:
            self._metrics.thread_pool_active += 1

            # Run function in thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor, lambda: func(*args, **kwargs)
            )

            return result

        finally:
            self._metrics.thread_pool_active -= 1
            self._metrics.thread_pool_queued -= 1
            self._metrics.last_updated = datetime.now(UTC)

    def get_metrics(self) -> PerformanceMetrics:
        """
        Get current thread pool metrics.

        Returns:
            Current metrics
        """
        return self._metrics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get thread pool statistics.

        Returns:
            Dictionary with pool statistics
        """
        metrics = self.get_metrics()

        stats = {
            "active_threads": metrics.thread_pool_active,
            "queued_tasks": metrics.thread_pool_queued,
            "config": {
                "max_workers": self.config.max_workers,
            },
            "last_updated": metrics.last_updated.isoformat(),
        }

        return stats


class PerformanceManager:
    """
    Central performance management for OASIS.

    Manages connection pooling, thread pools, and performance monitoring
    for optimal system throughput.
    """

    def __init__(
        self,
        connection_pool_config: Optional[ConnectionPoolConfig] = None,
        thread_pool_config: Optional[ThreadPoolConfig] = None,
    ):
        """
        Initialize performance manager.

        Args:
            connection_pool_config: Connection pool configuration
            thread_pool_config: Thread pool configuration
        """
        self.connection_pool = ConnectionPool(connection_pool_config)
        self.thread_pool = AsyncThreadPool(thread_pool_config)
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all performance components."""
        if self._initialized:
            logger.warning("Performance manager already initialized")
            return

        await self.connection_pool.initialize()
        self.thread_pool.initialize()
        self._initialized = True

        logger.info("Performance manager initialized")

    async def shutdown(self) -> None:
        """Shutdown all performance components."""
        if not self._initialized:
            return

        await self.connection_pool.close()
        self.thread_pool.shutdown(wait=True)
        self._initialized = False

        logger.info("Performance manager shutdown")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive performance statistics.

        Returns:
            Dictionary with all performance statistics
        """
        return {
            "connection_pool": self.connection_pool.get_stats(),
            "thread_pool": self.thread_pool.get_stats(),
            "initialized": self._initialized,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.shutdown()


# Global performance manager instance
_performance_manager: Optional[PerformanceManager] = None


def get_performance_manager() -> PerformanceManager:
    """
    Get the global performance manager instance.

    Returns:
        Global PerformanceManager instance
    """
    global _performance_manager
    if _performance_manager is None:
        _performance_manager = PerformanceManager()
    return _performance_manager


async def initialize_performance() -> None:
    """Initialize the global performance manager."""
    manager = get_performance_manager()
    await manager.initialize()


async def shutdown_performance() -> None:
    """Shutdown the global performance manager."""
    global _performance_manager
    if _performance_manager:
        await _performance_manager.shutdown()
        _performance_manager = None
