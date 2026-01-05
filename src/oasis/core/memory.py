"""
OASIS Memory Management Module

Provides memory-bounded processing for large payloads, streaming operations,
and automatic memory monitoring with garbage collection.
"""

import asyncio
import gc
import logging
import psutil
from typing import AsyncIterator, Optional, Dict, Any, BinaryIO
from dataclasses import dataclass, field
from datetime import datetime, UTC
from io import BytesIO
import os
import tempfile


logger = logging.getLogger(__name__)


@dataclass
class MemoryConfig:
    """Configuration for memory management."""

    max_memory_percent: float = 80.0  # Trigger cleanup at 80% memory usage
    large_payload_threshold: int = 10 * 1024 * 1024  # 10MB
    stream_chunk_size: int = 64 * 1024  # 64KB chunks
    enable_auto_gc: bool = True
    gc_threshold_mb: int = 100  # Trigger GC after 100MB allocated
    temp_file_dir: Optional[str] = None


@dataclass
class MemoryMetrics:
    """Memory usage metrics."""

    total_memory_mb: float = 0.0
    used_memory_mb: float = 0.0
    available_memory_mb: float = 0.0
    memory_percent: float = 0.0
    gc_collections: int = 0
    large_payloads_streamed: int = 0
    temp_files_created: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))


class StreamingBuffer:
    """
    Memory-bounded buffer that automatically spills to disk for large data.

    Keeps small data in memory, but writes large data to temporary files
    to prevent memory exhaustion.
    """

    def __init__(
        self, threshold: int = 10 * 1024 * 1024, temp_dir: Optional[str] = None
    ):
        """
        Initialize streaming buffer.

        Args:
            threshold: Size threshold for spilling to disk (bytes)
            temp_dir: Directory for temporary files
        """
        self.threshold = threshold
        self.temp_dir = temp_dir
        self._buffer: Optional[BytesIO] = BytesIO()
        self._temp_file: Optional[BinaryIO] = None
        self._size = 0
        self._spilled = False

    def write(self, data: bytes) -> int:
        """
        Write data to buffer.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        data_len = len(data)

        # Check if we need to spill to disk
        if not self._spilled and (self._size + data_len) > self.threshold:
            self._spill_to_disk()

        # Write to appropriate storage
        if self._spilled:
            written = self._temp_file.write(data)
        else:
            written = self._buffer.write(data)

        self._size += written
        return written

    def _spill_to_disk(self) -> None:
        """Spill buffer contents to temporary file."""
        if self._spilled:
            return

        # Create temporary file
        self._temp_file = tempfile.NamedTemporaryFile(
            mode="w+b", delete=False, dir=self.temp_dir
        )

        # Write existing buffer contents to file
        if self._buffer:
            self._buffer.seek(0)
            self._temp_file.write(self._buffer.read())
            self._buffer.close()
            self._buffer = None

        self._spilled = True
        logger.debug(f"Spilled buffer to disk: {self._temp_file.name}")

    def read(self, size: int = -1) -> bytes:
        """
        Read data from buffer.

        Args:
            size: Number of bytes to read (-1 for all)

        Returns:
            Data read
        """
        if self._spilled:
            return self._temp_file.read(size)
        else:
            return self._buffer.read(size)

    def seek(self, position: int, whence: int = 0) -> int:
        """
        Seek to position in buffer.

        Args:
            position: Position to seek to
            whence: Reference point (0=start, 1=current, 2=end)

        Returns:
            New position
        """
        if self._spilled:
            return self._temp_file.seek(position, whence)
        else:
            return self._buffer.seek(position, whence)

    def getvalue(self) -> bytes:
        """
        Get entire buffer contents.

        Returns:
            Buffer contents as bytes
        """
        if self._spilled:
            current_pos = self._temp_file.tell()
            self._temp_file.seek(0)
            data = self._temp_file.read()
            self._temp_file.seek(current_pos)
            return data
        else:
            return self._buffer.getvalue()

    def close(self) -> None:
        """Close and cleanup buffer resources."""
        if self._buffer:
            self._buffer.close()
            self._buffer = None

        if self._temp_file:
            temp_name = self._temp_file.name
            self._temp_file.close()
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            self._temp_file = None

    @property
    def size(self) -> int:
        """Get current buffer size."""
        return self._size

    @property
    def is_spilled(self) -> bool:
        """Check if buffer has been spilled to disk."""
        return self._spilled

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class StreamProcessor:
    """
    Process large data streams in memory-bounded chunks.

    Provides async iteration over large data with configurable chunk sizes
    to prevent loading entire payloads into memory.
    """

    def __init__(self, chunk_size: int = 64 * 1024):
        """
        Initialize stream processor.

        Args:
            chunk_size: Size of chunks to process (bytes)
        """
        self.chunk_size = chunk_size

    async def stream_bytes(self, data: bytes) -> AsyncIterator[bytes]:
        """
        Stream bytes in chunks.

        Args:
            data: Data to stream

        Yields:
            Chunks of data
        """
        offset = 0
        data_len = len(data)

        while offset < data_len:
            chunk = data[offset : offset + self.chunk_size]
            yield chunk
            offset += len(chunk)

            # Yield control to event loop
            await asyncio.sleep(0)

    async def stream_file(self, file_path: str) -> AsyncIterator[bytes]:
        """
        Stream file contents in chunks.

        Args:
            file_path: Path to file

        Yields:
            Chunks of file data
        """
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk

                # Yield control to event loop
                await asyncio.sleep(0)

    async def process_stream(
        self, stream: AsyncIterator[bytes], processor: callable
    ) -> AsyncIterator[Any]:
        """
        Process stream with a processor function.

        Args:
            stream: Input stream
            processor: Function to process each chunk

        Yields:
            Processed results
        """
        async for chunk in stream:
            result = processor(chunk)
            yield result

            # Yield control to event loop
            await asyncio.sleep(0)


class MemoryMonitor:
    """
    Monitor system memory usage and trigger cleanup when needed.

    Provides automatic garbage collection and memory usage tracking
    to prevent memory exhaustion.
    """

    def __init__(self, config: Optional[MemoryConfig] = None):
        """
        Initialize memory monitor.

        Args:
            config: Memory management configuration
        """
        self.config = config or MemoryConfig()
        self._metrics = MemoryMetrics()
        self._last_gc_size = 0
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None

    def get_memory_usage(self) -> Dict[str, float]:
        """
        Get current memory usage.

        Returns:
            Dictionary with memory usage information
        """
        memory = psutil.virtual_memory()

        return {
            "total_mb": memory.total / (1024 * 1024),
            "used_mb": memory.used / (1024 * 1024),
            "available_mb": memory.available / (1024 * 1024),
            "percent": memory.percent,
        }

    def update_metrics(self) -> None:
        """Update memory metrics."""
        usage = self.get_memory_usage()

        self._metrics.total_memory_mb = usage["total_mb"]
        self._metrics.used_memory_mb = usage["used_mb"]
        self._metrics.available_memory_mb = usage["available_mb"]
        self._metrics.memory_percent = usage["percent"]
        self._metrics.last_updated = datetime.now(UTC)

    def should_trigger_gc(self) -> bool:
        """
        Check if garbage collection should be triggered.

        Returns:
            True if GC should be triggered
        """
        if not self.config.enable_auto_gc:
            return False

        # Check memory usage
        usage = self.get_memory_usage()
        if usage["percent"] >= self.config.max_memory_percent:
            return True

        # Check allocated memory since last GC
        current_size = usage["used_mb"]
        if current_size - self._last_gc_size >= self.config.gc_threshold_mb:
            return True

        return False

    def trigger_gc(self) -> Dict[str, Any]:
        """
        Trigger garbage collection.

        Returns:
            Dictionary with GC results
        """
        before_usage = self.get_memory_usage()

        # Run garbage collection
        collected = gc.collect()

        after_usage = self.get_memory_usage()

        # Update metrics
        self._metrics.gc_collections += 1
        self._last_gc_size = after_usage["used_mb"]

        freed_mb = before_usage["used_mb"] - after_usage["used_mb"]

        logger.info(
            f"Garbage collection: collected {collected} objects, "
            f"freed {freed_mb:.2f}MB"
        )

        return {
            "objects_collected": collected,
            "memory_freed_mb": freed_mb,
            "before_percent": before_usage["percent"],
            "after_percent": after_usage["percent"],
        }

    async def start_monitoring(self, interval: float = 5.0) -> None:
        """
        Start automatic memory monitoring.

        Args:
            interval: Monitoring interval in seconds
        """
        if self._monitoring:
            logger.warning("Memory monitoring already started")
            return

        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop(interval))
        logger.info(f"Memory monitoring started (interval: {interval}s)")

    async def stop_monitoring(self) -> None:
        """Stop automatic memory monitoring."""
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

        logger.info("Memory monitoring stopped")

    async def _monitor_loop(self, interval: float) -> None:
        """Memory monitoring loop."""
        while self._monitoring:
            try:
                # Update metrics
                self.update_metrics()

                # Check if GC needed
                if self.should_trigger_gc():
                    self.trigger_gc()

                # Wait for next interval
                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in memory monitoring: {e}")
                await asyncio.sleep(interval)

    def get_metrics(self) -> MemoryMetrics:
        """
        Get current memory metrics.

        Returns:
            Current memory metrics
        """
        self.update_metrics()
        return self._metrics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get memory statistics.

        Returns:
            Dictionary with memory statistics
        """
        metrics = self.get_metrics()

        return {
            "total_memory_mb": round(metrics.total_memory_mb, 2),
            "used_memory_mb": round(metrics.used_memory_mb, 2),
            "available_memory_mb": round(metrics.available_memory_mb, 2),
            "memory_percent": round(metrics.memory_percent, 2),
            "gc_collections": metrics.gc_collections,
            "large_payloads_streamed": metrics.large_payloads_streamed,
            "temp_files_created": metrics.temp_files_created,
            "monitoring": self._monitoring,
            "config": {
                "max_memory_percent": self.config.max_memory_percent,
                "large_payload_threshold_mb": self.config.large_payload_threshold
                / (1024 * 1024),
                "auto_gc_enabled": self.config.enable_auto_gc,
            },
            "last_updated": metrics.last_updated.isoformat(),
        }


# Global memory monitor instance
_memory_monitor: Optional[MemoryMonitor] = None


def get_memory_monitor() -> MemoryMonitor:
    """
    Get the global memory monitor instance.

    Returns:
        Global MemoryMonitor instance
    """
    global _memory_monitor
    if _memory_monitor is None:
        _memory_monitor = MemoryMonitor()
    return _memory_monitor


async def start_memory_monitoring(interval: float = 5.0) -> None:
    """
    Start global memory monitoring.

    Args:
        interval: Monitoring interval in seconds
    """
    monitor = get_memory_monitor()
    await monitor.start_monitoring(interval)


async def stop_memory_monitoring() -> None:
    """Stop global memory monitoring."""
    if _memory_monitor:
        await _memory_monitor.stop_monitoring()
