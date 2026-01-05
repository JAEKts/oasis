"""
Property-based tests for OASIS memory-bounded processing.

Feature: oasis-pentest-suite, Property 7: Memory-Bounded Processing
Validates: Requirements 2.5, 11.3
"""

import pytest
import asyncio
import tempfile
import os
from hypothesis import given, strategies as st, settings, HealthCheck
from datetime import datetime, UTC

from src.oasis.core.memory import (
    StreamingBuffer,
    StreamProcessor,
    MemoryMonitor,
    MemoryConfig,
)


# Property 7: Memory-Bounded Processing
# For any large data processing operation, memory usage should remain within
# configured bounds through streaming and pagination


@given(
    data_size=st.integers(min_value=1024, max_value=50 * 1024 * 1024),  # 1KB to 50MB
    threshold=st.integers(min_value=1024 * 1024, max_value=20 * 1024 * 1024),  # 1MB to 20MB
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_streaming_buffer_respects_memory_threshold(data_size: int, threshold: int):
    """
    Property 7: Memory-Bounded Processing (Streaming Buffer)
    
    For any data size and threshold, the streaming buffer should automatically
    spill to disk when data exceeds the threshold, preventing memory exhaustion.
    
    Validates: Requirements 2.5, 11.3
    """
    # Create test data
    test_data = b'x' * data_size
    
    # Create streaming buffer with threshold
    with StreamingBuffer(threshold=threshold) as buffer:
        # Write data in chunks
        chunk_size = 64 * 1024  # 64KB chunks
        offset = 0
        
        while offset < data_size:
            chunk = test_data[offset:offset + chunk_size]
            buffer.write(chunk)
            offset += len(chunk)
        
        # Property assertions:
        # 1. Buffer size should match data size
        assert buffer.size == data_size
        
        # 2. If data exceeds threshold, buffer should be spilled to disk
        if data_size > threshold:
            assert buffer.is_spilled, (
                f"Buffer should be spilled for {data_size} bytes "
                f"with threshold {threshold}"
            )
        else:
            # Small data should stay in memory
            assert not buffer.is_spilled, (
                f"Buffer should not be spilled for {data_size} bytes "
                f"with threshold {threshold}"
            )
        
        # 3. Data should be retrievable regardless of spilling
        buffer.seek(0)
        retrieved_data = buffer.read()
        assert retrieved_data == test_data, "Retrieved data should match original"
        
        # 4. Seeking should work correctly
        buffer.seek(0)
        assert buffer.read(100) == test_data[:100]


@pytest.mark.asyncio
@given(
    data_size=st.integers(min_value=1024, max_value=10 * 1024 * 1024),  # 1KB to 10MB
    chunk_size=st.integers(min_value=1024, max_value=1024 * 1024),  # 1KB to 1MB
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_stream_processor_handles_large_data_in_chunks(
    data_size: int, chunk_size: int
):
    """
    Property 7: Memory-Bounded Processing (Stream Processor)
    
    For any data size, the stream processor should process data in chunks
    without loading the entire dataset into memory at once.
    
    Validates: Requirements 2.3, 2.5, 11.3
    """
    # Create test data
    test_data = b'A' * data_size
    
    # Create stream processor
    processor = StreamProcessor(chunk_size=chunk_size)
    
    # Track chunks processed
    chunks_processed = 0
    total_bytes_processed = 0
    max_chunk_size_seen = 0
    
    # Stream and process data
    async for chunk in processor.stream_bytes(test_data):
        chunks_processed += 1
        chunk_len = len(chunk)
        total_bytes_processed += chunk_len
        max_chunk_size_seen = max(max_chunk_size_seen, chunk_len)
    
    # Property assertions:
    # 1. All data should be processed
    assert total_bytes_processed == data_size
    
    # 2. No single chunk should exceed the configured chunk size
    assert max_chunk_size_seen <= chunk_size, (
        f"Chunk size {max_chunk_size_seen} exceeds limit {chunk_size}"
    )
    
    # 3. Number of chunks should be reasonable
    expected_chunks = (data_size + chunk_size - 1) // chunk_size
    assert chunks_processed == expected_chunks, (
        f"Expected {expected_chunks} chunks, got {chunks_processed}"
    )
    
    # 4. For data larger than chunk size, multiple chunks should be created
    if data_size > chunk_size:
        assert chunks_processed > 1, "Large data should be split into multiple chunks"


@pytest.mark.asyncio
@given(
    num_operations=st.integers(min_value=5, max_value=50),
)
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_memory_monitor_tracks_usage_accurately(num_operations: int):
    """
    Property 7: Memory-Bounded Processing (Memory Monitor)
    
    For any number of operations, the memory monitor should accurately
    track memory usage and provide current metrics.
    
    Validates: Requirements 2.5, 11.3
    """
    # Create memory monitor
    config = MemoryConfig(
        max_memory_percent=80.0,
        enable_auto_gc=False,  # Disable auto GC for predictable testing
    )
    monitor = MemoryMonitor(config)
    
    # Get initial metrics
    initial_metrics = monitor.get_metrics()
    
    # Property assertions on initial state:
    # 1. Memory metrics should be valid
    assert initial_metrics.total_memory_mb > 0
    assert initial_metrics.used_memory_mb >= 0
    assert initial_metrics.available_memory_mb >= 0
    assert 0 <= initial_metrics.memory_percent <= 100
    
    # 2. Used + Available should approximately equal Total
    # (allowing for some variance due to system accounting)
    total_accounted = initial_metrics.used_memory_mb + initial_metrics.available_memory_mb
    assert abs(total_accounted - initial_metrics.total_memory_mb) < initial_metrics.total_memory_mb * 0.1
    
    # Perform operations and track metrics
    for i in range(num_operations):
        # Allocate some memory
        data = bytearray(1024 * 1024)  # 1MB
        
        # Update metrics
        monitor.update_metrics()
        metrics = monitor.get_metrics()
        
        # Property assertions during operations:
        # 3. Metrics should always be valid
        assert metrics.total_memory_mb > 0
        assert metrics.used_memory_mb >= 0
        assert metrics.available_memory_mb >= 0
        assert 0 <= metrics.memory_percent <= 100
        
        # 4. Timestamp should be recent
        time_diff = (datetime.now(UTC) - metrics.last_updated).total_seconds()
        assert time_diff < 5.0
        
        # Clean up
        del data
    
    # Get final metrics
    final_metrics = monitor.get_metrics()
    
    # Property assertions on final state:
    # 5. Final metrics should still be valid
    assert final_metrics.total_memory_mb > 0
    assert 0 <= final_metrics.memory_percent <= 100


@pytest.mark.asyncio
async def test_memory_monitor_triggers_gc_when_needed():
    """
    Test that memory monitor triggers garbage collection when thresholds are exceeded.
    
    Validates: Requirements 2.5, 11.3
    """
    # Create memory monitor with low threshold for testing
    config = MemoryConfig(
        max_memory_percent=1.0,  # Very low threshold to trigger GC
        enable_auto_gc=True,
        gc_threshold_mb=1,  # Trigger after 1MB
    )
    monitor = MemoryMonitor(config)
    
    # Get initial GC count
    initial_gc_count = monitor.get_metrics().gc_collections
    
    # Force GC trigger check
    if monitor.should_trigger_gc():
        result = monitor.trigger_gc()
        
        # Property assertions:
        # 1. GC should have been performed
        assert result["objects_collected"] >= 0
        
        # 2. GC count should increase
        final_gc_count = monitor.get_metrics().gc_collections
        assert final_gc_count > initial_gc_count


@pytest.mark.asyncio
@given(
    file_size=st.integers(min_value=1024, max_value=5 * 1024 * 1024),  # 1KB to 5MB
    chunk_size=st.integers(min_value=1024, max_value=512 * 1024),  # 1KB to 512KB
)
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_stream_processor_handles_file_streaming(file_size: int, chunk_size: int):
    """
    Property 7: Memory-Bounded Processing (File Streaming)
    
    For any file size, the stream processor should stream file contents
    in memory-bounded chunks without loading the entire file.
    
    Validates: Requirements 2.3, 2.5, 11.3
    """
    # Create temporary file with test data
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        temp_path = f.name
        test_data = b'B' * file_size
        f.write(test_data)
    
    try:
        # Create stream processor
        processor = StreamProcessor(chunk_size=chunk_size)
        
        # Stream file contents
        chunks_processed = 0
        total_bytes_read = 0
        max_chunk_size_seen = 0
        
        async for chunk in processor.stream_file(temp_path):
            chunks_processed += 1
            chunk_len = len(chunk)
            total_bytes_read += chunk_len
            max_chunk_size_seen = max(max_chunk_size_seen, chunk_len)
        
        # Property assertions:
        # 1. All file data should be read
        assert total_bytes_read == file_size
        
        # 2. No chunk should exceed configured size
        assert max_chunk_size_seen <= chunk_size
        
        # 3. Multiple chunks for large files
        if file_size > chunk_size:
            assert chunks_processed > 1
        
    finally:
        # Cleanup temp file
        os.unlink(temp_path)


@pytest.mark.asyncio
async def test_memory_monitor_monitoring_lifecycle():
    """
    Test that memory monitor can start and stop monitoring correctly.
    
    Validates: Requirements 11.3
    """
    config = MemoryConfig(enable_auto_gc=False)
    monitor = MemoryMonitor(config)
    
    # Initially not monitoring
    assert not monitor._monitoring
    
    # Start monitoring
    await monitor.start_monitoring(interval=0.1)
    assert monitor._monitoring
    
    # Let it run briefly
    await asyncio.sleep(0.3)
    
    # Stop monitoring
    await monitor.stop_monitoring()
    assert not monitor._monitoring
    
    # Metrics should still be accessible
    metrics = monitor.get_metrics()
    assert metrics.total_memory_mb > 0


@given(
    data_size=st.integers(min_value=100, max_value=1024 * 1024),  # 100B to 1MB
    threshold=st.integers(min_value=1024, max_value=512 * 1024),  # 1KB to 512KB
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_streaming_buffer_getvalue_works_regardless_of_spilling(
    data_size: int, threshold: int
):
    """
    Property: StreamingBuffer.getvalue() should return complete data
    regardless of whether buffer was spilled to disk.
    
    Validates: Requirements 2.5, 11.3
    """
    test_data = b'Z' * data_size
    
    with StreamingBuffer(threshold=threshold) as buffer:
        buffer.write(test_data)
        
        # Get value should work regardless of spilling
        retrieved = buffer.getvalue()
        
        # Property assertions:
        # 1. Retrieved data should match original
        assert retrieved == test_data
        
        # 2. Length should match
        assert len(retrieved) == data_size
        
        # 3. Buffer size should be correct
        assert buffer.size == data_size


@pytest.mark.asyncio
@given(
    num_chunks=st.integers(min_value=2, max_value=20),
)
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
async def test_stream_processor_with_custom_processor(num_chunks: int):
    """
    Property: Stream processor should correctly apply custom processing
    functions to each chunk.
    
    Validates: Requirements 2.5, 11.3
    """
    # Create test data
    chunk_size = 1024
    test_data = b'C' * (chunk_size * num_chunks)
    
    processor = StreamProcessor(chunk_size=chunk_size)
    
    # Custom processor that counts bytes
    def count_bytes(chunk: bytes) -> int:
        return len(chunk)
    
    # Process stream
    chunk_counts = []
    async for count in processor.process_stream(
        processor.stream_bytes(test_data),
        count_bytes
    ):
        chunk_counts.append(count)
    
    # Property assertions:
    # 1. Should have processed expected number of chunks
    assert len(chunk_counts) == num_chunks
    
    # 2. Total bytes should match original data size
    assert sum(chunk_counts) == len(test_data)
    
    # 3. Each chunk should be the expected size
    for count in chunk_counts:
        assert count == chunk_size
