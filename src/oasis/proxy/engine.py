"""
OASIS Proxy Engine

Core HTTP/HTTPS proxy functionality using mitmproxy.
"""

import asyncio
import logging
from typing import Optional, Callable, Any, Dict, List
from threading import Thread
import time

from mitmproxy import options, master
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.addons import core

from ..core.exceptions import ProxyError
from ..core.models import (
    HTTPFlow,
    HTTPRequest,
    HTTPResponse,
    RequestSource,
    TrafficFilter,
    FilterSet,
)
from ..core.performance import (
    PerformanceManager,
    ConnectionPoolConfig,
    ThreadPoolConfig,
)
from .addon import OASISAddon, TrafficModifier
from .certificates import CertificateManager
from .filtering import FilterManager, FilterEngine
from ..storage.manager import StorageManager, StorageConfig


logger = logging.getLogger(__name__)


class ProxyEngine:
    """
    Core HTTP/HTTPS proxy engine using mitmproxy.

    Provides traffic interception, modification, and logging capabilities
    with configurable host/port binding and proper error handling.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        flow_callback: Optional[Callable[[HTTPFlow], None]] = None,
        max_connections: int = 1000,
        thread_pool_size: int = 10,
    ):
        """
        Initialize the proxy engine.

        Args:
            host: Host to bind the proxy to
            port: Port to bind the proxy to
            flow_callback: Optional callback for intercepted flows
            max_connections: Maximum concurrent connections
            thread_pool_size: Thread pool size for CPU-bound operations
        """
        self.host = host
        self.port = port
        self.flow_callback = flow_callback

        self._master: Optional[DumpMaster] = None
        self._addon: Optional[OASISAddon] = None
        self._thread: Optional[Thread] = None
        self._running = False
        self._start_event = asyncio.Event()
        self._stop_event = asyncio.Event()

        # Initialize certificate manager
        self.cert_manager = CertificateManager()

        # Initialize storage manager
        self.storage_manager = StorageManager()

        # Initialize performance manager
        connection_config = ConnectionPoolConfig(
            max_connections=max_connections,
            max_connections_per_host=max_connections // 3,
        )
        thread_config = ThreadPoolConfig(max_workers=thread_pool_size)
        self.performance_manager = PerformanceManager(connection_config, thread_config)

        # Ensure CA certificate exists
        self.cert_manager.ensure_ca_certificate()

    async def start_proxy(self) -> None:
        """
        Start the proxy server.

        Raises:
            ProxyError: If proxy fails to start or bind to port
        """
        if self._running:
            raise ProxyError("Proxy is already running")

        try:
            # Initialize performance manager
            await self.performance_manager.initialize()

            # Configure mitmproxy options
            opts = options.Options(
                listen_host=self.host,
                listen_port=self.port,
                http2=True,
                websocket=True,
                rawtcp=False,
                ssl_insecure=True,  # Allow insecure SSL for testing
                confdir="~/.mitmproxy",  # Configuration directory
            )

            # Create master and addon
            self._master = DumpMaster(opts)
            self._addon = OASISAddon(
                flow_callback=self.flow_callback,
                performance_manager=self.performance_manager,
            )

            # Add our custom addon
            self._master.addons.add(self._addon)

            # Start proxy in separate thread
            self._thread = Thread(target=self._run_proxy, daemon=True)
            self._thread.start()

            # Wait for proxy to start or fail
            try:
                await asyncio.wait_for(self._start_event.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                raise ProxyError("Proxy failed to start within timeout")

            # Give a small delay to catch immediate startup errors
            await asyncio.sleep(0.5)

            # Check if proxy actually started successfully
            if not self._running:
                # Check if there was a startup error
                if self._thread and not self._thread.is_alive():
                    raise ProxyError(
                        "Proxy thread failed to start (likely port binding error)"
                    )
                raise ProxyError("Proxy failed to start")

            logger.info(f"Proxy started on {self.host}:{self.port}")

        except Exception as e:
            await self._cleanup()
            if isinstance(e, ProxyError):
                raise
            raise ProxyError(f"Failed to start proxy: {str(e)}")

    async def stop_proxy(self) -> None:
        """
        Stop the proxy server.

        Raises:
            ProxyError: If proxy fails to stop cleanly
        """
        if not self._running:
            return

        try:
            logger.info("Stopping proxy...")

            # Signal shutdown
            if self._master:
                self._master.shutdown()

            # Wait for clean shutdown
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Proxy shutdown timeout, forcing stop")

            await self._cleanup()
            logger.info("Proxy stopped")

        except Exception as e:
            await self._cleanup()
            raise ProxyError(f"Failed to stop proxy cleanly: {str(e)}")

    def _run_proxy(self) -> None:
        """
        Run the proxy in a separate thread.

        This method is executed in a background thread and runs the mitmproxy event loop.
        """
        try:
            self._running = True

            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Signal that proxy has started
            loop.run_until_complete(self._signal_start())

            # Run the proxy (this is async in newer mitmproxy versions)
            try:
                loop.run_until_complete(self._master.run())
            except Exception as e:
                logger.error(f"Proxy run error: {e}")
                raise

            # Signal that proxy has stopped
            loop.run_until_complete(self._signal_stop())

        except Exception as e:
            logger.error(f"Proxy thread error: {e}")
            self._running = False
            # Try to signal start event in case we're waiting for it
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            loop.run_until_complete(self._signal_start())
        finally:
            self._running = False
            try:
                loop.close()
            except:
                pass

    async def _signal_start(self) -> None:
        """Signal that the proxy has started."""
        self._start_event.set()

    async def _signal_stop(self) -> None:
        """Signal that the proxy has stopped."""
        self._stop_event.set()

    async def _cleanup(self) -> None:
        """Clean up proxy resources."""
        self._running = False

        # Shutdown performance manager
        await self.performance_manager.shutdown()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        self._master = None
        self._addon = None
        self._thread = None
        self._start_event.clear()
        self._stop_event.clear()

    @property
    def is_running(self) -> bool:
        """Check if proxy is currently running."""
        return self._running

    @property
    def listen_address(self) -> str:
        """Get the proxy listen address."""
        return f"{self.host}:{self.port}"

    def get_stats(self) -> Dict[str, Any]:
        """
        Get proxy statistics.

        Returns:
            Dictionary containing proxy statistics
        """
        stats = {
            "running": self._running,
            "listen_address": self.listen_address,
            "https_interception_ready": self.is_https_interception_ready(),
        }

        if self._addon:
            addon_stats = self._addon.get_stats()
            stats.update(addon_stats)

        # Add certificate stats
        cert_stats = self.cert_manager.get_certificate_stats()
        stats["certificate_info"] = cert_stats

        # Add performance stats
        perf_stats = self.performance_manager.get_stats()
        stats["performance"] = perf_stats

        return stats

    def get_captured_flows(self) -> List[HTTPFlow]:
        """
        Get all captured flows.

        Returns:
            List of captured HTTP flows
        """
        if not self._addon:
            return []

        return self._addon.get_flows()

    def clear_flows(self) -> None:
        """Clear all captured flows."""
        if self._addon:
            self._addon.clear_flows()

    def get_traffic_modifier(self) -> Optional[TrafficModifier]:
        """
        Get the traffic modifier for configuring real-time modifications.

        Returns:
            TrafficModifier instance or None if proxy not running
        """
        if self._addon:
            return self._addon.get_traffic_modifier()
        return None

    def set_header_modification(self, header_name: str, header_value: str) -> bool:
        """
        Set a header to be modified in all requests.

        Args:
            header_name: Name of the header to modify
            header_value: New value for the header

        Returns:
            True if successful, False if proxy not running
        """
        modifier = self.get_traffic_modifier()
        if modifier:
            modifier.set_header_modification(header_name, header_value)
            return True
        return False

    def set_parameter_modification(self, param_name: str, param_value: str) -> bool:
        """
        Set a parameter to be modified in all requests.

        Args:
            param_name: Name of the parameter to modify
            param_value: New value for the parameter

        Returns:
            True if successful, False if proxy not running
        """
        modifier = self.get_traffic_modifier()
        if modifier:
            modifier.set_parameter_modification(param_name, param_value)
            return True
        return False

    def set_body_modification(self, url_pattern: str, new_body: bytes) -> bool:
        """
        Set body modification for requests matching URL pattern.

        Args:
            url_pattern: URL pattern to match
            new_body: New body content

        Returns:
            True if successful, False if proxy not running
        """
        modifier = self.get_traffic_modifier()
        if modifier:
            modifier.set_body_modification(url_pattern, new_body)
            return True
        return False

    def add_request_modifier(self, modifier_func: Callable[[Any], None]) -> bool:
        """
        Add a custom request modification function.

        Args:
            modifier_func: Function that modifies mitmproxy Request objects

        Returns:
            True if successful, False if proxy not running
        """
        modifier = self.get_traffic_modifier()
        if modifier:
            modifier.add_request_modifier(modifier_func)
            return True
        return False

    def add_response_modifier(self, modifier_func: Callable[[Any], None]) -> bool:
        """
        Add a custom response modification function.

        Args:
            modifier_func: Function that modifies mitmproxy Response objects

        Returns:
            True if successful, False if proxy not running
        """
        modifier = self.get_traffic_modifier()
        if modifier:
            modifier.add_response_modifier(modifier_func)
            return True
        return False

    def clear_modifications(self) -> bool:
        """
        Clear all traffic modifications.

        Returns:
            True if successful, False if proxy not running
        """
        modifier = self.get_traffic_modifier()
        if modifier:
            modifier.clear_modifications()
            return True
        return False

    def get_certificate_manager(self) -> CertificateManager:
        """
        Get the certificate manager instance.

        Returns:
            CertificateManager instance
        """
        return self.cert_manager

    def get_ca_certificate_info(self) -> Optional[Dict[str, Any]]:
        """
        Get CA certificate information.

        Returns:
            Dictionary with CA certificate info or None if not available
        """
        return self.cert_manager.get_ca_certificate_info()

    def get_certificate_installation_instructions(self) -> Dict[str, str]:
        """
        Get platform-specific instructions for installing the CA certificate.

        Returns:
            Dictionary with installation instructions for different platforms
        """
        return self.cert_manager.get_installation_instructions()

    def is_https_interception_ready(self) -> bool:
        """
        Check if HTTPS interception is ready (CA certificate exists).

        Returns:
            True if ready for HTTPS interception, False otherwise
        """
        return self.cert_manager.get_ca_certificate_info() is not None

    def generate_domain_certificate(self, domain: str) -> bool:
        """
        Pre-generate a certificate for a specific domain.

        Args:
            domain: Domain name

        Returns:
            True if successful, False otherwise
        """
        try:
            result = self.cert_manager.generate_domain_certificate(domain)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to generate certificate for {domain}: {e}")
            return False

    def get_filter_manager(self) -> Optional[FilterManager]:
        """
        Get the filter manager for configuring traffic filtering.

        Returns:
            FilterManager instance or None if proxy not running
        """
        if self._addon:
            return self._addon.get_filter_manager()
        return None

    def add_traffic_filter(self, traffic_filter: TrafficFilter) -> bool:
        """
        Add a traffic filter to the active filter set.

        Args:
            traffic_filter: TrafficFilter to add

        Returns:
            True if successful, False if proxy not running
        """
        filter_manager = self.get_filter_manager()
        if filter_manager:
            filter_engine = filter_manager.get_active_filter_engine()
            if filter_engine:
                filter_engine.add_filter(traffic_filter)
                return True
        return False

    def remove_traffic_filter(self, filter_id: str) -> bool:
        """
        Remove a traffic filter from the active filter set.

        Args:
            filter_id: ID of the filter to remove

        Returns:
            True if successful, False if filter not found or proxy not running
        """
        filter_manager = self.get_filter_manager()
        if filter_manager:
            filter_engine = filter_manager.get_active_filter_engine()
            if filter_engine:
                return filter_engine.remove_filter(filter_id)
        return False

    def set_active_filter_set(self, filter_set_id: str) -> bool:
        """
        Set the active filter set.

        Args:
            filter_set_id: ID of the filter set to activate

        Returns:
            True if successful, False if filter set not found or proxy not running
        """
        filter_manager = self.get_filter_manager()
        if filter_manager:
            return filter_manager.set_active_filter_set(filter_set_id)
        return False

    def create_filter_set(
        self, name: str, description: str = ""
    ) -> Optional[FilterSet]:
        """
        Create a new filter set.

        Args:
            name: Name of the filter set
            description: Description of the filter set

        Returns:
            Created FilterSet or None if proxy not running
        """
        filter_manager = self.get_filter_manager()
        if filter_manager:
            return filter_manager.create_filter_set(name, description)
        return None

    def get_filter_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get traffic filtering statistics.

        Returns:
            Dictionary with filter statistics or None if proxy not running
        """
        filter_manager = self.get_filter_manager()
        if filter_manager:
            filter_engine = filter_manager.get_active_filter_engine()
            if filter_engine:
                return filter_engine.get_filter_stats()
        return None

    def get_storage_manager(self) -> StorageManager:
        """
        Get the storage manager instance.

        Returns:
            StorageManager instance
        """
        return self.storage_manager

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics and usage information.

        Returns:
            Dictionary with storage statistics
        """
        return self.storage_manager.get_storage_stats()

    def force_storage_cleanup(self) -> Dict[str, Any]:
        """
        Force immediate storage cleanup.

        Returns:
            Dictionary with cleanup results
        """
        return self.storage_manager.force_cleanup()

    def update_storage_config(self, config: StorageConfig) -> None:
        """
        Update storage management configuration.

        Args:
            config: New storage configuration
        """
        self.storage_manager.update_config(config)
