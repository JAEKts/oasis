"""
Real-time Interaction Notification System

Provides callbacks and event notifications for out-of-band interactions.
"""

import asyncio
from typing import Callable, List, Optional
from datetime import datetime, UTC
import uuid

from .models import Interaction, Protocol


class InteractionNotifier:
    """
    Manages real-time notifications for collaborator interactions.
    """

    def __init__(self):
        """Initialize the notifier."""
        self._callbacks: List[Callable[[Interaction], None]] = []
        self._async_callbacks: List[Callable[[Interaction], asyncio.Future]] = []
        self._notification_queue: asyncio.Queue = asyncio.Queue()
        self._notification_task: Optional[asyncio.Task] = None

    def register_callback(self, callback: Callable[[Interaction], None]) -> None:
        """
        Register a synchronous callback for interaction notifications.

        Args:
            callback: Function to call when an interaction is captured
        """
        self._callbacks.append(callback)

    def register_async_callback(
        self, callback: Callable[[Interaction], asyncio.Future]
    ) -> None:
        """
        Register an asynchronous callback for interaction notifications.

        Args:
            callback: Async function to call when an interaction is captured
        """
        self._async_callbacks.append(callback)

    def unregister_callback(self, callback: Callable) -> None:
        """
        Unregister a callback.

        Args:
            callback: Callback to remove
        """
        if callback in self._callbacks:
            self._callbacks.remove(callback)
        if callback in self._async_callbacks:
            self._async_callbacks.remove(callback)

    async def notify(self, interaction: Interaction) -> None:
        """
        Notify all registered callbacks about an interaction.

        Args:
            interaction: Interaction to notify about
        """
        # Call synchronous callbacks
        for callback in self._callbacks:
            try:
                callback(interaction)
            except Exception as e:
                # Log error but don't stop other notifications
                print(f"Error in notification callback: {e}")

        # Call asynchronous callbacks
        for callback in self._async_callbacks:
            try:
                await callback(interaction)
            except Exception as e:
                print(f"Error in async notification callback: {e}")

    async def start_notification_processor(self) -> None:
        """Start the background notification processor."""
        if self._notification_task is not None:
            return

        self._notification_task = asyncio.create_task(self._process_notifications())

    async def stop_notification_processor(self) -> None:
        """Stop the background notification processor."""
        if self._notification_task is not None:
            self._notification_task.cancel()
            try:
                await self._notification_task
            except asyncio.CancelledError:
                pass
            self._notification_task = None

    async def _process_notifications(self) -> None:
        """Background task to process notification queue."""
        while True:
            try:
                interaction = await self._notification_queue.get()
                await self.notify(interaction)
                self._notification_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error processing notification: {e}")

    async def queue_notification(self, interaction: Interaction) -> None:
        """
        Queue an interaction for notification.

        Args:
            interaction: Interaction to queue
        """
        await self._notification_queue.put(interaction)


class InteractionLogger:
    """
    Logs interactions with detailed forensic information.
    """

    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize the logger.

        Args:
            log_file: Optional file path for logging interactions
        """
        self.log_file = log_file
        self._log_entries: List[dict] = []

    def log_interaction(self, interaction: Interaction) -> None:
        """
        Log an interaction with forensic details.

        Args:
            interaction: Interaction to log
        """
        log_entry = {
            "timestamp": interaction.timestamp.isoformat(),
            "interaction_id": str(interaction.id),
            "payload_id": str(interaction.payload_id),
            "protocol": interaction.protocol.value,
            "source_ip": interaction.source_ip,
        }

        # Add protocol-specific details
        if interaction.dns_query:
            log_entry["dns"] = {
                "query_name": interaction.dns_query.query_name,
                "query_type": interaction.dns_query.query_type,
            }

        if interaction.http_request:
            log_entry["http"] = interaction.http_request
            log_entry["user_agent"] = interaction.user_agent

        if interaction.smtp_message:
            log_entry["smtp"] = {
                "from": interaction.smtp_message.from_address,
                "to": interaction.smtp_message.to_address,
                "subject": interaction.smtp_message.subject,
            }

        self._log_entries.append(log_entry)

        # Write to file if configured
        if self.log_file:
            self._write_to_file(log_entry)

    def _write_to_file(self, log_entry: dict) -> None:
        """Write log entry to file."""
        import json

        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")

    def get_logs(self) -> List[dict]:
        """Get all logged interactions."""
        return self._log_entries.copy()

    def clear_logs(self) -> None:
        """Clear all logged interactions."""
        self._log_entries.clear()
