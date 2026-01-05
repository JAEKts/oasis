"""
Collaborator Service Implementation

Provides out-of-band interaction detection for blind vulnerability testing.
"""

import asyncio
import hashlib
import secrets
import uuid
from datetime import datetime, UTC
from typing import Dict, List, Optional, Set, Callable
from collections import defaultdict

from .models import (
    CollaboratorPayload,
    Interaction,
    PayloadType,
    Protocol,
    DNSQuery,
    SMTPMessage,
)
from .notifications import InteractionNotifier, InteractionLogger
from .forensics import ForensicAnalyzer


class CollaboratorService:
    """
    Out-of-band application security testing service.

    Generates unique payloads and captures interactions for blind vulnerability detection.
    """

    def __init__(
        self,
        base_domain: str = "oasis-collab.local",
        self_hosted: bool = True,
        enable_notifications: bool = True,
        log_file: Optional[str] = None,
    ):
        """
        Initialize the collaborator service.

        Args:
            base_domain: Base domain for generating subdomains
            self_hosted: Whether this is a self-hosted deployment
            enable_notifications: Whether to enable real-time notifications
            log_file: Optional file path for logging interactions
        """
        self.base_domain = base_domain
        self.self_hosted = self_hosted

        # Payload tracking
        self._payloads: Dict[uuid.UUID, CollaboratorPayload] = {}
        self._subdomain_to_payload: Dict[str, uuid.UUID] = {}

        # Interaction storage
        self._interactions: Dict[uuid.UUID, List[Interaction]] = defaultdict(list)

        # Listener state
        self._listeners: Dict[Protocol, bool] = {}
        self._listener_tasks: Dict[Protocol, asyncio.Task] = {}

        # Notification and forensics
        self._notifier = InteractionNotifier() if enable_notifications else None
        self._logger = InteractionLogger(log_file=log_file)
        self._forensic_analyzer = ForensicAnalyzer()

    def _generate_unique_subdomain(self) -> str:
        """
        Generate a unique subdomain for payload identification.

        Returns:
            Unique subdomain string
        """
        # Generate a random token
        random_bytes = secrets.token_bytes(16)

        # Create a hash for the subdomain
        subdomain_hash = hashlib.sha256(random_bytes).hexdigest()[:16]

        # Ensure uniqueness
        while subdomain_hash in self._subdomain_to_payload:
            random_bytes = secrets.token_bytes(16)
            subdomain_hash = hashlib.sha256(random_bytes).hexdigest()[:16]

        return subdomain_hash

    async def generate_payload(
        self, payload_type: PayloadType, metadata: Optional[Dict] = None
    ) -> CollaboratorPayload:
        """
        Generate a unique collaborator payload.

        Args:
            payload_type: Type of payload to generate
            metadata: Optional metadata to associate with the payload

        Returns:
            CollaboratorPayload with unique subdomain
        """
        subdomain = self._generate_unique_subdomain()
        full_domain = f"{subdomain}.{self.base_domain}"

        payload = CollaboratorPayload(
            payload_type=payload_type,
            subdomain=subdomain,
            full_domain=full_domain,
            metadata=metadata or {},
        )

        # Store payload for correlation
        self._payloads[payload.id] = payload
        self._subdomain_to_payload[subdomain] = payload.id

        return payload

    def _correlate_subdomain(self, subdomain: str) -> Optional[uuid.UUID]:
        """
        Correlate a subdomain with its payload ID.

        Args:
            subdomain: Subdomain to correlate

        Returns:
            Payload ID if found, None otherwise
        """
        # Extract subdomain from full domain if needed
        if "." in subdomain:
            parts = subdomain.split(".")
            # Try to find the payload subdomain
            for i in range(len(parts)):
                potential_subdomain = parts[i]
                if potential_subdomain in self._subdomain_to_payload:
                    return self._subdomain_to_payload[potential_subdomain]

        # Direct lookup
        return self._subdomain_to_payload.get(subdomain)

    async def capture_dns_interaction(
        self,
        query_name: str,
        query_type: str,
        source_ip: str,
        raw_data: Optional[str] = None,
    ) -> Optional[Interaction]:
        """
        Capture a DNS interaction.

        Args:
            query_name: DNS query name
            query_type: DNS query type (A, AAAA, MX, TXT, etc.)
            source_ip: Source IP address
            raw_data: Raw DNS query data

        Returns:
            Interaction object if payload correlation succeeds, None otherwise
        """
        # Correlate with payload
        payload_id = self._correlate_subdomain(query_name)
        if not payload_id:
            return None

        dns_query = DNSQuery(
            query_name=query_name,
            query_type=query_type,
            source_ip=source_ip,
            raw_data=raw_data,
        )

        interaction = Interaction(
            payload_id=payload_id,
            protocol=Protocol.DNS,
            source_ip=source_ip,
            dns_query=dns_query,
        )

        # Store interaction
        self._interactions[payload_id].append(interaction)

        # Log interaction
        self._logger.log_interaction(interaction)

        # Notify listeners
        if self._notifier:
            await self._notifier.notify(interaction)

        return interaction

    async def capture_http_interaction(
        self,
        host: str,
        method: str,
        path: str,
        headers: Dict[str, str],
        source_ip: str,
        body: Optional[str] = None,
    ) -> Optional[Interaction]:
        """
        Capture an HTTP interaction.

        Args:
            host: HTTP host header
            method: HTTP method
            path: Request path
            headers: Request headers
            source_ip: Source IP address
            body: Request body

        Returns:
            Interaction object if payload correlation succeeds, None otherwise
        """
        # Correlate with payload using host header
        payload_id = self._correlate_subdomain(host)
        if not payload_id:
            return None

        http_request = {"method": method, "path": path, "host": host, "body": body}

        interaction = Interaction(
            payload_id=payload_id,
            protocol=(
                Protocol.HTTP
                if not headers.get("X-Forwarded-Proto") == "https"
                else Protocol.HTTPS
            ),
            source_ip=source_ip,
            http_request=http_request,
            user_agent=headers.get("User-Agent"),
            headers=headers,
        )

        # Store interaction
        self._interactions[payload_id].append(interaction)

        # Log interaction
        self._logger.log_interaction(interaction)

        # Notify listeners
        if self._notifier:
            await self._notifier.notify(interaction)

        return interaction

    async def capture_smtp_interaction(
        self,
        from_address: str,
        to_address: str,
        source_ip: str,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        raw_data: Optional[str] = None,
    ) -> Optional[Interaction]:
        """
        Capture an SMTP interaction.

        Args:
            from_address: Sender email address
            to_address: Recipient email address
            source_ip: Source IP address
            subject: Email subject
            body: Email body
            raw_data: Raw SMTP data

        Returns:
            Interaction object if payload correlation succeeds, None otherwise
        """
        # Correlate with payload using to_address domain
        if "@" in to_address:
            domain = to_address.split("@")[1]
            payload_id = self._correlate_subdomain(domain)
        else:
            payload_id = self._correlate_subdomain(to_address)

        if not payload_id:
            return None

        smtp_message = SMTPMessage(
            from_address=from_address,
            to_address=to_address,
            subject=subject,
            body=body,
            source_ip=source_ip,
            raw_data=raw_data,
        )

        interaction = Interaction(
            payload_id=payload_id,
            protocol=Protocol.SMTP,
            source_ip=source_ip,
            smtp_message=smtp_message,
        )

        # Store interaction
        self._interactions[payload_id].append(interaction)

        # Log interaction
        self._logger.log_interaction(interaction)

        # Notify listeners
        if self._notifier:
            await self._notifier.notify(interaction)

        return interaction

    async def poll_interactions(self, payload_id: uuid.UUID) -> List[Interaction]:
        """
        Poll for interactions associated with a payload.

        Args:
            payload_id: Payload ID to poll interactions for

        Returns:
            List of interactions for the payload
        """
        return self._interactions.get(payload_id, [])

    def get_payload(self, payload_id: uuid.UUID) -> Optional[CollaboratorPayload]:
        """
        Get a payload by ID.

        Args:
            payload_id: Payload ID

        Returns:
            CollaboratorPayload if found, None otherwise
        """
        return self._payloads.get(payload_id)

    def get_all_payloads(self) -> List[CollaboratorPayload]:
        """
        Get all generated payloads.

        Returns:
            List of all payloads
        """
        return list(self._payloads.values())

    def get_interaction_count(self, payload_id: uuid.UUID) -> int:
        """
        Get the number of interactions for a payload.

        Args:
            payload_id: Payload ID

        Returns:
            Number of interactions
        """
        return len(self._interactions.get(payload_id, []))

    async def start_listener(self, protocol: Protocol, port: int) -> None:
        """
        Start a listener for a specific protocol.

        Args:
            protocol: Protocol to listen for
            port: Port to listen on

        Note:
            This is a placeholder for actual listener implementation.
            Real implementation would start DNS, HTTP, or SMTP servers.
        """
        self._listeners[protocol] = True
        # Actual listener implementation would go here
        # For now, this is a stub that marks the listener as active

    async def stop_listener(self, protocol: Protocol) -> None:
        """
        Stop a listener for a specific protocol.

        Args:
            protocol: Protocol to stop listening for
        """
        if protocol in self._listener_tasks:
            self._listener_tasks[protocol].cancel()
            del self._listener_tasks[protocol]

        self._listeners[protocol] = False

    def is_listener_active(self, protocol: Protocol) -> bool:
        """
        Check if a listener is active.

        Args:
            protocol: Protocol to check

        Returns:
            True if listener is active, False otherwise
        """
        return self._listeners.get(protocol, False)

    def register_notification_callback(
        self, callback: Callable[[Interaction], None]
    ) -> None:
        """
        Register a callback for real-time interaction notifications.

        Args:
            callback: Function to call when an interaction is captured
        """
        if self._notifier:
            self._notifier.register_callback(callback)

    def register_async_notification_callback(
        self, callback: Callable[[Interaction], asyncio.Future]
    ) -> None:
        """
        Register an async callback for real-time interaction notifications.

        Args:
            callback: Async function to call when an interaction is captured
        """
        if self._notifier:
            self._notifier.register_async_callback(callback)

    def get_interaction_logs(self) -> List[dict]:
        """
        Get all logged interactions.

        Returns:
            List of logged interaction entries
        """
        return self._logger.get_logs()

    def analyze_interaction(self, interaction: Interaction) -> Dict:
        """
        Perform forensic analysis on an interaction.

        Args:
            interaction: Interaction to analyze

        Returns:
            Forensic analysis results
        """
        return self._forensic_analyzer.analyze_interaction(interaction)

    def generate_forensic_report(self, payload_id: uuid.UUID) -> Dict:
        """
        Generate a comprehensive forensic report for a payload.

        Args:
            payload_id: Payload ID to generate report for

        Returns:
            Forensic report
        """
        payload = self.get_payload(payload_id)
        if not payload:
            return {"error": "Payload not found"}

        interactions = self._interactions.get(payload_id, [])
        return self._forensic_analyzer.generate_forensic_report(payload, interactions)

    def detect_interaction_patterns(self, payload_id: uuid.UUID) -> List[Dict]:
        """
        Detect patterns in interactions for a payload.

        Args:
            payload_id: Payload ID to analyze

        Returns:
            List of detected patterns
        """
        interactions = self._interactions.get(payload_id, [])
        return self._forensic_analyzer.detect_patterns(interactions)
