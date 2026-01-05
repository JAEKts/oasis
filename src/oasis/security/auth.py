"""
OASIS Authentication Manager

Provides enterprise authentication integration supporting LDAP, SAML, and OAuth.
"""

import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..core.logging import get_logger
from .audit import AuditEventType, log_audit_event
from .encryption import hash_password, verify_password

logger = get_logger(__name__)


class AuthProviderType(str, Enum):
    """Types of authentication providers."""

    LOCAL = "local"
    LDAP = "ldap"
    SAML = "saml"
    OAUTH = "oauth"


class AuthProvider(ABC):
    """Base class for authentication providers."""

    @abstractmethod
    def authenticate(
        self, username: str, credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user.

        Args:
            username: Username
            credentials: Authentication credentials

        Returns:
            User information if successful, None otherwise
        """
        pass

    @abstractmethod
    def get_provider_type(self) -> AuthProviderType:
        """Get the provider type."""
        pass


class LocalAuthProvider(AuthProvider):
    """Local authentication provider using password hashing."""

    def __init__(self) -> None:
        """Initialize local auth provider."""
        self.users: Dict[str, Dict[str, Any]] = {}

    def register_user(
        self, username: str, password: str, email: str, **kwargs: Any
    ) -> bool:
        """
        Register a new user.

        Args:
            username: Username
            password: Password
            email: Email address
            **kwargs: Additional user attributes

        Returns:
            True if successful, False otherwise
        """
        try:
            if username in self.users:
                logger.warning(f"User {username} already exists")
                return False

            password_hash = hash_password(password)

            self.users[username] = {
                "username": username,
                "password_hash": password_hash,
                "email": email,
                "created_at": datetime.now(UTC).isoformat(),
                "last_login": None,
                **kwargs,
            }

            log_audit_event(
                AuditEventType.DATA_WRITE,
                "User registered",
                username=username,
                resource_type="user",
                resource_id=username,
            )

            logger.info(f"Registered user: {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to register user {username}: {e}")
            return False

    def authenticate(
        self, username: str, credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user with password.

        Args:
            username: Username
            credentials: Dictionary containing 'password'

        Returns:
            User information if successful, None otherwise
        """
        try:
            if username not in self.users:
                log_audit_event(
                    AuditEventType.LOGIN_FAILED,
                    "User not found",
                    username=username,
                    result="failure",
                )
                return None

            user = self.users[username]
            password = credentials.get("password")

            if not password:
                log_audit_event(
                    AuditEventType.LOGIN_FAILED,
                    "No password provided",
                    username=username,
                    result="failure",
                )
                return None

            if not verify_password(password, user["password_hash"]):
                log_audit_event(
                    AuditEventType.LOGIN_FAILED,
                    "Invalid password",
                    username=username,
                    result="failure",
                )
                return None

            # Update last login
            user["last_login"] = datetime.now(UTC).isoformat()

            log_audit_event(
                AuditEventType.LOGIN,
                "User logged in",
                username=username,
                resource_type="user",
                resource_id=username,
            )

            # Return user info (without password hash)
            user_info = {k: v for k, v in user.items() if k != "password_hash"}
            return user_info

        except Exception as e:
            logger.error(f"Authentication failed for {username}: {e}")
            log_audit_event(
                AuditEventType.LOGIN_FAILED,
                f"Authentication error: {e}",
                username=username,
                result="failure",
                severity="error",
            )
            return None

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> bool:
        """
        Change user password.

        Args:
            username: Username
            old_password: Current password
            new_password: New password

        Returns:
            True if successful, False otherwise
        """
        try:
            if username not in self.users:
                return False

            user = self.users[username]

            # Verify old password
            if not verify_password(old_password, user["password_hash"]):
                log_audit_event(
                    AuditEventType.PASSWORD_CHANGE,
                    "Password change failed - invalid old password",
                    username=username,
                    result="failure",
                )
                return False

            # Update password
            user["password_hash"] = hash_password(new_password)

            log_audit_event(
                AuditEventType.PASSWORD_CHANGE,
                "Password changed",
                username=username,
                resource_type="user",
                resource_id=username,
            )

            logger.info(f"Password changed for user: {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to change password for {username}: {e}")
            return False

    def get_provider_type(self) -> AuthProviderType:
        """Get the provider type."""
        return AuthProviderType.LOCAL


class LDAPAuthProvider(AuthProvider):
    """LDAP authentication provider (stub for enterprise integration)."""

    def __init__(self, server: str, base_dn: str, **kwargs: Any) -> None:
        """
        Initialize LDAP auth provider.

        Args:
            server: LDAP server URL
            base_dn: Base DN for user search
            **kwargs: Additional LDAP configuration
        """
        self.server = server
        self.base_dn = base_dn
        self.config = kwargs
        logger.info(f"Initialized LDAP auth provider: {server}")

    def authenticate(
        self, username: str, credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user via LDAP.

        Args:
            username: Username
            credentials: Dictionary containing 'password'

        Returns:
            User information if successful, None otherwise
        """
        # This is a stub implementation
        # In production, this would use python-ldap or ldap3 library
        logger.warning("LDAP authentication not fully implemented - stub only")

        log_audit_event(
            AuditEventType.LOGIN_FAILED,
            "LDAP authentication not implemented",
            username=username,
            result="failure",
            details={"provider": "ldap", "server": self.server},
        )

        return None

    def get_provider_type(self) -> AuthProviderType:
        """Get the provider type."""
        return AuthProviderType.LDAP


class SAMLAuthProvider(AuthProvider):
    """SAML authentication provider (stub for enterprise integration)."""

    def __init__(self, idp_url: str, sp_entity_id: str, **kwargs: Any) -> None:
        """
        Initialize SAML auth provider.

        Args:
            idp_url: Identity Provider URL
            sp_entity_id: Service Provider entity ID
            **kwargs: Additional SAML configuration
        """
        self.idp_url = idp_url
        self.sp_entity_id = sp_entity_id
        self.config = kwargs
        logger.info(f"Initialized SAML auth provider: {idp_url}")

    def authenticate(
        self, username: str, credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user via SAML.

        Args:
            username: Username
            credentials: Dictionary containing SAML assertion

        Returns:
            User information if successful, None otherwise
        """
        # This is a stub implementation
        # In production, this would use python3-saml library
        logger.warning("SAML authentication not fully implemented - stub only")

        log_audit_event(
            AuditEventType.LOGIN_FAILED,
            "SAML authentication not implemented",
            username=username,
            result="failure",
            details={"provider": "saml", "idp": self.idp_url},
        )

        return None

    def get_provider_type(self) -> AuthProviderType:
        """Get the provider type."""
        return AuthProviderType.SAML


class OAuthAuthProvider(AuthProvider):
    """OAuth authentication provider (stub for enterprise integration)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_url: str,
        token_url: str,
        **kwargs: Any,
    ) -> None:
        """
        Initialize OAuth auth provider.

        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            auth_url: Authorization URL
            token_url: Token URL
            **kwargs: Additional OAuth configuration
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = auth_url
        self.token_url = token_url
        self.config = kwargs
        logger.info(f"Initialized OAuth auth provider: {auth_url}")

    def authenticate(
        self, username: str, credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user via OAuth.

        Args:
            username: Username
            credentials: Dictionary containing OAuth token

        Returns:
            User information if successful, None otherwise
        """
        # This is a stub implementation
        # In production, this would use requests-oauthlib or authlib
        logger.warning("OAuth authentication not fully implemented - stub only")

        log_audit_event(
            AuditEventType.LOGIN_FAILED,
            "OAuth authentication not implemented",
            username=username,
            result="failure",
            details={"provider": "oauth", "auth_url": self.auth_url},
        )

        return None

    def get_provider_type(self) -> AuthProviderType:
        """Get the provider type."""
        return AuthProviderType.OAUTH


class Session(BaseModel):
    """User session model."""

    session_id: str = Field(description="Session ID")
    user_id: str = Field(description="User ID")
    username: str = Field(description="Username")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Session creation time"
    )
    expires_at: datetime = Field(description="Session expiration time")
    last_activity: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Last activity time"
    )
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")


class AuthenticationManager:
    """
    Manages authentication and session management.

    Provides:
    - Multiple authentication provider support
    - Session management with timeout
    - User activity tracking
    - Integration with audit logging
    """

    def __init__(self, session_timeout: int = 3600) -> None:
        """
        Initialize authentication manager.

        Args:
            session_timeout: Session timeout in seconds (default 1 hour)
        """
        self.providers: Dict[AuthProviderType, AuthProvider] = {}
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = session_timeout

        # Initialize default local provider
        self.add_provider(LocalAuthProvider())

    def add_provider(self, provider: AuthProvider) -> None:
        """
        Add an authentication provider.

        Args:
            provider: Authentication provider instance
        """
        provider_type = provider.get_provider_type()
        self.providers[provider_type] = provider
        logger.info(f"Added authentication provider: {provider_type.value}")

    def authenticate(
        self,
        username: str,
        credentials: Dict[str, Any],
        provider_type: AuthProviderType = AuthProviderType.LOCAL,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[str]:
        """
        Authenticate a user and create a session.

        Args:
            username: Username
            credentials: Authentication credentials
            provider_type: Authentication provider to use
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Session ID if successful, None otherwise
        """
        try:
            # Get provider
            provider = self.providers.get(provider_type)
            if not provider:
                logger.error(
                    f"Authentication provider not found: {provider_type.value}"
                )
                return None

            # Authenticate
            user_info = provider.authenticate(username, credentials)
            if not user_info:
                return None

            # Create session
            session_id = secrets.token_urlsafe(32)
            expires_at = datetime.now(UTC) + timedelta(seconds=self.session_timeout)

            session = Session(
                session_id=session_id,
                user_id=user_info.get("username", username),
                username=username,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            self.sessions[session_id] = session

            logger.info(f"Created session for user: {username}")
            return session_id

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None

    def validate_session(self, session_id: str) -> Optional[Session]:
        """
        Validate a session.

        Args:
            session_id: Session ID

        Returns:
            Session if valid, None otherwise
        """
        session = self.sessions.get(session_id)
        if not session:
            return None

        # Check expiration
        if datetime.now(UTC) > session.expires_at:
            self.logout(session_id)
            return None

        # Update last activity
        session.last_activity = datetime.now(UTC)

        return session

    def logout(self, session_id: str) -> bool:
        """
        Logout a user and destroy session.

        Args:
            session_id: Session ID

        Returns:
            True if successful, False otherwise
        """
        session = self.sessions.get(session_id)
        if not session:
            return False

        log_audit_event(
            AuditEventType.LOGOUT,
            "User logged out",
            username=session.username,
            user_id=session.user_id,
        )

        del self.sessions[session_id]
        logger.info(f"Logged out user: {session.username}")
        return True

    def get_active_sessions(self) -> List[Session]:
        """
        Get all active sessions.

        Returns:
            List of active sessions
        """
        now = datetime.now(UTC)
        return [s for s in self.sessions.values() if s.expires_at > now]

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.

        Returns:
            Number of sessions removed
        """
        now = datetime.now(UTC)
        expired = [sid for sid, s in self.sessions.items() if s.expires_at <= now]

        for session_id in expired:
            del self.sessions[session_id]

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")

        return len(expired)


# Global authentication manager instance
_auth_manager: Optional[AuthenticationManager] = None


def get_auth_manager() -> AuthenticationManager:
    """Get the global authentication manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthenticationManager()
    return _auth_manager
