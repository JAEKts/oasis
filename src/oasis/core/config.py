"""
OASIS Configuration Management

Provides centralized configuration management with validation and environment support.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, ConfigDict

try:
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback for older pydantic versions
    from pydantic import BaseSettings


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = Field(default="INFO", description="Logging level")
    file_path: Optional[str] = Field(default=None, description="Log file path")
    max_file_size: int = Field(
        default=10_000_000, description="Max log file size in bytes"
    )
    backup_count: int = Field(default=5, description="Number of backup log files")

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()


class ProxyConfig(BaseModel):
    """Proxy configuration."""

    host: str = Field(default="127.0.0.1", description="Proxy bind host")
    port: int = Field(default=8080, description="Proxy bind port")
    ca_cert_path: Optional[str] = Field(default=None, description="CA certificate path")
    ca_key_path: Optional[str] = Field(default=None, description="CA private key path")

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Invalid port: {v}. Must be between 1 and 65535")
        return v


class DatabaseConfig(BaseModel):
    """Database configuration."""

    url: str = Field(default="sqlite:///oasis.db", description="Database URL")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max connection overflow")
    echo: bool = Field(default=False, description="Enable SQL query logging")


class RedisConfig(BaseModel):
    """Redis configuration."""

    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, description="Redis port")
    db: int = Field(default=0, description="Redis database number")
    password: Optional[str] = Field(default=None, description="Redis password")

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Invalid port: {v}. Must be between 1 and 65535")
        return v


class SecurityConfig(BaseModel):
    """Security configuration."""

    secret_key: str = Field(description="Secret key for encryption")
    encryption_algorithm: str = Field(
        default="AES-256-GCM", description="Encryption algorithm"
    )
    hash_algorithm: str = Field(default="SHA-256", description="Hash algorithm")
    session_timeout: int = Field(default=3600, description="Session timeout in seconds")


class PerformanceConfig(BaseModel):
    """Performance configuration."""

    max_concurrent_connections: int = Field(
        default=1000, description="Max concurrent connections"
    )
    request_timeout: int = Field(default=30, description="Request timeout in seconds")
    max_request_size: int = Field(
        default=100_000_000, description="Max request size in bytes"
    )
    thread_pool_size: int = Field(default=10, description="Thread pool size")


class VaultConfig(BaseModel):
    """Vault storage configuration."""

    base_path: str = Field(
        default="./oasis_vault", description="Base vault directory path"
    )
    auto_save: bool = Field(default=True, description="Enable automatic saving")
    backup_enabled: bool = Field(default=True, description="Enable automatic backups")
    backup_interval: int = Field(default=3600, description="Backup interval in seconds")
    max_backups: int = Field(
        default=10, description="Maximum number of backups to keep"
    )


class OASISConfig(BaseSettings):
    """Main OASIS configuration."""

    # Environment and deployment
    environment: str = Field(default="development", description="Environment name")
    debug: bool = Field(default=False, description="Enable debug mode")

    # Component configurations
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    security: SecurityConfig = Field(default=None, description="Security configuration")
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)

    # Plugin configuration
    plugin_directories: List[str] = Field(default_factory=lambda: ["./plugins"])

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    @field_validator("security", mode="before")
    @classmethod
    def ensure_security_config(
        cls, v: Union[Dict[str, Any], SecurityConfig, None]
    ) -> SecurityConfig:
        if v is None or (isinstance(v, dict) and not v):
            # Generate secret key if not provided
            import secrets

            return SecurityConfig(secret_key=secrets.token_urlsafe(32))
        elif isinstance(v, dict):
            # Generate secret key if not provided
            if "secret_key" not in v:
                import secrets

                v["secret_key"] = secrets.token_urlsafe(32)
            return SecurityConfig(**v)
        return v


# Global configuration instance
_config: Optional[OASISConfig] = None


def get_config() -> OASISConfig:
    """
    Get the global configuration instance.

    Returns:
        The global OASISConfig instance
    """
    global _config
    if _config is None:
        _config = load_config()
    return _config


def load_config(config_file: Optional[Path] = None) -> OASISConfig:
    """
    Load configuration from file and environment variables.

    Args:
        config_file: Optional path to configuration file

    Returns:
        Loaded configuration instance
    """
    # Set environment file if provided
    if config_file and config_file.exists():
        os.environ.setdefault("ENV_FILE", str(config_file))

    return OASISConfig()


def reload_config(config_file: Optional[Path] = None) -> OASISConfig:
    """
    Reload the global configuration.

    Args:
        config_file: Optional path to configuration file

    Returns:
        Reloaded configuration instance
    """
    global _config
    _config = load_config(config_file)
    return _config


def update_config(**kwargs: Any) -> None:
    """
    Update configuration values at runtime.

    Args:
        **kwargs: Configuration values to update
    """
    global _config
    if _config is None:
        _config = load_config()

    # Update configuration values
    for key, value in kwargs.items():
        if hasattr(_config, key):
            setattr(_config, key, value)
        else:
            raise ValueError(f"Unknown configuration key: {key}")


def get_vault_path() -> Path:
    """
    Get the configured vault base path.

    Returns:
        Path to the vault directory
    """
    config = get_config()
    vault_path = Path(config.vault.base_path)
    vault_path.mkdir(parents=True, exist_ok=True)
    return vault_path
