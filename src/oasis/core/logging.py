"""
OASIS Logging Configuration

Provides centralized logging configuration with structured logging support.
"""

import logging
import logging.config
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .config import get_config


class StructuredFormatter(logging.Formatter):
    """Custom formatter that adds structured data to log records."""

    def format(self, record: logging.LogRecord) -> str:
        # Add structured data if available
        if hasattr(record, "structured_data"):
            record.msg = f"{record.msg} | Data: {record.structured_data}"
        return super().format(record)


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[Path] = None,
    enable_structured: bool = True,
) -> None:
    """
    Configure logging for the OASIS system.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, logs to console only)
        enable_structured: Whether to enable structured logging
    """
    config = get_config()

    # Use provided level or fall back to config
    level = log_level or config.logging.level

    # Use provided file or fall back to config
    if log_file is None and config.logging.file_path:
        log_file = Path(config.logging.file_path)

    # Create log directory if needed
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)

    # Base logging configuration
    logging_config: Dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "detailed": {
                "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": "standard",
                "stream": sys.stdout,
            }
        },
        "loggers": {
            "oasis": {"level": level, "handlers": ["console"], "propagate": False},
            "mitmproxy": {
                "level": "WARNING",  # Reduce mitmproxy noise
                "handlers": ["console"],
                "propagate": False,
            },
        },
        "root": {"level": "WARNING", "handlers": ["console"]},
    }

    # Add structured formatter if enabled
    if enable_structured:
        logging_config["formatters"]["structured"] = {
            "()": StructuredFormatter,
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }
        logging_config["handlers"]["console"]["formatter"] = "structured"

    # Add file handler if log file specified
    if log_file:
        logging_config["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": level,
            "formatter": "detailed",
            "filename": str(log_file),
            "maxBytes": config.logging.max_file_size,
            "backupCount": config.logging.backup_count,
            "encoding": "utf-8",
        }
        logging_config["loggers"]["oasis"]["handlers"].append("file")
        logging_config["loggers"]["mitmproxy"]["handlers"].append("file")
        logging_config["root"]["handlers"].append("file")

    # Apply configuration
    logging.config.dictConfig(logging_config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


def log_structured(
    logger: logging.Logger, level: int, message: str, **structured_data: Any
) -> None:
    """
    Log a message with structured data.

    Args:
        logger: Logger instance
        level: Logging level
        message: Log message
        **structured_data: Additional structured data to include
    """
    # Create a custom LogRecord with structured data
    record = logger.makeRecord(logger.name, level, "", 0, message, (), None)
    record.structured_data = structured_data
    logger.handle(record)
