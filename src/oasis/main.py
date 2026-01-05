"""
OASIS Main Entry Point

Provides the main entry point for the OASIS application with proper initialization.
"""

import argparse
import sys
from pathlib import Path

from .core.config import get_config
from .core.logging import get_logger, setup_logging


def main() -> None:
    """Main entry point for OASIS application."""
    # Parse arguments first (before any heavy initialization)
    parser = argparse.ArgumentParser(
        description="OASIS - Open Architecture Security Interception Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="OASIS 0.1.0",
    )
    parser.add_argument(
        "--theme",
        choices=["dark", "light"],
        default="dark",
        help="UI theme (default: dark)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize configuration
        config = get_config()

        # Setup logging
        setup_logging(
            log_level=config.logging.level,
            log_file=(
                Path(config.logging.file_path) if config.logging.file_path else None
            ),
        )

        logger = get_logger(__name__)
        logger.info("Starting OASIS - Open Architecture Security Interception Suite")
        logger.info(f"Environment: {config.environment}")
        logger.info(f"Debug mode: {config.debug or args.debug}")

        # Launch GUI application
        from .ui.app import launch_gui

        # Use theme from args or config
        theme = args.theme if args.theme else getattr(config, "ui_theme", "dark")

        exit_code = launch_gui(theme=theme)
        sys.exit(exit_code)

    except KeyboardInterrupt:
        logger = get_logger(__name__)
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger = get_logger(__name__)
        logger.error(f"Failed to start OASIS: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
