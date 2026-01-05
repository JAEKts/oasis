# OASIS Launch Guide

This guide provides simple, reliable methods to launch OASIS after cloning the repository.

## Table of Contents

- [Quick Start](#quick-start)
  - [Method 1: Using Launch Scripts (Recommended)](#method-1-using-launch-scripts-recommended)
  - [Method 2: Using Python Module](#method-2-using-python-module)
- [Entry Points](#entry-points)
  - [1. GUI Application (Primary)](#1-gui-application-primary)
  - [2. CLI Application](#2-cli-application)
  - [3. API Server](#3-api-server)
- [Troubleshooting](#troubleshooting)
  - [Import Errors](#import-errors)
  - [Configuration Errors](#configuration-errors)
  - [Missing Dependencies](#missing-dependencies)
  - [GUI Doesn't Start](#gui-doesnt-start)
- [Validation](#validation)
- [Configuration](#configuration)
- [Development Mode](#development-mode)
- [Next Steps](#next-steps)

## Quick Start

### Method 1: Using Launch Scripts (Recommended)

The easiest way to launch OASIS:

```bash
# Launch GUI application
./scripts/launch_oasis.sh

# Launch CLI application
./scripts/launch_oasis_cli.sh --help
```

### Method 2: Using Python Module

If you prefer to use Python directly:

```bash
# Launch GUI application
PYTHONPATH=src python -m oasis

# Launch CLI application
PYTHONPATH=src python -m oasis.cli.main --help
```

## Entry Points

OASIS provides three main entry points:

### 1. GUI Application (Primary)

The main graphical user interface for interactive penetration testing.

**Launch command:**
```bash
PYTHONPATH=src python -m oasis
```

**What it does:**
- Starts the PyQt6 GUI application
- Provides access to all OASIS tools (Proxy, Repeater, Scanner, Intruder, etc.)
- Loads configuration from `.env` file or uses defaults

**Requirements:**
- Python 3.11+
- PyQt6 (installed)
- Other dependencies in requirements.txt

### 2. CLI Application

Command-line interface for automation and scripting.

**Launch command:**
```bash
PYTHONPATH=src python -m oasis.cli.main [COMMAND] [OPTIONS]
```

**Available commands:**
```bash
# Project management
PYTHONPATH=src python -m oasis.cli.main project create "My Project"
PYTHONPATH=src python -m oasis.cli.main project list
PYTHONPATH=src python -m oasis.cli.main project info <project-id>

# Vulnerability scanning
PYTHONPATH=src python -m oasis.cli.main scan start <project-id>

# Data export
PYTHONPATH=src python -m oasis.cli.main export findings <project-id> -f json

# Start API server
PYTHONPATH=src python -m oasis.cli.main serve --host 0.0.0.0 --port 8080
```

**Requirements:**
- Python 3.11+
- Click (installed)
- Other dependencies in requirements.txt

### 3. API Server

REST API for programmatic access and external tool integration.

**Launch command:**
```bash
PYTHONPATH=src python -m oasis.cli.main serve
```

Or directly:
```bash
PYTHONPATH=src python -c "from oasis.api.app import run_server; run_server()"
```

**Requirements:**
- Python 3.11+
- FastAPI and uvicorn (requires installation)
- Other dependencies in requirements.txt

**Note:** The API server requires additional dependencies that may not be installed:
```bash
pip install fastapi uvicorn
```

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError: No module named 'oasis'`:

**Solution:** Make sure to set `PYTHONPATH=src` before running Python commands, or use the provided launch scripts.

### Configuration Errors

If you see validation errors about missing configuration:

**Solution:** The application will auto-generate default configuration. You can customize it by creating a `.env` file in the project root.

### Missing Dependencies

If you see errors about missing packages (e.g., `fastapi`, `uvicorn`):

**Solution:** Install the missing dependencies:
```bash
pip install -r requirements.txt
```

Note: Some dependencies may have build issues. The GUI and CLI work with minimal dependencies.

### GUI Doesn't Start

If the GUI launches but doesn't display:

**Solution:** Ensure PyQt6 is properly installed:
```bash
pip install PyQt6
```

## Validation

To validate that all entry points are working correctly:

```bash
python scripts/test_entry_points.py
```

This script tests all entry points and reports their status.

## Configuration

OASIS uses environment variables for configuration. Create a `.env` file in the project root:

```env
# Environment
ENVIRONMENT=development
DEBUG=false

# Logging
LOGGING__LEVEL=INFO
LOGGING__FILE_PATH=./logs/oasis.log

# Proxy
PROXY__HOST=127.0.0.1
PROXY__PORT=8080

# Database
DATABASE__URL=sqlite:///oasis.db

# Vault Storage
VAULT__BASE_PATH=./oasis_vault
VAULT__AUTO_SAVE=true
```

## Development Mode

For development, you can install OASIS in editable mode (if dependencies allow):

```bash
pip install -e .
```

Then you can use the simpler commands:
```bash
oasis              # GUI
oasis-cli --help   # CLI
oasis-api          # API server
```

**Note:** Installation may fail due to dependency build issues. The `PYTHONPATH` method is more reliable.

## Next Steps

- Read the [../../README.md](../../README.md) for project overview
- Check [../../CONTRIBUTING.md](../../CONTRIBUTING.md) for development guidelines
- See [../](../) for detailed documentation
