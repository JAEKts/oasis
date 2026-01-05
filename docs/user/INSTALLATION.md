# OASIS Installation & Launch Guide

## Table of Contents

- [Installation](#installation)
  - [Option 1: Install from Source (Development)](#option-1-install-from-source-development)
  - [Option 2: Install from PyPI (When Published)](#option-2-install-from-pypi-when-published)
- [Launching OASIS](#launching-oasis)
  - [1. GUI Application (Default)](#1-gui-application-default)
  - [2. CLI Interface](#2-cli-interface)
  - [3. API Server](#3-api-server)
  - [4. Python Module (Development)](#4-python-module-development)
- [Development Setup](#development-setup)
- [Troubleshooting](#troubleshooting)
  - [Command not found](#command-not-found)
  - [Import errors](#import-errors)
- [Next Steps](#next-steps)

## Installation

### Option 1: Install from Source (Development)
```bash
# Clone the repository
git clone https://github.com/your-org/oasis.git
cd oasis

# Install in editable mode
pip install -e .
```

### Option 2: Install from PyPI (When Published)
```bash
pip install oasis-pentest
```

## Launching OASIS

After installation, you have multiple ways to launch OASIS:

### 1. GUI Application (Default)
Launch the full graphical interface:
```bash
oasis
```

### 2. CLI Interface
Use the command-line interface for automation:
```bash
oasis-cli --help
```

**CLI Examples:**
```bash
# Create a new project
oasis-cli project create "My Test" -s "https://example.com/*"

# List all projects
oasis-cli project list

# Start a vulnerability scan
oasis-cli scan start <project-id> -c sql_injection -c xss

# Export findings
oasis-cli export findings <project-id> -f json -o results.json
```

### 3. API Server
Start the REST API server:
```bash
oasis-api
```

Or with custom host/port:
```bash
oasis-cli serve --host 0.0.0.0 --port 8080
```

API documentation will be available at: `http://localhost:8000/api/docs`

### 4. Python Module (Development)
Run directly as a Python module without installation:
```bash
python -m oasis
```

## Development Setup

For development, install with dev dependencies:
```bash
# Using Poetry
poetry install

# Using pip
pip install -e ".[dev]"
```

## Troubleshooting

### Command not found
If `oasis` command is not found after installation:
1. Ensure pip's bin directory is in your PATH
2. Try using the full path: `python -m oasis`
3. Reinstall: `pip install --force-reinstall -e .`

### Import errors
If you get import errors:
1. Ensure you're in the correct virtual environment
2. Reinstall dependencies: `pip install -r requirements.txt`
3. Check Python version: `python --version` (requires Python 3.11+)

## Next Steps

- Read the [README](../../README.md) for feature overview
- Check [CONTRIBUTING](../../CONTRIBUTING.md) for development guidelines
- See [../deployment/DEPLOYMENT_GUIDE.md](../deployment/DEPLOYMENT_GUIDE.md) for production deployment
