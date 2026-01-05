# OASIS Quick Start Guide

## Table of Contents

- [Installation](#installation)
- [Verify Installation](#verify-installation)
- [Launch OASIS](#launch-oasis)
  - [GUI Application](#gui-application)
  - [CLI Interface](#cli-interface)
  - [API Server](#api-server)
- [Development Mode](#development-mode)
- [Troubleshooting](#troubleshooting)
  - [Commands not found?](#commands-not-found)
  - [Import errors?](#import-errors)
- [Next Steps](#next-steps)
- [Key Features](#key-features)
- [Support](#support)

## Installation

```bash
# Clone and install
git clone https://github.com/your-org/oasis.git
cd oasis
pip install -e .
```

## Verify Installation

```bash
python scripts/verify_installation.py
```

## Launch OASIS

### GUI Application
```bash
oasis
```

### CLI Interface
```bash
# Get help
oasis-cli --help

# Create a project
oasis-cli project create "My Test" -s "https://example.com/*"

# List projects
oasis-cli project list

# Start a scan
oasis-cli scan start <project-id> -c sql_injection -c xss

# Export findings
oasis-cli export findings <project-id> -f json -o results.json
```

### API Server
```bash
# Start with defaults (localhost:8000)
oasis-api

# Or with custom settings
oasis-cli serve --host 0.0.0.0 --port 8080
```

API docs: http://localhost:8000/api/docs

## Development Mode

Run without installation:
```bash
python -m oasis
```

## Troubleshooting

### Commands not found?
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Reinstall
pip install -e .
```

### Import errors?
```bash
# Check Python version (requires 3.11+)
python --version

# Reinstall dependencies
pip install -r requirements.txt
```

## Next Steps

- Read [../../README.md](../../README.md) for full feature overview
- Check [INSTALLATION.md](INSTALLATION.md) for detailed setup
- See [../](../) for comprehensive documentation
- Review [../../CONTRIBUTING.md](../../CONTRIBUTING.md) to contribute

## Key Features

- **Proxy**: Intercept HTTP/HTTPS traffic
- **Scanner**: Detect OWASP Top 10 vulnerabilities
- **Repeater**: Manually craft and send requests
- **Intruder**: Automated attack engine
- **Decoder**: Encode/decode utilities
- **Sequencer**: Token randomness analysis
- **Collaborator**: Out-of-band interaction detection
- **Extensions**: Plugin framework

## Support

- Issues: https://github.com/your-org/oasis/issues
- Docs: [../../docs/](../../docs/)
- Examples: [../../examples/](../../examples/)
