# OASIS - Open Architecture Security Interception Suite

[![Python 3.11/3.12](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-269%20passing-brightgreen.svg)](tests/)
## Table of Contents

- [🚀 Features](#-features)
  - [Core Capabilities](#core-capabilities)
  - [Advanced Features](#advanced-features)
- [📋 Requirements](#-requirements)
- [🔧 Installation](#-installation)
  - [Quick Install](#quick-install)
  - [Alternative Installation Methods](#alternative-installation-methods)
- [🎯 Quick Start](#-quick-start)
  - [1. Launch OASIS](#1-launch-oasis)
    - [GUI Application (Recommended)](#gui-application-recommended)
    - [CLI Interface](#cli-interface)
    - [API Server](#api-server)
    - [Python Module (Development)](#python-module-development)
  - [2. Configure Your Browser](#2-configure-your-browser)
  - [3. CLI Usage Examples](#3-cli-usage-examples)
  - [4. Troubleshooting](#4-troubleshooting)
- [📚 Documentation](#-documentation)
- [🏗️ Project Structure](#-project-structure)
- [🧪 Testing](#-testing)
- [🔒 Security](#-security)
- [🤝 Contributing](#-contributing)
  - [Development Setup](#development-setup)
- [📊 Performance](#-performance)
- [🆚 Comparison with Burp Suite](#-comparison-with-burp-suite)
- [📝 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Support](#-support)
- [🗺️ Roadmap](#-roadmap)


A comprehensive, open-source penetration testing platform designed as a modern alternative to Burp Suite. Built with Python 3.11+, featuring async I/O, property-based testing, and enterprise-grade security.

## 🚀 Features

### Core Capabilities
- **HTTP/HTTPS Proxy**: Full traffic interception with automatic certificate generation
- **Vulnerability Scanner**: OWASP Top 10 detection with passive and active scanning
- **Request Repeater**: Manual request crafting with syntax highlighting
- **Attack Engine (Intruder)**: Automated attacks with multiple attack types
- **Data Decoder**: Comprehensive encoding/decoding utilities
- **Session Analyzer (Sequencer)**: Token randomness and entropy analysis
- **Collaborator Service**: Out-of-band interaction detection (OAST)
- **Extension Framework**: Plugin architecture with security sandboxing

### Advanced Features
- **Async I/O Architecture**: High-performance concurrent request handling
- **Connection Pooling**: Efficient resource management
- **Memory-Bounded Processing**: Streaming for large payloads (>10MB)
- **REST API**: Full programmatic access
- **CLI Interface**: Command-line automation support
- **External Integrations**: JIRA, GitHub, webhooks
- **Enterprise Authentication**: LDAP, SAML, OAuth support
- **Compliance Reporting**: PCI DSS, HIPAA, SOX compatible

## 📋 Requirements

- Python 3.11/3.12
- 4GB RAM minimum (8GB recommended)
- Linux, macOS, or Windows

## 🔧 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/JAEKTS/oasis.git
cd oasis

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install OASIS
pip install -e .

# Run oasis
oasis
```

## 🎯 Quick Start

### 1. Launch OASIS

After installation, you have multiple ways to launch OASIS:

#### GUI Application (Recommended)
Launch the full graphical interface:
```bash
oasis
```

#### CLI Interface
Use the command-line interface for automation:
```bash
oasis-cli --help
```

#### API Server
Start the REST API server:
```bash
oasis-api
```

Or with custom host/port:
```bash
oasis-cli serve --host 0.0.0.0 --port 8080
```

API documentation will be available at: `http://localhost:8000/api/docs`

#### Python Module (Development)
Run directly as a Python module without installation:
```bash
python -m oasis
```

### 2. Configure Your Browser

Set your browser's proxy settings to:
- **Host**: 127.0.0.1
- **Port**: 8080

For HTTPS traffic, install the mitmproxy CA certificate (found in `~/.mitmproxy/`).

### 3. CLI Usage Examples

```bash
# Create a new project
oasis-cli project create "My Test" -s "https://example.com/*"

# List all projects
oasis-cli project list

# Start a vulnerability scan
oasis-cli scan start <project-id> -c sql_injection -c xss

# Export findings
oasis-cli export findings <project-id> -f json -o results.json

# Start API server
oasis-cli serve --host 0.0.0.0 --port 8080
```

### 4. Troubleshooting

**Command not found?**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Reinstall if needed
pip install --force-reinstall -e .
```

**Import errors?**
```bash
# Check Python version (requires 3.11/3.12)
python --version

# Reinstall dependencies
pip install -r requirements.txt
```

**GUI doesn't start?**
```bash
# Ensure PyQt6 is installed
pip install PyQt6
```

## 📚 Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- **[API Documentation](docs/api/README.md)**: REST API reference and OpenAPI specification
- **[Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md)**: Production deployment instructions
- **[Contributing Guide](CONTRIBUTING.md)**: Guidelines for contributors
- **[Project Structure](docs/developer/PROJECT_STRUCTURE.md)**: Codebase organization

For additional resources:
- **Examples**: See [examples/](examples/) for usage demonstrations
- **Issues**: Report bugs at [GitHub Issues](https://github.com/yourusername/oasis/issues)
- **Discussions**: Join conversations at [GitHub Discussions](https://github.com/yourusername/oasis/discussions)

## 🏗️ Project Structure

```
oasis/
├── src/oasis/                    # Main application code
│   ├── api/                      # REST API
│   ├── cli/                      # Command-line interface
│   ├── collaborator/             # Out-of-band testing
│   ├── core/                     # Core infrastructure
│   ├── decoder/                  # Encoding/decoding utilities
│   ├── deployment/               # Packaging and updates
│   ├── extensions/               # Plugin framework
│   ├── integrations/             # External tool integrations
│   ├── intruder/                 # Attack engine
│   ├── proxy/                    # HTTP/HTTPS proxy
│   ├── repeater/                 # Request repeater
│   ├── scanner/                  # Vulnerability scanner
│   ├── security/                 # Security features
│   ├── sequencer/                # Token analyzer
│   ├── storage/                  # Data persistence
│   └── ui/                       # PyQt6 GUI
├── tests/                        # Comprehensive test suite
│   ├── core/                     # Core component tests
│   ├── integration/              # Integration tests
│   ├── system/                   # System-level tests
│   └── */                        # Module-specific tests
├── examples/                     # Usage examples
├── docs/                         # Documentation
├── scripts/                      # Utility scripts
└── .kiro/specs/                  # Feature specifications
```

## 🧪 Testing

OASIS uses comprehensive testing with both unit tests and property-based tests:

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/core/                    # Core functionality
pytest tests/integration/             # Integration tests
pytest -m "not slow"                  # Skip slow tests

# Run with coverage
pytest --cov=src/oasis --cov-report=html

# Run property-based tests
pytest tests/ -k "properties"
```

**Test Results**: 269 passing tests (92.8% pass rate)

## 🔒 Security

OASIS implements enterprise-grade security features:

- **Encryption at Rest**: AES-256 for sensitive data
- **Encryption in Transit**: TLS 1.3 for all network communications
- **Secure Key Management**: Key derivation and rotation
- **Audit Logging**: Comprehensive logging of all actions

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📊 Performance

OASIS is designed for high performance:

- **Concurrent Connections**: 1000+ simultaneous connections
- **Response Time Overhead**: <100ms average
- **Memory Management**: Automatic garbage collection
- **Large Payload Streaming**: Efficient handling of >10MB payloads
- **Async I/O**: Non-blocking operations throughout

See [docs/reports/PRODUCTION_READINESS_REPORT.md](docs/reports/PRODUCTION_READINESS_REPORT.md) for detailed performance metrics.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [mitmproxy](https://mitmproxy.org/) - HTTP/HTTPS proxy library
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) - GUI framework
- [Hypothesis](https://hypothesis.readthedocs.io/) - Property-based testing
- [FastAPI](https://fastapi.tiangolo.com/) - REST API framework

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Examples**: [examples/](examples/)
- **Issues**: [GitHub Issues](https://github.com/JAEKts/oasis/issues)
- **Discussions**: [GitHub Discussions](https://github.com/JAEKts/oasis/discussions)

---

**Last Updated**: January 05, 2026
