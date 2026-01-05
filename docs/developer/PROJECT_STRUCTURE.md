# OASIS Project Structure

This document provides a comprehensive overview of the OASIS project structure and organization.

## Table of Contents

- [Directory Layout](#directory-layout)
- [Module Organization](#module-organization)
  - [Core Modules (`src/oasis/core/`)](#core-modules-srcoasiscore)
  - [Feature Modules](#feature-modules)
  - [Infrastructure Modules](#infrastructure-modules)
- [Test Organization](#test-organization)
  - [Unit Tests](#unit-tests)
  - [Property-Based Tests](#property-based-tests)
  - [Integration Tests (`tests/integration/`)](#integration-tests-testsintegration)
  - [System Tests (`tests/system/`)](#system-tests-testssystem)
- [Documentation Organization](#documentation-organization)
  - [User Documentation](#user-documentation)
  - [Developer Documentation](#developer-documentation)
  - [Validation Documentation](#validation-documentation)
- [Configuration Files](#configuration-files)
  - [Python Configuration](#python-configuration)
  - [Development Tools](#development-tools)
  - [IDE Configuration](#ide-configuration)
- [Entry Points](#entry-points)
  - [Main Entry Points](#main-entry-points)
  - [Example Scripts](#example-scripts)
- [Build Artifacts (Gitignored)](#build-artifacts-gitignored)
  - [Python Artifacts](#python-artifacts)
  - [Test Artifacts](#test-artifacts)
  - [Runtime Artifacts](#runtime-artifacts)
- [Naming Conventions](#naming-conventions)
  - [Files](#files)
  - [Code](#code)
  - [Tests](#tests)
- [Dependencies](#dependencies)
  - [Core Dependencies](#core-dependencies)
  - [Testing Dependencies](#testing-dependencies)
  - [Development Dependencies](#development-dependencies)
- [Version Control](#version-control)
  - [Tracked Files](#tracked-files)
  - [Ignored Files (see `.gitignore`)](#ignored-files-see-gitignore)
- [Maintenance](#maintenance)
  - [Regular Updates](#regular-updates)
  - [Cleanup Tasks](#cleanup-tasks)

## Directory Layout

```
oasis/
├── .git/                         # Git version control
├── .github/                      # GitHub workflows (if added)
├── .hypothesis/                  # Hypothesis test data (gitignored)
├── .kiro/                        # Kiro IDE specifications
│   └── specs/
│       └── oasis-pentest-suite/
│           ├── design.md         # System design document
│           ├── requirements.md   # Requirements specification
│           └── tasks.md          # Implementation task list
├── .pytest_cache/                # Pytest cache (gitignored)
├── .vscode/                      # VS Code settings (gitignored)
├── docs/                         # Documentation
│   ├── README.md                # Documentation index
│   ├── api/                      # API documentation
│   │   ├── README.md            # API overview
│   │   └── openapi.yaml         # OpenAPI specification
│   ├── deployment/              # Deployment documentation
│   │   └── DEPLOYMENT_GUIDE.md  # Deployment instructions
│   ├── developer/               # Developer documentation
│   │   ├── ENTRY_POINTS_FIXED.md # Entry point fixes
│   │   ├── PROJECT_STRUCTURE.md # This file
│   │   └── repeater_implementation.md # Repeater module details
│   ├── reports/                 # Analysis reports
│   │   └── PRODUCTION_READINESS_REPORT.md
│   └── user/                    # User documentation
│       ├── INSTALLATION.md      # Installation guide
│       ├── LAUNCH_GUIDE.md      # Launch guide
│       ├── LAUNCH_METHODS.md    # Launch methods
│       └── QUICK_START.md       # Quick start guide
├── examples/                     # Usage examples
│   ├── collaborator_demo.py     # Collaborator service example
│   ├── decoder_demo.py          # Decoder utilities example
│   ├── extension_demo.py        # Extension development example
│   ├── intruder_demo.py         # Intruder attack example
│   ├── repeater_demo.py         # Repeater usage example
│   ├── scanner_demo.py          # Scanner usage example
│   ├── security_demo.py         # Security features example
│   └── sequencer_demo.py        # Sequencer analysis example
├── scripts/                      # Utility scripts
│   └── run_system_tests.py      # System test runner
├── src/oasis/                    # Main application source
│   ├── api/                      # REST API
│   │   ├── routes/              # API route handlers
│   │   │   ├── findings.py      # Findings endpoints
│   │   │   ├── flows.py         # HTTP flows endpoints
│   │   │   ├── intruder.py      # Intruder endpoints
│   │   │   ├── projects.py      # Project management endpoints
│   │   │   ├── repeater.py      # Repeater endpoints
│   │   │   └── scanner.py       # Scanner endpoints
│   │   └── app.py               # FastAPI application
│   ├── cli/                      # Command-line interface
│   │   └── main.py              # CLI entry point
│   ├── collaborator/             # Out-of-band testing
│   │   ├── forensics.py         # Forensic analysis
│   │   └── notifications.py     # Interaction notifications
│   ├── core/                     # Core infrastructure
│   │   ├── config.py            # Configuration management
│   │   ├── exceptions.py        # Exception hierarchy
│   │   ├── load_testing.py      # Load testing utilities
│   │   ├── logging.py           # Logging configuration
│   │   ├── memory.py            # Memory management
│   │   ├── models.py            # Core data models
│   │   ├── performance.py       # Performance optimization
│   │   └── resource_manager.py  # Resource management
│   ├── decoder/                  # Encoding/decoding
│   │   ├── hasher.py            # Hash generation
│   │   └── transformer.py       # Data transformation
│   ├── deployment/               # Deployment tools
│   │   ├── packager.py          # Package creation
│   │   ├── security.py          # Deployment security
│   │   └── updater.py           # Update management
│   ├── extensions/               # Plugin framework
│   │   ├── api.py               # Extension API
│   │   ├── implementation.py    # Extension implementation
│   │   ├── manager.py           # Extension manager
│   │   ├── models.py            # Extension models
│   │   └── sandbox.py           # Security sandboxing
│   ├── integrations/             # External integrations
│   │   ├── github.py            # GitHub integration
│   │   ├── jira.py              # JIRA integration
│   │   └── webhook.py           # Webhook support
│   ├── intruder/                 # Attack engine
│   │   ├── analysis.py          # Result analysis
│   │   ├── config.py            # Attack configuration
│   │   ├── engine.py            # Attack execution
│   │   └── payloads.py          # Payload generation
│   ├── proxy/                    # HTTP/HTTPS proxy
│   │   └── engine.py            # Proxy engine
│   ├── repeater/                 # Request repeater
│   │   ├── comparison.py        # Response comparison
│   │   ├── editor.py            # Request editor
│   │   └── session.py           # Session management
│   ├── scanner/                  # Vulnerability scanner
│   │   ├── detectors/           # Vulnerability detectors
│   │   │   ├── csrf.py          # CSRF detection
│   │   │   ├── sql_injection.py # SQL injection detection
│   │   │   ├── ssrf.py          # SSRF detection
│   │   │   ├── xss.py           # XSS detection
│   │   │   └── xxe.py           # XXE detection
│   │   ├── active.py            # Active scanning
│   │   ├── detector.py          # Base detector
│   │   ├── engine.py            # Scanner engine
│   │   ├── passive.py           # Passive scanning
│   │   ├── policy.py            # Scan policies
│   │   └── reporting.py         # Report generation
│   ├── security/                 # Security features
│   │   ├── audit.py             # Audit logging
│   │   ├── auth.py              # Authentication
│   │   ├── compliance.py        # Compliance reporting
│   │   └── encryption.py        # Encryption utilities
│   ├── sequencer/                # Token analyzer
│   │   ├── analyzer.py          # Token analysis
│   │   ├── patterns.py          # Pattern detection
│   │   ├── reporting.py         # Report generation
│   │   └── tests.py             # Statistical tests
│   ├── storage/                  # Data persistence
│   │   ├── json_vault.py        # JSON storage
│   │   ├── manager.py           # Storage manager
│   │   ├── secure_vault.py      # Encrypted storage
│   │   ├── sqlite_vault.py      # SQLite storage
│   │   └── vault.py             # Base vault interface
│   ├── ui/                       # PyQt6 GUI
│   │   ├── dialogs/             # Dialog windows
│   │   │   ├── export_dialog.py # Export dialog
│   │   │   └── project_dialog.py # Project dialog
│   │   ├── widgets/             # UI widgets
│   │   │   ├── intruder_widget.py # Intruder widget
│   │   │   ├── proxy_widget.py  # Proxy widget
│   │   │   ├── repeater_widget.py # Repeater widget
│   │   │   ├── scanner_widget.py # Scanner widget
│   │   │   └── search_widget.py # Search widget
│   │   ├── app.py               # Application class
│   │   ├── main_window.py       # Main window
│   │   └── theme.py             # UI theming
│   ├── __init__.py              # Package initialization
│   └── main.py                  # Application entry point
├── tests/                        # Test suite
│   ├── collaborator/            # Collaborator tests
│   │   └── test_collaborator_properties.py
│   ├── core/                    # Core tests
│   │   ├── test_config_properties.py
│   │   ├── test_load_testing.py
│   │   ├── test_memory_properties.py
│   │   ├── test_models_properties.py
│   │   ├── test_performance_properties.py
│   │   ├── test_resource_efficiency_properties.py
│   │   └── test_resource_manager.py
│   ├── decoder/                 # Decoder tests
│   │   ├── test_decoder_properties.py
│   │   └── test_hasher.py
│   ├── extensions/              # Extension tests
│   │   └── test_extension_properties.py
│   ├── integration/             # Integration tests
│   │   ├── conftest.py
│   │   ├── test_cross_component.py
│   │   ├── test_e2e_workflows.py
│   │   └── test_external_dependencies.py
│   ├── intruder/                # Intruder tests
│   │   └── test_intruder_properties.py
│   ├── proxy/                   # Proxy tests
│   │   ├── test_certificates.py
│   │   ├── test_filtering_properties.py
│   │   ├── test_proxy_engine.py
│   │   ├── test_proxy_properties.py
│   │   └── test_traffic_modification.py
│   ├── repeater/                # Repeater tests
│   │   ├── test_editor.py
│   │   ├── test_repeater_properties.py
│   │   └── test_session.py
│   ├── scanner/                 # Scanner tests
│   │   └── test_scanner_properties.py
│   ├── security/                # Security tests
│   │   ├── test_audit_properties.py
│   │   └── test_security_properties.py
│   ├── sequencer/               # Sequencer tests
│   │   └── test_sequencer_properties.py
│   ├── storage/                 # Storage tests
│   │   ├── test_storage_management_properties.py
│   │   └── test_vault_properties.py
│   ├── system/                  # System tests
│   │   ├── test_performance_validation.py
│   │   └── test_system_integration.py
│   └── conftest.py              # Pytest configuration
├── venv/                         # Virtual environment (gitignored)
├── .env.example                  # Example environment file
├── .gitignore                    # Git ignore patterns
├── .pre-commit-config.yaml       # Pre-commit hooks
├── LICENSE                       # MIT License
├── Makefile                      # Development commands
├── pyproject.toml                # Project configuration
├── README.md                     # Project README
└── requirements.txt              # Python dependencies
```

## Module Organization

### Core Modules (`src/oasis/core/`)
Foundation components used throughout the application:
- Configuration management
- Data models (HTTPRequest, HTTPResponse, Project, Finding)
- Exception hierarchy
- Logging infrastructure
- Performance optimization (async I/O, connection pooling)
- Resource management (memory, CPU, connections)

### Feature Modules
Each feature module is self-contained with its own:
- Core implementation
- Data models
- Configuration
- README documentation

**Feature Modules:**
- `proxy/` - HTTP/HTTPS traffic interception
- `scanner/` - Vulnerability detection
- `repeater/` - Manual request testing
- `intruder/` - Automated attacks
- `decoder/` - Data transformation
- `sequencer/` - Token analysis
- `collaborator/` - Out-of-band testing
- `extensions/` - Plugin framework

### Infrastructure Modules
Supporting infrastructure:
- `api/` - REST API for programmatic access
- `cli/` - Command-line interface
- `ui/` - PyQt6 desktop application
- `storage/` - Data persistence (SQLite, JSON, encrypted)
- `security/` - Authentication, encryption, audit logging
- `deployment/` - Packaging and updates
- `integrations/` - External tool connections

## Test Organization

Tests mirror the source structure with additional categories:

### Unit Tests
Located in `tests/<module>/` matching `src/oasis/<module>/`:
- Test individual components in isolation
- Fast execution
- High coverage of edge cases

### Property-Based Tests
Files ending in `_properties.py`:
- Test universal correctness properties
- Use Hypothesis for input generation
- Validate design document properties
- Minimum 100 iterations per property

### Integration Tests (`tests/integration/`)
- `test_cross_component.py` - Multi-component workflows
- `test_e2e_workflows.py` - End-to-end scenarios
- `test_external_dependencies.py` - Database, filesystem, cache

### System Tests (`tests/system/`)
- `test_performance_validation.py` - Performance requirements
- `test_system_integration.py` - Complete system validation

## Documentation Organization

### User Documentation
- `README.md` - Project overview and quick start
- `docs/deployment/DEPLOYMENT_GUIDE.md` - Installation and deployment
- `docs/api/` - REST API documentation

### Developer Documentation
- `docs/developer/PROJECT_STRUCTURE.md` - This file
- `docs/developer/repeater_implementation.md` - Module implementation details
- `.kiro/specs/` - Feature specifications and design documents

### Validation Documentation
- `docs/reports/PRODUCTION_READINESS_REPORT.md` - Production validation results
- Test files serve as executable documentation

## Configuration Files

### Python Configuration
- `pyproject.toml` - Project metadata, dependencies, tool configuration
- `requirements.txt` - Pip-compatible dependency list
- `.pre-commit-config.yaml` - Code quality hooks

### Development Tools
- `Makefile` - Common development commands
- `.gitignore` - Version control exclusions
- `.env.example` - Environment variable template

### IDE Configuration
- `.vscode/` - VS Code settings (gitignored, user-specific)
- `.kiro/` - Kiro IDE specifications

## Entry Points

### Main Entry Points
1. **GUI Application**: `python -m src.oasis.main` (primary)
2. **CLI**: `python -m src.oasis.cli <command>` (for automation)
3. **API Server**: `python -m src.oasis.api.app` (REST API)
4. **Legacy**: `python oasis.py` (deprecated, backwards compatibility only)

### Example Scripts
Located in `examples/`, demonstrating:
- Module usage patterns
- API integration
- Extension development
- Common workflows

## Build Artifacts (Gitignored)

### Python Artifacts
- `__pycache__/` - Bytecode cache
- `*.pyc`, `*.pyo` - Compiled Python files
- `*.egg-info/` - Package metadata
- `dist/`, `build/` - Distribution packages

### Test Artifacts
- `.pytest_cache/` - Pytest cache
- `.hypothesis/` - Hypothesis test data
- `.coverage` - Coverage data
- `htmlcov/` - Coverage reports

### Runtime Artifacts
- `*.db`, `*.sqlite` - Database files
- `*.log` - Log files
- `venv/`, `env/` - Virtual environments

## Naming Conventions

### Files
- Python modules: `snake_case.py`
- Test files: `test_<module>.py` or `test_<module>_properties.py`
- Documentation: `UPPERCASE.md` for root, `Title_Case.md` for docs/

### Code
- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private members: `_leading_underscore`

### Tests
- Test classes: `Test<Feature>`
- Test methods: `test_<scenario>`
- Property tests: `test_property_<number>_<description>`

## Dependencies

### Core Dependencies
- **mitmproxy**: HTTP/HTTPS proxy engine
- **PyQt6**: Desktop GUI framework
- **FastAPI**: REST API framework
- **aiohttp**: Async HTTP client
- **pydantic**: Data validation
- **SQLAlchemy**: Database ORM

### Testing Dependencies
- **pytest**: Test framework
- **pytest-asyncio**: Async test support
- **hypothesis**: Property-based testing
- **pytest-cov**: Coverage reporting

### Development Dependencies
- **black**: Code formatting
- **flake8**: Linting
- **mypy**: Type checking
- **pre-commit**: Git hooks

## Version Control

### Tracked Files
- All source code (`src/`, `tests/`)
- Documentation (`docs/`, `*.md`)
- Configuration files
- Examples and scripts
- Specifications (`.kiro/specs/`)

### Ignored Files (see `.gitignore`)
- Build artifacts
- Test cache and coverage
- Virtual environments
- IDE-specific settings
- Runtime data (logs, databases)
- Temporary files

## Maintenance

### Regular Updates
- Dependencies: Review and update quarterly
- Documentation: Update with feature changes
- Tests: Maintain >90% coverage
- Specifications: Keep synchronized with implementation

### Cleanup Tasks
- Remove unused imports and code
- Archive old documentation
- Prune test data
- Update examples with API changes

---

**Last Updated**: January 5, 2026  
**Version**: 1.0.0  
**Status**: Production Ready
---

**Last Updated**: January 05, 2026
