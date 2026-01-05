# OASIS Launch Methods

## Table of Contents

- [Summary of Changes](#summary-of-changes)
  - [What Changed](#what-changed)
  - [Available Launch Methods](#available-launch-methods)
- [1. Console Scripts (Recommended)](#1-console-scripts-recommended)
- [2. Python Module Execution](#2-python-module-execution)
- [3. Direct Python Import](#3-direct-python-import)
- [Installation Instructions](#installation-instructions)
  - [For Users](#for-users)
  - [For Developers](#for-developers)
- [Entry Point Configuration](#entry-point-configuration)
- [Benefits of This Approach](#benefits-of-this-approach)
- [Migration from oasis.py](#migration-from-oasispy)

## Summary of Changes

We've modernized OASIS entry points following Python best practices for 2026:

### What Changed
- ✅ Removed legacy `oasis.py` script
- ✅ Added `src/oasis/__main__.py` for module execution
- ✅ Fixed console scripts in `pyproject.toml`
- ✅ Added multiple entry points for different modes

### Available Launch Methods

After running `pip install -e .`, users can launch OASIS in multiple ways:

## 1. Console Scripts (Recommended)

These are the cleanest, most professional entry points:

```bash
# Launch GUI application
oasis

# Launch CLI interface
oasis-cli --help
oasis-cli project list
oasis-cli scan start <project-id>

# Launch API server
oasis-api
```

**How it works:** pip creates executable scripts in your PATH that call the appropriate Python functions.

## 2. Python Module Execution

Run OASIS as a Python module (useful for development):

```bash
# Launch GUI
python -m oasis

# Launch CLI
python -m oasis.cli --help

# Launch API
python -m oasis.api
```

**How it works:** Python's `-m` flag runs the `__main__.py` file in the specified package.

## 3. Direct Python Import

For programmatic use or custom scripts:

```python
from oasis.main import main
from oasis.cli.main import main as cli_main
from oasis.api.app import run_server

# Launch GUI
main()

# Launch CLI
cli_main()

# Launch API
run_server(host="0.0.0.0", port=8080)
```

## Installation Instructions

### For Users
```bash
# Install from source
git clone https://github.com/your-org/oasis.git
cd oasis
pip install -e .

# Now you can use: oasis, oasis-cli, oasis-api
```

### For Developers
```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Or with Poetry
poetry install
```

## Entry Point Configuration

The entry points are defined in `pyproject.toml`:

```toml
[tool.poetry.scripts]
oasis = "oasis.main:main"           # GUI application
oasis-cli = "oasis.cli.main:main"   # CLI interface
oasis-api = "oasis.api.app:run_server"  # API server
```

## Benefits of This Approach

1. **Professional**: Industry-standard package structure
2. **Cross-platform**: Works on Windows, Linux, macOS
3. **Flexible**: Multiple ways to launch for different use cases
4. **Clean**: No loose scripts in the root directory
5. **Discoverable**: Users can find commands easily
6. **Maintainable**: Standard Python packaging practices

## Migration from oasis.py

If you previously used `python oasis.py`, simply switch to:
- `oasis` (after installation)
- `python -m oasis` (without installation)

The old `oasis.py` file has been removed as it's no longer needed.
