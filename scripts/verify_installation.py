#!/usr/bin/env python3
"""
Verify OASIS Installation

Checks that all entry points are properly configured and accessible.
"""

import sys
import subprocess
from pathlib import Path


def check_import(module_path: str, description: str) -> bool:
    """Check if a module can be imported."""
    try:
        parts = module_path.split(":")
        if len(parts) == 2:
            module, func = parts
            exec(f"from {module} import {func}")
        else:
            exec(f"import {module_path}")
        print(f"✓ {description}")
        return True
    except Exception as e:
        print(f"✗ {description}: {e}")
        return False


def check_command(command: str) -> bool:
    """Check if a command is available."""
    try:
        result = subprocess.run(
            ["which", command],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✓ Command '{command}' found at: {result.stdout.strip()}")
            return True
        else:
            print(f"✗ Command '{command}' not found in PATH")
            return False
    except Exception as e:
        print(f"✗ Error checking command '{command}': {e}")
        return False


def main():
    """Run verification checks."""
    print("=" * 60)
    print("OASIS Installation Verification")
    print("=" * 60)
    print()
    
    # Check Python version
    print("Python Version:")
    version = sys.version_info
    if version >= (3, 11):
        print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (requires 3.11+)")
        return False
    print()
    
    # Check imports
    print("Module Imports:")
    checks = [
        ("oasis.main:main", "GUI entry point"),
        ("oasis.cli.main:main", "CLI entry point"),
        ("oasis.api.app:run_server", "API entry point"),
        ("oasis.__main__", "Module execution support"),
    ]
    
    import_results = []
    for module, desc in checks:
        import_results.append(check_import(module, desc))
    print()
    
    # Check console scripts
    print("Console Scripts:")
    commands = ["oasis", "oasis-cli", "oasis-api"]
    command_results = []
    for cmd in commands:
        command_results.append(check_command(cmd))
    print()
    
    # Summary
    print("=" * 60)
    print("Summary:")
    print("=" * 60)
    
    total_checks = len(import_results) + len(command_results)
    passed_checks = sum(import_results) + sum(command_results)
    
    print(f"Passed: {passed_checks}/{total_checks} checks")
    print()
    
    if passed_checks == total_checks:
        print("✓ Installation verified successfully!")
        print()
        print("You can now use:")
        print("  - oasis          (launch GUI)")
        print("  - oasis-cli      (use CLI)")
        print("  - oasis-api      (start API server)")
        print("  - python -m oasis (alternative launch)")
        return True
    else:
        print("✗ Installation incomplete")
        print()
        print("To fix, run:")
        print("  pip install -e .")
        print()
        print("If issues persist, check:")
        print("  - Virtual environment is activated")
        print("  - Dependencies are installed")
        print("  - Python version is 3.11+")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
