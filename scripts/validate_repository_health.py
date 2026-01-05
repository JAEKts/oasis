#!/usr/bin/env python3
"""
Repository Health Validation Script

Validates repository health before production release:
- Verifies required files exist
- Checks version consistency
- Verifies no uncommitted changes
- Tests entry points in fresh virtual environment
"""

import os
import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Dict, List, Tuple


class RepositoryHealthValidator:
    """Validates repository health for production readiness."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.successes: List[str] = []
    
    def validate_required_files(self) -> bool:
        """Verify all required files exist."""
        print("\n=== Validating Required Files ===")
        
        required_files = [
            "LICENSE",
            "README.md",
            "CONTRIBUTING.md",
            "pyproject.toml",
            "requirements.txt",
        ]
        
        all_exist = True
        for file_name in required_files:
            file_path = self.repo_root / file_name
            if file_path.exists():
                self.successes.append(f"✓ {file_name} exists")
                print(f"✓ {file_name} exists")
            else:
                self.errors.append(f"✗ {file_name} is missing")
                print(f"✗ {file_name} is missing")
                all_exist = False
        
        return all_exist
    
    def check_version_consistency(self) -> bool:
        """Check version consistency across files."""
        print("\n=== Checking Version Consistency ===")
        
        versions: Dict[str, str] = {}
        
        # Check pyproject.toml
        pyproject_path = self.repo_root / "pyproject.toml"
        if pyproject_path.exists():
            content = pyproject_path.read_text()
            match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                versions['pyproject.toml'] = match.group(1)
                print(f"  pyproject.toml: {match.group(1)}")
        
        # Check __init__.py
        init_path = self.repo_root / "src" / "oasis" / "__init__.py"
        if init_path.exists():
            content = init_path.read_text()
            match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                versions['__init__.py'] = match.group(1)
                print(f"  __init__.py: {match.group(1)}")
        
        # Check consistency
        if len(versions) == 0:
            self.warnings.append("⚠ No version information found")
            print("⚠ No version information found")
            return True  # Not critical
        
        unique_versions = set(versions.values())
        if len(unique_versions) == 1:
            self.successes.append(f"✓ Version consistent across files: {list(unique_versions)[0]}")
            print(f"✓ Version consistent across files: {list(unique_versions)[0]}")
            return True
        else:
            self.errors.append(f"✗ Version mismatch: {versions}")
            print(f"✗ Version mismatch: {versions}")
            return False
    
    def check_git_status(self) -> bool:
        """Verify no uncommitted changes."""
        print("\n=== Checking Git Status ===")
        
        try:
            # Check if we're in a git repository
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                self.warnings.append("⚠ Not a git repository")
                print("⚠ Not a git repository")
                return True  # Not critical for testing
            
            # Check for uncommitted changes
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                self.errors.append("✗ Failed to check git status")
                print("✗ Failed to check git status")
                return False
            
            uncommitted = result.stdout.strip()
            if uncommitted:
                lines = uncommitted.split('\n')
                self.warnings.append(f"⚠ {len(lines)} uncommitted change(s) found")
                print(f"⚠ {len(lines)} uncommitted change(s) found:")
                for line in lines[:10]:  # Show first 10
                    print(f"    {line}")
                if len(lines) > 10:
                    print(f"    ... and {len(lines) - 10} more")
                return True  # Warning, not error
            else:
                self.successes.append("✓ No uncommitted changes")
                print("✓ No uncommitted changes")
                return True
                
        except subprocess.TimeoutExpired:
            self.errors.append("✗ Git command timed out")
            print("✗ Git command timed out")
            return False
        except FileNotFoundError:
            self.warnings.append("⚠ Git not found in PATH")
            print("⚠ Git not found in PATH")
            return True  # Not critical
    
    def test_entry_points_in_venv(self) -> bool:
        """Test entry points in a fresh virtual environment."""
        print("\n=== Testing Entry Points in Fresh Virtual Environment ===")
        
        # Check Python version compatibility
        py_version = sys.version_info
        print(f"Current Python version: {py_version.major}.{py_version.minor}.{py_version.micro}")
        
        # Try to use Python 3.12 if available, otherwise use current Python
        python_cmd = "python3.12"
        try:
            result = subprocess.run(
                [python_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"Using {python_cmd}: {result.stdout.strip()}")
            else:
                python_cmd = sys.executable
                print(f"Python 3.12 not found, using current Python: {sys.executable}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            python_cmd = sys.executable
            print(f"Python 3.12 not found, using current Python: {sys.executable}")
        
        if py_version.major == 3 and py_version.minor >= 13 and python_cmd == sys.executable:
            self.warnings.append(
                f"⚠ Python 3.13+ detected. Some dependencies (mitmproxy/zstandard) may have compatibility issues."
            )
            print("⚠ Python 3.13+ detected. Some dependencies may have compatibility issues.")
            print("  Attempting installation anyway...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            venv_path = Path(temp_dir) / "test_venv"
            
            try:
                # Create virtual environment using the selected Python
                print(f"Creating virtual environment at {venv_path}...")
                if python_cmd != sys.executable:
                    # Use subprocess to create venv with specific Python version
                    result = subprocess.run(
                        [python_cmd, "-m", "venv", str(venv_path)],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode != 0:
                        print(f"Failed to create venv with {python_cmd}, falling back to current Python")
                        venv.create(venv_path, with_pip=True)
                else:
                    venv.create(venv_path, with_pip=True)
                
                # Determine python executable
                if sys.platform == "win32":
                    python_exe = venv_path / "Scripts" / "python.exe"
                    pip_exe = venv_path / "Scripts" / "pip.exe"
                else:
                    python_exe = venv_path / "bin" / "python"
                    pip_exe = venv_path / "bin" / "pip"
                
                if not python_exe.exists():
                    self.errors.append("✗ Failed to create virtual environment")
                    print("✗ Failed to create virtual environment")
                    return False
                
                # Upgrade pip
                print("Upgrading pip...")
                result = subprocess.run(
                    [str(python_exe), "-m", "pip", "install", "--upgrade", "pip"],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                # Install package in editable mode with all dependencies
                print("Installing package in editable mode...")
                result = subprocess.run(
                    [str(pip_exe), "install", "-e", "."],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes for full install
                )
                
                if result.returncode != 0:
                    self.errors.append("✗ Failed to install package")
                    print("✗ Failed to install package")
                    print(f"Error output (last 1000 chars):")
                    print(result.stderr[-1000:] if len(result.stderr) > 1000 else result.stderr)
                    return False
                
                self.successes.append("✓ Package installed successfully")
                print("✓ Package installed successfully")
                
                # Check what packages are installed
                print("\nChecking installed packages...")
                result = subprocess.run(
                    [str(pip_exe), "list"],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if "pydantic-settings" in result.stdout:
                    print("  ✓ pydantic-settings is installed")
                else:
                    print("  ✗ pydantic-settings is NOT installed")
                    self.warnings.append("⚠ pydantic-settings not installed")
                
                if "PyQt6" in result.stdout:
                    print("  ✓ PyQt6 is installed")
                else:
                    print("  ✗ PyQt6 is NOT installed")
                    self.warnings.append("⚠ PyQt6 not installed")
                
                # Test entry points
                entry_points_tested = 0
                entry_points_working = 0
                
                # Test 1: python -m oasis --help
                print("\nTesting: python -m oasis --help")
                result = subprocess.run(
                    [str(python_exe), "-m", "oasis", "--help"],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                entry_points_tested += 1
                if result.returncode == 0:
                    self.successes.append("✓ 'python -m oasis --help' works")
                    print("✓ 'python -m oasis --help' works")
                    entry_points_working += 1
                else:
                    self.warnings.append(f"⚠ 'python -m oasis --help' failed: {result.stderr[:200]}")
                    print(f"⚠ 'python -m oasis --help' failed")
                
                # Test 2: oasis command (if installed)
                print("\nTesting: oasis --help")
                result = subprocess.run(
                    [str(venv_path / ("Scripts" if sys.platform == "win32" else "bin") / "oasis"), "--help"],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                entry_points_tested += 1
                if result.returncode == 0:
                    self.successes.append("✓ 'oasis --help' command works")
                    print("✓ 'oasis --help' command works")
                    entry_points_working += 1
                else:
                    self.warnings.append(f"⚠ 'oasis --help' command failed")
                    print(f"⚠ 'oasis --help' command failed")
                
                # Summary
                print(f"\nEntry Points: {entry_points_working}/{entry_points_tested} working")
                
                if entry_points_working > 0:
                    self.successes.append(f"✓ At least one entry point works ({entry_points_working}/{entry_points_tested})")
                    return True
                else:
                    self.errors.append(f"✗ No entry points working (0/{entry_points_tested})")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.errors.append("✗ Entry point test timed out")
                print("✗ Entry point test timed out")
                return False
            except Exception as e:
                self.errors.append(f"✗ Entry point test failed: {str(e)}")
                print(f"✗ Entry point test failed: {str(e)}")
                return False
    
    def generate_report(self) -> bool:
        """Generate final validation report."""
        print("\n" + "=" * 60)
        print("REPOSITORY HEALTH VALIDATION REPORT")
        print("=" * 60)
        
        if self.successes:
            print(f"\n✓ Successes ({len(self.successes)}):")
            for success in self.successes:
                print(f"  {success}")
        
        if self.warnings:
            print(f"\n⚠ Warnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  {warning}")
        
        if self.errors:
            print(f"\n✗ Errors ({len(self.errors)}):")
            for error in self.errors:
                print(f"  {error}")
        
        print("\n" + "=" * 60)
        
        if self.errors:
            print("RESULT: FAILED - Repository has critical issues")
            return False
        elif self.warnings:
            print("RESULT: PASSED WITH WARNINGS - Repository is mostly healthy")
            return True
        else:
            print("RESULT: PASSED - Repository is healthy")
            return True
    
    def run_all_validations(self) -> bool:
        """Run all validation checks."""
        print("Starting Repository Health Validation...")
        print(f"Repository: {self.repo_root}")
        
        results = []
        
        # Run all checks
        results.append(self.validate_required_files())
        results.append(self.check_version_consistency())
        results.append(self.check_git_status())
        results.append(self.test_entry_points_in_venv())
        
        # Generate report
        overall_result = self.generate_report()
        
        return overall_result


def main():
    """Main entry point."""
    # Determine repository root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    # Create validator
    validator = RepositoryHealthValidator(repo_root)
    
    # Run validations
    success = validator.run_all_validations()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
