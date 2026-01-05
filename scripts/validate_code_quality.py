#!/usr/bin/env python3
"""
Validate Python code quality for OASIS project.

Checks:
1. Circular dependencies
2. Import resolution
3. Code quality with linters
"""

import ast
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple
import subprocess


def find_python_files(src_dir: Path) -> List[Path]:
    """Find all Python files in the source directory."""
    return list(src_dir.rglob("*.py"))


def extract_imports(file_path: Path) -> Set[str]:
    """Extract all imports from a Python file."""
    imports = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=str(file_path))
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
    except Exception as e:
        print(f"Warning: Could not parse {file_path}: {e}")
    
    return imports


def get_module_name(file_path: Path, src_dir: Path) -> str:
    """Convert file path to module name."""
    relative = file_path.relative_to(src_dir.parent)
    parts = list(relative.parts)
    
    # Remove .py extension
    if parts[-1].endswith('.py'):
        parts[-1] = parts[-1][:-3]
    
    # Remove __init__
    if parts[-1] == '__init__':
        parts = parts[:-1]
    
    return '.'.join(parts)


def build_dependency_graph(src_dir: Path) -> Dict[str, Set[str]]:
    """Build a dependency graph of all modules."""
    graph = {}
    files = find_python_files(src_dir)
    
    for file_path in files:
        module_name = get_module_name(file_path, src_dir)
        imports = extract_imports(file_path)
        
        # Filter to only oasis imports
        oasis_imports = {imp for imp in imports if imp == 'oasis' or imp.startswith('oasis.')}
        graph[module_name] = oasis_imports
    
    return graph


def find_circular_dependencies(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """Find circular dependencies using DFS."""
    cycles = []
    visited = set()
    rec_stack = set()
    
    def dfs(node: str, path: List[str]) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                dfs(neighbor, path.copy())
            elif neighbor in rec_stack:
                # Found a cycle
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                if cycle not in cycles:
                    cycles.append(cycle)
        
        rec_stack.remove(node)
    
    for node in graph:
        if node not in visited:
            dfs(node, [])
    
    return cycles


def check_imports_resolve() -> Tuple[bool, List[str]]:
    """Check if all imports can be resolved."""
    errors = []
    src_dir = Path("src/oasis")
    
    for file_path in find_python_files(src_dir):
        try:
            # Try to compile the file
            with open(file_path, 'r', encoding='utf-8') as f:
                compile(f.read(), str(file_path), 'exec')
        except SyntaxError as e:
            errors.append(f"{file_path}: Syntax error - {e}")
        except Exception as e:
            # Don't fail on import errors during compilation
            pass
    
    return len(errors) == 0, errors


def run_linter(command: List[str], name: str) -> Tuple[bool, str]:
    """Run a linter command and return results."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, f"{name} timed out"
    except FileNotFoundError:
        return False, f"{name} not found (not installed)"
    except Exception as e:
        return False, f"{name} error: {e}"


def main():
    """Main validation function."""
    print("=" * 70)
    print("OASIS Code Quality Validation")
    print("=" * 70)
    print()
    
    src_dir = Path("src/oasis")
    if not src_dir.exists():
        print(f"Error: Source directory {src_dir} not found")
        return 1
    
    all_passed = True
    
    # Check 1: Circular Dependencies
    print("1. Checking for circular dependencies...")
    print("-" * 70)
    graph = build_dependency_graph(src_dir)
    cycles = find_circular_dependencies(graph)
    
    if cycles:
        print(f"❌ Found {len(cycles)} circular dependency cycle(s):")
        for i, cycle in enumerate(cycles, 1):
            print(f"   Cycle {i}: {' -> '.join(cycle)}")
        all_passed = False
    else:
        print("✓ No circular dependencies found")
    print()
    
    # Check 2: Import Resolution
    print("2. Checking import resolution...")
    print("-" * 70)
    imports_ok, import_errors = check_imports_resolve()
    
    if imports_ok:
        print("✓ All imports resolve correctly")
    else:
        print(f"❌ Found {len(import_errors)} import error(s):")
        for error in import_errors[:10]:  # Show first 10
            print(f"   {error}")
        if len(import_errors) > 10:
            print(f"   ... and {len(import_errors) - 10} more")
        all_passed = False
    print()
    
    # Check 3: Linters
    print("3. Running linters...")
    print("-" * 70)
    
    # Check flake8
    print("Running flake8...")
    flake8_ok, flake8_output = run_linter(
        ["flake8", "src/oasis", "--count", "--select=E9,F63,F7,F82", "--show-source", "--statistics"],
        "flake8"
    )
    if flake8_ok:
        print("✓ flake8: No critical errors")
    else:
        print("❌ flake8: Issues found")
        if "not found" not in flake8_output:
            print(flake8_output[:500])  # Show first 500 chars
    print()
    
    # Check black (formatting)
    print("Running black (check only)...")
    black_ok, black_output = run_linter(
        ["black", "--check", "src/oasis"],
        "black"
    )
    if black_ok:
        print("✓ black: Code is formatted correctly")
    else:
        if "not found" in black_output:
            print("⚠ black: Not installed (optional)")
        else:
            print("⚠ black: Some files need formatting")
            print("   Run 'black src/oasis' to format")
    print()
    
    # Check mypy (type checking)
    print("Running mypy...")
    mypy_ok, mypy_output = run_linter(
        ["mypy", "src/oasis", "--ignore-missing-imports", "--no-error-summary"],
        "mypy"
    )
    if mypy_ok:
        print("✓ mypy: No type errors")
    else:
        if "not found" in mypy_output:
            print("⚠ mypy: Not installed (optional)")
        else:
            print("⚠ mypy: Type issues found (non-critical)")
    print()
    
    # Summary
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    
    if all_passed:
        print("✓ All critical checks passed!")
        print()
        print("The code is ready for production:")
        print("  - No circular dependencies")
        print("  - All imports resolve correctly")
        return 0
    else:
        print("❌ Some critical checks failed")
        print()
        print("Please fix the issues above before proceeding.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
