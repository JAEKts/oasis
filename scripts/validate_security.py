#!/usr/bin/env python3
"""
Security validation script for OASIS repository.
Scans for sensitive information, validates example files, and checks .env.example.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict

# Patterns for sensitive information
SENSITIVE_PATTERNS = {
    'api_key': [
        r'api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
        r'apikey\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
    ],
    'password': [
        r'password\s*[=:]\s*["\'](?!.*(?:your|example|placeholder|changeme|password|secret|xxx|test|demo))[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]{8,}["\']',
    ],
    'token': [
        r'token\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
        r'bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    ],
    'secret': [
        r'secret\s*[=:]\s*["\'](?!.*(?:your|example|placeholder|changeme|password|secret|xxx|test|demo))[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]{8,}["\']',
    ],
    'aws_key': [
        r'AKIA[0-9A-Z]{16}',
    ],
    'private_key': [
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    ],
}

# Placeholder patterns that are acceptable
PLACEHOLDER_PATTERNS = [
    r'your[_-]?api[_-]?key',
    r'your[_-]?password',
    r'your[_-]?token',
    r'your[_-]?secret',
    r'example',
    r'placeholder',
    r'changeme',
    r'xxx+',
    r'test[_-]?key',
    r'demo[_-]?key',
    r'\*+',
    r'<[^>]+>',  # <your-key-here>
    r'\{[^}]+\}',  # {your-key-here}
    r'\$\{[^}]+\}',  # ${YOUR_KEY}
]

# Files to exclude from scanning
EXCLUDE_PATTERNS = [
    r'\.git/',
    r'\.hypothesis/',
    r'__pycache__/',
    r'\.pytest_cache/',
    r'venv/',
    r'\.venv/',
    r'node_modules/',
    r'\.egg-info/',
    r'dist/',
    r'build/',
    r'\.pyc$',
    r'\.pyo$',
    r'\.so$',
    r'\.dylib$',
]

# Example files that should only have placeholders
EXAMPLE_FILE_PATTERNS = [
    r'example',
    r'demo',
    r'sample',
    r'template',
]


def should_exclude(file_path: Path) -> bool:
    """Check if file should be excluded from scanning."""
    path_str = str(file_path)
    return any(re.search(pattern, path_str) for pattern in EXCLUDE_PATTERNS)


def is_example_file(file_path: Path) -> bool:
    """Check if file is an example/demo file."""
    name = file_path.name.lower()
    return any(pattern in name for pattern in EXAMPLE_FILE_PATTERNS)


def is_placeholder(value: str) -> bool:
    """Check if a value is a placeholder."""
    value_lower = value.lower()
    return any(re.search(pattern, value_lower, re.IGNORECASE) for pattern in PLACEHOLDER_PATTERNS)


def scan_file_for_sensitive_info(file_path: Path) -> List[Tuple[int, str, str]]:
    """
    Scan a file for sensitive information.
    Returns list of (line_number, pattern_type, matched_text).
    """
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # Skip comments in Python files
                if file_path.suffix == '.py' and line.strip().startswith('#'):
                    continue
                
                # Check for test/example markers in the line or nearby lines
                context_lines = []
                for i in range(max(0, line_num - 3), min(len(lines), line_num + 2)):
                    context_lines.append(lines[i].lower())
                context = ' '.join(context_lines)
                
                # Skip if context indicates test/example data
                test_markers = ['test', 'example', 'demo', 'sample', 'placeholder', 'truncated', 'not a real']
                if any(marker in context for marker in test_markers):
                    continue
                
                for pattern_type, patterns in SENSITIVE_PATTERNS.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            matched_text = match.group(0)
                            # Check if it's a placeholder
                            if not is_placeholder(matched_text):
                                # Additional check: if it's truncated (ends with ...)
                                if '...' in matched_text or matched_text.endswith('...'):
                                    continue
                                findings.append((line_num, pattern_type, matched_text))
    
    except Exception as e:
        print(f"Warning: Could not scan {file_path}: {e}", file=sys.stderr)
    
    return findings


def validate_env_example(file_path: Path) -> List[str]:
    """Validate .env.example file has only placeholders."""
    issues = []
    
    if not file_path.exists():
        return [f"{file_path} does not exist"]
    
    # Safe default patterns that are acceptable
    safe_defaults = [
        r'^development$',
        r'^staging$',
        r'^production$',
        r'^true$',
        r'^false$',
        r'^INFO$',
        r'^DEBUG$',
        r'^WARNING$',
        r'^ERROR$',
        r'^\./.*',  # Relative paths
        r'^127\.0\.0\.1$',
        r'^localhost$',
        r'^sqlite:///',
        r'^\d+$',  # Numbers
    ]
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                original_line = line
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip().strip('"').strip("'")
                    
                    # Remove inline comments
                    if '#' in value:
                        value = value.split('#')[0].strip()
                    
                    # Skip empty values
                    if not value:
                        continue
                    
                    # Check if value is a safe default
                    is_safe = any(re.match(pattern, value, re.IGNORECASE) for pattern in safe_defaults)
                    if is_safe:
                        continue
                    
                    # Check if value is a placeholder
                    if not is_placeholder(value):
                        # Check if it looks like a real value (long and not starting with $)
                        if len(value) > 20 and not value.startswith('$') and not value.startswith('./'):
                            issues.append(
                                f"Line {line_num}: {key} may contain a real value instead of placeholder: {value[:30]}..."
                            )
    
    except Exception as e:
        issues.append(f"Error reading {file_path}: {e}")
    
    return issues


def validate_example_files(root_path: Path) -> Dict[Path, List[str]]:
    """Validate that example files use placeholders."""
    issues = {}
    
    for file_path in root_path.rglob('*'):
        if not file_path.is_file():
            continue
        
        if should_exclude(file_path):
            continue
        
        if is_example_file(file_path) and file_path.suffix in ['.py', '.yaml', '.yml', '.json', '.env', '.conf', '.cfg']:
            findings = scan_file_for_sensitive_info(file_path)
            if findings:
                issues[file_path] = [
                    f"Line {line_num}: {pattern_type} - {text[:50]}"
                    for line_num, pattern_type, text in findings
                ]
    
    return issues


def scan_repository(root_path: Path) -> Dict[str, any]:
    """Scan entire repository for security issues."""
    results = {
        'sensitive_info': {},
        'env_example_issues': [],
        'example_file_issues': {},
    }
    
    # Scan all files for sensitive information
    print("Scanning repository for sensitive information...")
    for file_path in root_path.rglob('*'):
        if not file_path.is_file():
            continue
        
        if should_exclude(file_path):
            continue
        
        # Only scan text files
        if file_path.suffix in ['.py', '.md', '.txt', '.yaml', '.yml', '.json', '.env', '.sh', '.conf', '.cfg', '.toml']:
            findings = scan_file_for_sensitive_info(file_path)
            if findings:
                results['sensitive_info'][file_path] = findings
    
    # Validate .env.example
    print("Validating .env.example...")
    env_example = root_path / '.env.example'
    results['env_example_issues'] = validate_env_example(env_example)
    
    # Validate example files
    print("Validating example files...")
    results['example_file_issues'] = validate_example_files(root_path)
    
    return results


def print_results(results: Dict[str, any]) -> int:
    """Print scan results and return exit code."""
    exit_code = 0
    
    # Print sensitive information findings
    if results['sensitive_info']:
        print("\n❌ SENSITIVE INFORMATION FOUND:")
        print("=" * 80)
        for file_path, findings in results['sensitive_info'].items():
            print(f"\n{file_path}:")
            for line_num, pattern_type, text in findings:
                print(f"  Line {line_num}: {pattern_type} - {text[:60]}")
        exit_code = 1
    else:
        print("\n✅ No sensitive information found in tracked files")
    
    # Print .env.example issues
    if results['env_example_issues']:
        print("\n❌ .ENV.EXAMPLE ISSUES:")
        print("=" * 80)
        for issue in results['env_example_issues']:
            print(f"  {issue}")
        exit_code = 1
    else:
        print("✅ .env.example uses only placeholders")
    
    # Print example file issues
    if results['example_file_issues']:
        print("\n❌ EXAMPLE FILE ISSUES:")
        print("=" * 80)
        for file_path, issues in results['example_file_issues'].items():
            print(f"\n{file_path}:")
            for issue in issues:
                print(f"  {issue}")
        exit_code = 1
    else:
        print("✅ All example files use placeholders")
    
    return exit_code


def main():
    """Main entry point."""
    root_path = Path(__file__).parent.parent
    
    print("OASIS Repository Security Validation")
    print("=" * 80)
    print(f"Scanning: {root_path}")
    print()
    
    results = scan_repository(root_path)
    exit_code = print_results(results)
    
    print("\n" + "=" * 80)
    if exit_code == 0:
        print("✅ Security validation PASSED")
    else:
        print("❌ Security validation FAILED")
        print("\nPlease review and fix the issues above before proceeding.")
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
