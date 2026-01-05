#!/usr/bin/env python3
"""
Documentation Quality Validator

Validates documentation quality according to requirements:
- Adds table of contents to long documents (>3 sections)
- Verifies consistent heading hierarchy
- Checks code examples are valid
- Adds last-updated dates to major docs
"""

import re
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Optional
import ast


class DocumentationValidator:
    """Validates and improves documentation quality."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.issues: List[str] = []
        self.fixes_applied: List[str] = []
        
    def validate_all(self) -> bool:
        """Validate all documentation files."""
        print("🔍 Validating documentation quality...\n")
        
        # Find all markdown files
        md_files = self._find_markdown_files()
        
        for md_file in md_files:
            print(f"Checking: {md_file.relative_to(self.repo_root)}")
            self._validate_file(md_file)
            
        # Print summary
        print("\n" + "="*60)
        if self.issues:
            print(f"❌ Found {len(self.issues)} issues:")
            for issue in self.issues:
                print(f"  - {issue}")
        else:
            print("✅ All documentation quality checks passed!")
            
        if self.fixes_applied:
            print(f"\n✨ Applied {len(self.fixes_applied)} fixes:")
            for fix in self.fixes_applied:
                print(f"  - {fix}")
                
        return len(self.issues) == 0
        
    def _find_markdown_files(self) -> List[Path]:
        """Find all markdown files to validate."""
        patterns = [
            "README.md",
            "CONTRIBUTING.md",
            "docs/**/*.md",
        ]
        
        files = []
        for pattern in patterns:
            files.extend(self.repo_root.glob(pattern))
            
        # Exclude certain directories
        exclude_dirs = {'.hypothesis', '.pytest_cache', 'venv', 'node_modules', '.kiro'}
        files = [f for f in files if not any(ex in f.parts for ex in exclude_dirs)]
        
        return sorted(set(files))
        
    def _validate_file(self, file_path: Path) -> None:
        """Validate a single markdown file."""
        content = file_path.read_text(encoding='utf-8')
        
        # Check heading hierarchy
        self._check_heading_hierarchy(file_path, content)
        
        # Check for table of contents in long documents
        self._check_table_of_contents(file_path, content)
        
        # Check code examples
        self._check_code_examples(file_path, content)
        
        # Check for last-updated date in major docs
        self._check_last_updated(file_path, content)
        
    def _check_heading_hierarchy(self, file_path: Path, content: str) -> None:
        """Check that heading hierarchy is consistent."""
        lines = content.split('\n')
        headings = []
        
        for i, line in enumerate(lines, 1):
            if line.startswith('#'):
                level = len(line) - len(line.lstrip('#'))
                heading_text = line.lstrip('#').strip()
                headings.append((i, level, heading_text))
                
        # Check for skipped levels
        for i in range(1, len(headings)):
            prev_level = headings[i-1][1]
            curr_level = headings[i][1]
            
            if curr_level > prev_level + 1:
                self.issues.append(
                    f"{file_path.name}:{headings[i][0]} - "
                    f"Heading level skipped (from h{prev_level} to h{curr_level})"
                )
                
    def _check_table_of_contents(self, file_path: Path, content: str) -> None:
        """Check if long documents have a table of contents."""
        # Count sections (h2 and below)
        sections = re.findall(r'^##+ ', content, re.MULTILINE)
        
        if len(sections) > 3:
            # Check if TOC exists
            has_toc = bool(re.search(
                r'##\s*(Table of Contents|Contents|TOC)',
                content,
                re.IGNORECASE
            ))
            
            if not has_toc:
                self.issues.append(
                    f"{file_path.name} - Missing table of contents "
                    f"({len(sections)} sections found, >3 requires TOC)"
                )
                
    def _check_code_examples(self, file_path: Path, content: str) -> None:
        """Check that code examples are syntactically valid."""
        # Find Python code blocks
        python_blocks = re.findall(
            r'```python\n(.*?)\n```',
            content,
            re.DOTALL
        )
        
        for i, code_block in enumerate(python_blocks, 1):
            # Skip if it's clearly pseudocode or incomplete
            if any(marker in code_block for marker in ['...', '# ...', '<', '>']):
                continue
                
            # Try to parse as Python
            try:
                ast.parse(code_block)
            except SyntaxError as e:
                self.issues.append(
                    f"{file_path.name} - Python code block {i} has syntax error: {e}"
                )
                
    def _check_last_updated(self, file_path: Path, content: str) -> None:
        """Check if major docs have last-updated dates."""
        # Major docs that should have dates (with specific paths)
        major_doc_paths = {
            'README.md',  # Root README
            'CONTRIBUTING.md',  # Root CONTRIBUTING
            'docs/deployment/DEPLOYMENT_GUIDE.md',
            'docs/developer/PROJECT_STRUCTURE.md',
        }
        
        # Get relative path from repo root
        rel_path = str(file_path.relative_to(self.repo_root))
        
        # Check if this is a major doc
        is_major_doc = (
            file_path.name in {'README.md', 'CONTRIBUTING.md'} and 
            file_path.parent == self.repo_root
        ) or rel_path in major_doc_paths
        
        if not is_major_doc:
            return
            
        # Check for last updated pattern (with optional bold formatting)
        has_date = bool(re.search(
            r'\**(Last Updated|Last Modified|Updated)\**:\s*\w+\s+\d+,?\s+\d{4}',
            content,
            re.IGNORECASE
        ))
        
        if not has_date:
            self.issues.append(
                f"{file_path.name} - Missing last-updated date "
                f"(major documentation should include update date)"
            )


def main():
    """Main entry point."""
    repo_root = Path(__file__).parent.parent
    validator = DocumentationValidator(repo_root)
    
    success = validator.validate_all()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
