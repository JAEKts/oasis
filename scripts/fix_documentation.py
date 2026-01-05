#!/usr/bin/env python3
"""
Documentation Quality Fixer

Automatically fixes documentation quality issues:
- Adds table of contents to long documents (>3 sections)
- Adds last-updated dates to major docs
- Reports heading hierarchy issues (manual fix required)
"""

import re
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict


class DocumentationFixer:
    """Fixes documentation quality issues."""
    
    def __init__(self, repo_root: Path, dry_run: bool = False):
        self.repo_root = repo_root
        self.dry_run = dry_run
        self.fixes_applied: List[str] = []
        self.manual_fixes_needed: List[str] = []
        
    def fix_all(self) -> None:
        """Fix all documentation files."""
        print("🔧 Fixing documentation quality issues...\n")
        
        # Find all markdown files
        md_files = self._find_markdown_files()
        
        for md_file in md_files:
            print(f"Processing: {md_file.relative_to(self.repo_root)}")
            self._fix_file(md_file)
            
        # Print summary
        print("\n" + "="*60)
        if self.fixes_applied:
            print(f"✅ Applied {len(self.fixes_applied)} fixes:")
            for fix in self.fixes_applied:
                print(f"  - {fix}")
        else:
            print("ℹ️  No automatic fixes needed")
            
        if self.manual_fixes_needed:
            print(f"\n⚠️  {len(self.manual_fixes_needed)} issues require manual fixing:")
            for issue in self.manual_fixes_needed:
                print(f"  - {issue}")
                
        if self.dry_run:
            print("\n🔍 DRY RUN - No files were modified")
        
    def _find_markdown_files(self) -> List[Path]:
        """Find all markdown files to fix."""
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
        
    def _fix_file(self, file_path: Path) -> None:
        """Fix a single markdown file."""
        content = file_path.read_text(encoding='utf-8')
        original_content = content
        
        # Add table of contents if needed
        content = self._add_table_of_contents(file_path, content)
        
        # Add last-updated date if needed
        content = self._add_last_updated(file_path, content)
        
        # Check heading hierarchy (report only, no auto-fix)
        self._check_heading_hierarchy(file_path, content)
        
        # Write back if changed
        if content != original_content:
            if not self.dry_run:
                file_path.write_text(content, encoding='utf-8')
                
    def _add_table_of_contents(self, file_path: Path, content: str) -> str:
        """Add table of contents to long documents."""
        # Count sections (h2 and below)
        lines = content.split('\n')
        sections = []
        
        for i, line in enumerate(lines):
            if re.match(r'^##+ ', line):
                level = len(line) - len(line.lstrip('#'))
                heading_text = line.lstrip('#').strip()
                # Remove markdown links from heading text
                heading_text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', heading_text)
                sections.append((level, heading_text, i))
                
        if len(sections) <= 3:
            return content
            
        # Check if TOC already exists
        has_toc = bool(re.search(
            r'##\s*(Table of Contents|Contents|TOC)',
            content,
            re.IGNORECASE
        ))
        
        if has_toc:
            return content
            
        # Generate TOC
        toc_lines = ["## Table of Contents\n"]
        for level, heading, _ in sections:
            if level == 1:  # Skip h1
                continue
            indent = "  " * (level - 2)
            # Create anchor link
            anchor = heading.lower()
            anchor = re.sub(r'[^\w\s-]', '', anchor)
            anchor = re.sub(r'[\s]+', '-', anchor)
            toc_lines.append(f"{indent}- [{heading}](#{anchor})")
            
        toc_lines.append("")  # Empty line after TOC
        
        # Find where to insert TOC (after first heading and any intro text)
        insert_pos = 0
        for i, line in enumerate(lines):
            if line.startswith('# '):
                # Found title, look for next section or empty line
                for j in range(i + 1, len(lines)):
                    if lines[j].startswith('##') or (j > i + 3 and not lines[j].strip()):
                        insert_pos = j
                        break
                break
                
        if insert_pos > 0:
            lines.insert(insert_pos, '\n'.join(toc_lines))
            self.fixes_applied.append(
                f"{file_path.name} - Added table of contents ({len(sections)} sections)"
            )
            return '\n'.join(lines)
            
        return content
        
    def _add_last_updated(self, file_path: Path, content: str) -> str:
        """Add last-updated date to major docs."""
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
            return content
            
        # Check if already has date
        has_date = bool(re.search(
            r'(Last Updated|Last Modified|Updated):\s*\w+\s+\d+,?\s+\d{4}',
            content,
            re.IGNORECASE
        ))
        
        if has_date:
            return content
            
        # Add date at the end
        current_date = datetime.now().strftime("%B %d, %Y")
        footer = f"\n---\n\n**Last Updated**: {current_date}\n"
        
        # Check if there's already a footer separator
        if content.rstrip().endswith('---'):
            # Add after existing separator
            content = content.rstrip() + f"\n\n**Last Updated**: {current_date}\n"
        else:
            content = content.rstrip() + footer
            
        self.fixes_applied.append(
            f"{file_path.name} - Added last-updated date"
        )
        
        return content
        
    def _check_heading_hierarchy(self, file_path: Path, content: str) -> None:
        """Check heading hierarchy and report issues."""
        lines = content.split('\n')
        headings = []
        
        for i, line in enumerate(lines, 1):
            if line.startswith('#'):
                level = len(line) - len(line.lstrip('#'))
                heading_text = line.lstrip('#').strip()
                headings.append((i, level, heading_text))
                
        # Check for skipped levels
        issues = []
        for i in range(1, len(headings)):
            prev_level = headings[i-1][1]
            curr_level = headings[i][1]
            
            if curr_level > prev_level + 1:
                issues.append(
                    f"Line {headings[i][0]}: Heading level skipped "
                    f"(from h{prev_level} to h{curr_level})"
                )
                
        if issues:
            self.manual_fixes_needed.append(
                f"{file_path.name} - Heading hierarchy issues:\n    " + 
                "\n    ".join(issues)
            )


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix documentation quality issues')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be fixed without making changes')
    args = parser.parse_args()
    
    repo_root = Path(__file__).parent.parent
    fixer = DocumentationFixer(repo_root, dry_run=args.dry_run)
    fixer.fix_all()


if __name__ == '__main__':
    main()
