# Contributing to OASIS

Thank you for your interest in contributing to OASIS! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
  - [1. Create a Branch](#1-create-a-branch)
  - [2. Make Changes](#2-make-changes)
  - [3. Test Your Changes](#3-test-your-changes)
  - [4. Commit Your Changes](#4-commit-your-changes)
  - [5. Push and Create Pull Request](#5-push-and-create-pull-request)
- [Code Style Guidelines](#code-style-guidelines)
  - [Python Style](#python-style)
  - [Async Code](#async-code)
  - [Testing](#testing)
    - [Unit Tests](#unit-tests)
    - [Property-Based Tests](#property-based-tests)
- [Documentation](#documentation)
  - [Code Documentation](#code-documentation)
  - [README Updates](#readme-updates)
  - [API Documentation](#api-documentation)
- [Pull Request Guidelines](#pull-request-guidelines)
  - [Before Submitting](#before-submitting)
  - [PR Description Template](#pr-description-template)
- [Description](#description)
- [Type of Change](#type-of-change)
- [Testing](#testing)
- [Checklist](#checklist)
- [Related Issues](#related-issues)
  - [Review Process](#review-process)
- [Feature Development](#feature-development)
  - [Adding a New Module](#adding-a-new-module)
  - [Adding a Vulnerability Detector](#adding-a-vulnerability-detector)
- [Bug Reports](#bug-reports)
  - [Before Reporting](#before-reporting)
  - [Bug Report Template](#bug-report-template)
- [Description](#description)
- [Steps to Reproduce](#steps-to-reproduce)
- [Expected Behavior](#expected-behavior)
- [Actual Behavior](#actual-behavior)
- [Environment](#environment)
- [Additional Context](#additional-context)
- [Feature Requests](#feature-requests)
  - [Feature Request Template](#feature-request-template)
- [Feature Description](#feature-description)
- [Use Case](#use-case)
- [Proposed Solution](#proposed-solution)
- [Alternatives Considered](#alternatives-considered)
- [Additional Context](#additional-context)
- [Community](#community)
  - [Communication Channels](#communication-channels)
  - [Getting Help](#getting-help)
- [Recognition](#recognition)
- [License](#license)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- Basic understanding of penetration testing concepts
- Familiarity with async Python programming

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/oasis.git
   cd oasis
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

5. **Run Tests**
   ```bash
   pytest tests/
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or fixes

### 2. Make Changes

- Write clean, readable code
- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/core/
pytest tests/integration/

# Run with coverage
pytest --cov=src/oasis --cov-report=html

# Run linters
make lint

# Format code
make format
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "feat: add new feature description"
```

Commit message format:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots (if UI changes)
- Test results

## Code Style Guidelines

### Python Style

We follow PEP 8 with some modifications:

```python
# Good
def calculate_entropy(tokens: List[str]) -> float:
    """
    Calculate Shannon entropy of token set.
    
    Args:
        tokens: List of token strings
        
    Returns:
        Entropy value in bits
    """
    if not tokens:
        return 0.0
    
    # Implementation
    return entropy_value


# Bad
def calc_ent(t):
    if not t: return 0.0
    return entropy_value
```

**Key Points:**
- Use type hints for all function parameters and returns
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines when possible
- Use meaningful variable names
- Add comments for complex logic

### Async Code

```python
# Good
async def scan_target(target: str) -> List[Finding]:
    """Scan target for vulnerabilities."""
    async with aiohttp.ClientSession() as session:
        findings = await perform_scan(session, target)
        return findings


# Bad
def scan_target(target):
    # Blocking I/O
    response = requests.get(target)
    return parse_response(response)
```

**Key Points:**
- Use `async`/`await` for I/O operations
- Properly manage async context managers
- Avoid blocking calls in async functions
- Use `asyncio.gather()` for concurrent operations

### Testing

#### Unit Tests

```python
def test_token_entropy_calculation():
    """Test entropy calculation for token set."""
    tokens = ["abc123", "def456", "ghi789"]
    entropy = calculate_entropy(tokens)
    
    assert entropy > 0
    assert entropy < 10  # Reasonable upper bound
```

#### Property-Based Tests

```python
from hypothesis import given, strategies as st

@given(st.lists(st.text(min_size=1), min_size=1))
def test_property_entropy_non_negative(tokens):
    """Property: Entropy is always non-negative."""
    entropy = calculate_entropy(tokens)
    assert entropy >= 0
```

**Testing Requirements:**
- Write tests for all new functionality
- Maintain >80% code coverage
- Include both unit tests and property tests
- Test edge cases and error conditions
- Use descriptive test names

## Documentation

### Code Documentation

```python
class VulnerabilityScanner:
    """
    Automated vulnerability scanner for web applications.
    
    Performs both passive and active scanning to detect security
    vulnerabilities including OWASP Top 10.
    
    Attributes:
        policy: Scan policy configuration
        detectors: List of vulnerability detectors
        
    Example:
        >>> scanner = VulnerabilityScanner(policy=ScanPolicy())
        >>> findings = await scanner.scan("https://example.com")
    """
    
    async def scan(self, target: str) -> List[Finding]:
        """
        Scan target URL for vulnerabilities.
        
        Args:
            target: Target URL to scan
            
        Returns:
            List of detected vulnerabilities
            
        Raises:
            ScanError: If scan fails
        """
        pass
```

### README Updates

When adding new features:
1. Update main README.md with feature description
2. Add usage examples
3. Update feature comparison table
4. Add to roadmap if applicable

### API Documentation

Update OpenAPI specification in `docs/api/openapi.yaml` for API changes.

## Pull Request Guidelines

### Before Submitting

- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] Branch is up to date with main

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Property tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally

## Related Issues
Fixes #123
```

### Review Process

1. Automated checks run (tests, linting)
2. Code review by maintainers
3. Address feedback
4. Approval and merge

## Feature Development

### Adding a New Module

1. **Create Module Structure**
   ```
   src/oasis/newmodule/
   ├── __init__.py
   ├── engine.py
   ├── models.py
   └── README.md
   ```

2. **Add Tests**
   ```
   tests/newmodule/
   ├── __init__.py
   ├── test_engine.py
   └── test_newmodule_properties.py
   ```

3. **Add Documentation**
   - Module README
   - Usage examples
   - API documentation

4. **Update Integration**
   - Add to main application
   - Update CLI commands
   - Add API endpoints

### Adding a Vulnerability Detector

1. **Create Detector Class**
   ```python
   # src/oasis/scanner/detectors/new_vuln.py
   from src.oasis.scanner.detector import VulnerabilityDetector
   
   class NewVulnDetector(VulnerabilityDetector):
       """Detector for new vulnerability type."""
       
       async def detect(self, context: ScanContext) -> List[Finding]:
           """Detect new vulnerability."""
           pass
   ```

2. **Register Detector**
   ```python
   # src/oasis/scanner/detectors/__init__.py
   from .new_vuln import NewVulnDetector
   ```

3. **Add Tests**
   ```python
   # tests/scanner/test_new_vuln.py
   def test_new_vuln_detection():
       """Test new vulnerability detection."""
       pass
   ```

## Bug Reports

### Before Reporting

1. Check existing issues
2. Verify it's reproducible
3. Test on latest version
4. Gather relevant information

### Bug Report Template

```markdown
## Description
Clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.5]
- OASIS Version: [e.g., 1.0.0]

## Additional Context
Logs, screenshots, etc.
```

## Feature Requests

### Feature Request Template

```markdown
## Feature Description
Clear description of the feature

## Use Case
Why is this feature needed?

## Proposed Solution
How should it work?

## Alternatives Considered
Other approaches considered

## Additional Context
Any other relevant information
```

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Pull Requests**: Code contributions

### Getting Help

- Check documentation first
- Search existing issues
- Ask in GitHub Discussions
- Be specific and provide context

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes
- Project documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to OASIS! 🎉
---

**Last Updated**: January 05, 2026
