# Contributing to CVElk

Thank you for your interest in contributing to CVElk! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check the [existing issues](https://github.com/jgamblin/CVElk/issues) to avoid duplicates.

When reporting a bug, include:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Python version, Docker version)
- Relevant logs or error messages

### Suggesting Features

Feature requests are welcome! Please:
- Check existing issues and discussions first
- Provide a clear description of the feature
- Explain the use case and benefits
- Consider if this fits the project's scope

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install development dependencies**: `pip install -e ".[dev]"`
3. **Make your changes** following our coding standards
4. **Add tests** for any new functionality
5. **Run the test suite**: `make test`
6. **Run linting**: `make lint`
7. **Update documentation** if needed
8. **Submit your pull request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/CVElk.git
cd CVElk

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Start development Elasticsearch
cd docker && docker compose -f docker-compose.dev.yml up -d
```

## Coding Standards

### Python Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
# Check for issues
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/
```

### Type Hints

All new code should include type hints:

```python
def process_cve(cve_id: str, score: float) -> dict[str, Any]:
    """Process a CVE and return enriched data."""
    ...
```

Run type checking with:
```bash
make type-check
```

### Docstrings

Use Google-style docstrings:

```python
def fetch_cves(start_date: datetime, end_date: datetime) -> list[CVE]:
    """Fetch CVEs within a date range.

    Args:
        start_date: Start of the date range.
        end_date: End of the date range.

    Returns:
        List of CVE objects matching the criteria.

    Raises:
        NVDAPIError: If the API request fails.
    """
    ...
```

### Testing

- Write tests for all new functionality
- Aim for >80% code coverage
- Use pytest fixtures for common test data
- Mark slow tests with `@pytest.mark.slow`

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific tests
pytest tests/unit/test_models_cve.py -v
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add CVSS v4.0 support
fix: correct EPSS percentile calculation
docs: update README with new CLI commands
test: add tests for KEV service
refactor: simplify NVD API pagination
```

## Project Structure

```
CVElk/
├── src/cvelk/           # Main package
│   ├── models/          # Data models (Pydantic)
│   ├── services/        # Business logic
│   ├── utils/           # Utilities
│   ├── cli.py           # CLI commands
│   └── config.py        # Configuration
├── tests/               # Test suite
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   └── fixtures/       # Test data
├── docker/              # Docker configuration
└── docs/                # Documentation
```

## Release Process

Releases are automated via GitHub Actions when a new tag is pushed:

1. Update version in `src/cvelk/__init__.py` and `pyproject.toml`
2. Update CHANGELOG.md
3. Create a GitHub release with the new tag
4. CI automatically builds and publishes to PyPI and GHCR

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/jgamblin/CVElk/discussions)
- **Bugs**: Open an [Issue](https://github.com/jgamblin/CVElk/issues)
- **Security**: See [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
