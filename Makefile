# OASIS Development Makefile

.PHONY: help install install-dev test test-cov lint format type-check pre-commit clean run

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install production dependencies
	poetry install --only=main

install-dev:  ## Install all dependencies including development tools
	poetry install
	poetry run pre-commit install

test:  ## Run tests
	poetry run pytest -v

test-cov:  ## Run tests with coverage report
	poetry run pytest --cov=src --cov-report=html --cov-report=term-missing

lint:  ## Run linting checks
	poetry run flake8 src tests
	poetry run black --check src tests
	poetry run isort --check-only src tests

format:  ## Format code
	poetry run black src tests
	poetry run isort src tests

type-check:  ## Run type checking
	poetry run mypy src

pre-commit:  ## Run pre-commit hooks on all files
	poetry run pre-commit run --all-files

clean:  ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +

run:  ## Run OASIS application
	poetry run python -m oasis

dev-setup: install-dev  ## Complete development environment setup
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify everything is working."