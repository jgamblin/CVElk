.PHONY: help install dev lint format type-check test test-cov clean build docker-build docker-up docker-down sync setup

# Default target
help:
	@echo "CVElk - Vulnerability Intelligence Platform"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  install      Install production dependencies"
	@echo "  dev          Install development dependencies"
	@echo "  lint         Run linter (ruff)"
	@echo "  format       Format code (ruff format)"
	@echo "  type-check   Run type checker (mypy)"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage"
	@echo "  clean        Remove build artifacts"
	@echo ""
	@echo "Build:"
	@echo "  build        Build Python package"
	@echo "  docker-build Build Docker image"
	@echo ""
	@echo "Docker:"
	@echo "  docker-up    Start Elasticsearch and Kibana (dev mode)"
	@echo "  docker-down  Stop Docker containers"
	@echo "  docker-logs  View Docker container logs"
	@echo ""
	@echo "CVElk Commands:"
	@echo "  sync         Sync CVE data to Elasticsearch"
	@echo "  setup        Set up Kibana dashboards"
	@echo "  stats        Show CVE statistics"

# =============================================================================
# Development
# =============================================================================

install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

type-check:
	mypy src/

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=cvelk --cov-report=term-missing --cov-report=html

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +

# =============================================================================
# Build
# =============================================================================

build: clean
	pip install hatch
	hatch build

docker-build:
	docker build -t cvelk:latest .

# =============================================================================
# Docker
# =============================================================================

docker-up:
	cd docker && docker compose -f docker-compose.dev.yml up -d

docker-down:
	cd docker && docker compose -f docker-compose.dev.yml down

docker-logs:
	cd docker && docker compose -f docker-compose.dev.yml logs -f

docker-up-secure:
	cd docker && docker compose up -d

docker-down-secure:
	cd docker && docker compose down

# =============================================================================
# CVElk Commands
# =============================================================================

sync:
	cvelk sync --days 7

sync-full:
	cvelk sync --full

setup:
	cvelk setup

stats:
	cvelk stats

# =============================================================================
# CI/CD
# =============================================================================

ci: lint type-check test

release: clean build
	twine upload dist/*
