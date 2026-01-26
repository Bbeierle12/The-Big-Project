# Unified Security Platform - Task Runner
# Usage: just <recipe>

# Default recipe: show available recipes
default:
    @just --list

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# Build all Rust crates
build-rust:
    cargo build --workspace

# Build Rust crates in release mode
build-rust-release:
    cargo build --workspace --release

# Build Python package (compiles Rust + bundles native extension)
build-python:
    maturin develop

# Build everything
build: build-rust build-python

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

# Run all Rust tests
test-rust:
    cargo test --workspace

# Run Python tests
test-python:
    python -m pytest tests/python/ -v

# Run all tests
test: test-rust test-python

# ---------------------------------------------------------------------------
# Lint & Format
# ---------------------------------------------------------------------------

# Lint Rust code
lint-rust:
    cargo clippy --workspace -- -D warnings

# Lint Python code
lint-python:
    ruff check python/ tests/

# Lint everything
lint: lint-rust lint-python

# Format Rust code
fmt-rust:
    cargo fmt --all

# Format Python code
fmt-python:
    ruff format python/ tests/

# Format everything
fmt: fmt-rust fmt-python

# Check formatting without changes
fmt-check:
    cargo fmt --all -- --check
    ruff format --check python/ tests/

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------

# Run development server
dev:
    python -m netsec

# Run with auto-reload
dev-reload:
    uvicorn netsec.api.app:create_app --factory --reload --host 127.0.0.1 --port 8420

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

# Run database migrations
migrate:
    alembic upgrade head

# Create a new migration
migration name:
    alembic revision --autogenerate -m "{{name}}"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

# Clean Rust build artifacts
clean-rust:
    cargo clean

# Clean Python build artifacts
clean-python:
    rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache __pycache__
    find python/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Clean everything
clean: clean-rust clean-python

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

# Build Docker image
docker-build:
    docker build -f deploy/docker/Dockerfile -t netsec .

# Run with Docker Compose
docker-up:
    docker compose -f deploy/docker/docker-compose.yml up -d

# Stop Docker Compose
docker-down:
    docker compose -f deploy/docker/docker-compose.yml down

# ---------------------------------------------------------------------------
# CI
# ---------------------------------------------------------------------------

# Full CI check (lint, format check, test)
ci: lint fmt-check test
