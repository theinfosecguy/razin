.PHONY: help install install-docs lint format test ci docs-serve docs-build docs-check clean

# Show available targets
help: ## Show available targets
	@grep -E '^[a-z][a-z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

# Install project with dev dependencies
install: ## Install project with dev dependencies
	uv sync --dev

# Install docs toolchain dependencies
install-docs: ## Install docs dependencies
	uv sync --group docs

# Run ruff linter on src and tests
lint: ## Run ruff linter on src and tests
	uv run ruff check src tests

# Format code with black and isort
format: ## Format code with black and isort
	uv run isort src tests
	uv run black src tests

# Run test suite
test: ## Run test suite
	uv run pytest -q

# Run all checks (isort, black, ruff, mypy)
ci: ## Run all checks (isort, black, ruff, mypy)
	uv run isort --check-only src tests
	uv run black --check src tests
	uv run ruff check src tests
	uv run mypy src tests

# Serve docs locally with autoreload
docs-serve: ## Serve docs locally
	uv run mkdocs serve

# Build docs with strict warnings as errors
docs-build: ## Build docs site with strict validation
	uv run mkdocs build --strict

# Run docs style and local link checks
docs-check: ## Run docs style and link checks
	uv run mkdocs build --strict
	uv run mdformat --check README.md docs
	uv run linkchecker --no-warnings site/index.html README.md

# Remove scan outputs and cache
clean: ## Remove scan outputs and cache
	rm -rf output/
	rm -f .razin-cache.json
