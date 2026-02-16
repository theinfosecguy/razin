.PHONY: help install lint format test ci clean

# Show available targets
help: ## Show available targets
	@grep -E '^[a-z][a-z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

# Install project with dev dependencies
install: ## Install project with dev dependencies
	uv sync --dev

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

# Remove scan outputs and cache
clean: ## Remove scan outputs and cache
	rm -rf output/
	rm -f .razin-cache.json
