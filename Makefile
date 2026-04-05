.PHONY: help build build-release test test-quick clippy check install reinstall \
       start start-detach stop restart clean kill-port \
       docker-dev docker-dev-build docker-dev-stop docker-dev-rebuild docker-dev-watch docker-dev-shell docker-dev-clean

# Build flags to avoid OOM on Linux (systemd-oomd)
JOBS ?= 4
TEST_THREADS ?= 4

# Default target: show help
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## Development

build: ## Compile all workspace crates (lib only)
	cargo build --workspace --lib

build-release: ## Build optimized release binary
	RUST_MIN_STACK=16777216 cargo build --release -p openfang-cli

test: ## Run full test suite (one crate at a time to avoid OOM)
	@for crate in $$(cargo metadata --no-deps --format-version=1 | python3 -c "import sys,json; [print(p['name']) for p in json.load(sys.stdin)['packages']]"); do \
		echo "\n\033[36m=== Testing $$crate ===\033[0m"; \
		cargo test -p $$crate -j $(JOBS) -- --test-threads=$(TEST_THREADS) || exit 1; \
	done

test-quick: ## Run lib-only tests (faster, no integration tests)
	@for crate in $$(cargo metadata --no-deps --format-version=1 | python3 -c "import sys,json; [print(p['name']) for p in json.load(sys.stdin)['packages']]"); do \
		echo "\n\033[36m=== Testing $$crate (lib) ===\033[0m"; \
		cargo test -p $$crate --lib -j $(JOBS) -- --test-threads=$(TEST_THREADS) || exit 1; \
	done

clippy: ## Lint with clippy (warnings are errors)
	cargo clippy --workspace --all-targets -- -D warnings

check: build clippy test ## Build + lint + test (full CI check)

## Install & daemon management

install: ## Install openfang binary via cargo install
	cargo install --path crates/openfang-cli

start: ## Start daemon in foreground
	openfang start &

start-detach: ## Start daemon in background (log: /tmp/openfang.log)
	nohup openfang start &>/tmp/openfang.log &
	@echo "OpenFang started (log: /tmp/openfang.log)"

kill-port: ## Kill any process listening on port 4200
	@pid=$$(lsof -ti :4200 2>/dev/null) && kill -9 $$pid && echo "Killed PID $$pid on :4200" || echo "Nothing on :4200"

stop: ## Stop the running daemon
	@openfang stop 2>/dev/null || echo "Not running"

restart: stop ## Restart the daemon
	@sleep 1
	openfang start &

reinstall: build-release kill-port stop ## Stop, rebuild, install, and restart
	@sleep 1
	cp target/release/openfang ~/.cargo/bin/openfang
	$(MAKE) start-detach
	@echo "Reinstalled and restarted openfang"

## Docker dev environment

COMPOSE_DEV = docker compose -f docker-compose.dev.yml

docker-dev: ## Start dev container (incremental build + run)
	$(COMPOSE_DEV) up

docker-dev-build: ## Rebuild dev container image from scratch
	$(COMPOSE_DEV) up --build

docker-dev-stop: ## Stop dev container
	$(COMPOSE_DEV) down

docker-dev-rebuild: ## Rebuild openfang inside running dev container
	$(COMPOSE_DEV) exec openfang cargo build --bin openfang

docker-dev-watch: ## Start dev container with cargo-watch (auto-rebuild on changes)
	$(COMPOSE_DEV) run --rm -p 4200:4200 openfang \
		cargo watch -x 'build --bin openfang' -s './target/debug/openfang start'

docker-dev-shell: ## Open a shell in the dev container
	$(COMPOSE_DEV) exec openfang bash

docker-dev-clean: ## Remove dev volumes (target cache, cargo registry)
	$(COMPOSE_DEV) down -v

## Cleanup

clean: ## Remove all build artifacts
	cargo clean
