.PHONY: help build build-release test test-quick clippy check install reinstall \
       start start-detach stop restart clean clean-stale kill-port mem-check \
       docker-dev docker-dev-up docker-dev-stop docker-dev-restart docker-dev-logs docker-dev-clean

# Memory-aware parallelism to avoid OOM on Linux (systemd-oomd)
# [profile.test] in Cargo.toml uses debug=false to keep test binaries small (~4MB vs ~250MB)
# .cargo/config.toml caps build jobs; TEST_THREADS limits parallel test execution
# Hard caps on test path (TEST_JOBS=4, TEST_THREADS_CAP=2) bound concurrent mold link
# spikes that previously triggered nvidia-modeset display-engine timeouts under load.
AVAILABLE_GB := $(shell awk '/MemAvailable/ {printf "%d", $$2/1048576}' /proc/meminfo)
JOBS ?= $(shell echo $$(( $(AVAILABLE_GB) > 48 ? 8 : $(AVAILABLE_GB) > 24 ? 4 : 2 )))
TEST_THREADS ?= $(shell echo $$(( $(AVAILABLE_GB) > 32 ? 4 : $(AVAILABLE_GB) > 16 ? 2 : 1 )))
TEST_JOBS ?= 4
TEST_THREADS_CAP ?= 2

# Default target: show help
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## Development

build: ## Compile all workspace crates (lib only)
	cargo build --workspace --lib

build-release: ## Build optimized release binary
	RUST_MIN_STACK=16777216 cargo build --release -p openfang-cli -j $(JOBS)

mem-check: ## Show current memory and recommended parallelism
	@echo "Available: $(AVAILABLE_GB) GB | JOBS=$(JOBS) | TEST_THREADS=$(TEST_THREADS)"
	@echo "Test caps: TEST_JOBS=$(TEST_JOBS) | TEST_THREADS_CAP=$(TEST_THREADS_CAP)"
	@echo "Swap: $$(swapon --show=SIZE --noheadings 2>/dev/null || echo 'none')"

test: ## Run full test suite (nextest: process-per-test)
	cargo nextest run --workspace --build-jobs $(TEST_JOBS) --test-threads $(TEST_THREADS_CAP)

test-quick: ## Run lib-only tests (faster, no integration tests)
	cargo nextest run --workspace --lib --build-jobs $(TEST_JOBS) --test-threads $(TEST_THREADS_CAP)

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

## Docker dev environment (runs host-built binary)

COMPOSE_DEV = docker compose -f docker-compose.dev.yml

docker-dev: build-release ## Build on host and run in Docker
	$(COMPOSE_DEV) up

docker-dev-up: ## Start dev container (assumes binary already built)
	$(COMPOSE_DEV) up

docker-dev-stop: ## Stop dev container
	$(COMPOSE_DEV) down

docker-dev-restart: build-release docker-dev-stop ## Rebuild on host and restart container
	$(COMPOSE_DEV) up -d

docker-dev-logs: ## Show dev container logs
	$(COMPOSE_DEV) logs -f

docker-dev-clean: ## Remove dev volumes
	$(COMPOSE_DEV) down -v

## OpenAPI

openapi: ## Generate openapi.json from openfang-api utoipa annotations
	cargo run -p xtask -- openapi --out openapi.json

## Cleanup

clean: ## Remove all build artifacts
	cargo clean

clean-stale: ## Periodic deep clean: drop debug artifacts to avoid 10s of GB accumulation
	@before=$$(du -sh target/debug 2>/dev/null | cut -f1); \
	  rm -rf target/debug; \
	  echo "Removed target/debug (was $${before:-absent})."
	@echo "Tip: run monthly or after rustup updates (mixed-toolchain rlibs accumulate)."
