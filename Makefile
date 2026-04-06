.PHONY: help build build-release test test-quick clippy check install reinstall \
       start start-detach stop restart clean kill-port mem-check \
       docker-dev docker-dev-up docker-dev-stop docker-dev-restart docker-dev-logs docker-dev-clean

# Memory-aware parallelism to avoid OOM on Linux (systemd-oomd)
# [profile.test] in Cargo.toml uses debug=false to keep test binaries small (~4MB vs ~250MB)
# .cargo/config.toml caps build jobs; TEST_THREADS limits parallel test execution
AVAILABLE_GB := $(shell awk '/MemAvailable/ {printf "%d", $$2/1048576}' /proc/meminfo)
JOBS ?= $(shell echo $$(( $(AVAILABLE_GB) > 48 ? 8 : $(AVAILABLE_GB) > 24 ? 4 : 2 )))
TEST_THREADS ?= $(shell echo $$(( $(AVAILABLE_GB) > 32 ? 4 : $(AVAILABLE_GB) > 16 ? 2 : 1 )))

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
	@echo "Swap: $$(swapon --show=SIZE --noheadings 2>/dev/null || echo 'none')"

test: ## Run full test suite (parallel workspace build, shared deps)
	cargo test --workspace -j $(JOBS) -- --test-threads=$(TEST_THREADS)

test-quick: ## Run lib-only tests (faster, no integration tests)
	cargo test --workspace --lib -j $(JOBS) -- --test-threads=$(TEST_THREADS)

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

## Cleanup

clean: ## Remove all build artifacts
	cargo clean
