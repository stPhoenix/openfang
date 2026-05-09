# OpenFang — Agent Instructions
# Important: use mcp for code exploration

## Project Overview
OpenFang is an open-source Agent Operating System written in Rust (14 crates).
- Config: `~/.openfang/config.toml`
- Default API: `http://127.0.0.1:4200`
- CLI binary: `target/release/openfang.exe` (or `target/debug/openfang.exe`)

## Build & Verify Workflow
After every feature implementation, run ALL THREE checks:
```bash
make build    # Compile all workspace crates (lib only)
make test     # Run full test suite (memory-aware parallelism)
make clippy   # Lint with clippy (warnings are errors)
```
Or run all three at once: `make check`

## Runtime: Docker Compose

Daemon runs in Docker. Two compose files:

- `docker-compose.dev.yml` — dev daemon. Mounts host `target/release/openfang`. Port 4200. API key `dev-local-key`.
- `docker-compose.tests.yml` — live integration tests. Daemon + pytest sibling container against host LM Studio.

### Dev daemon

```bash
make build-release                              # build host binary first
docker compose -f docker-compose.dev.yml up -d  # start
docker compose -f docker-compose.dev.yml logs -f
docker compose -f docker-compose.dev.yml down   # stop
```

Rebuild loop: `make build-release && docker compose -f docker-compose.dev.yml restart`.

### Key Make Targets
| Target | Description |
|--------|-------------|
| `make build` | Compile all workspace crates (`--lib` only) |
| `make build-release` | Build optimized release binary (openfang-cli) |
| `make test` | Full test suite with memory-aware parallelism |
| `make test-quick` | Lib-only tests (faster, no integration tests) |
| `make clippy` | Lint (warnings are errors) |
| `make check` | Build + clippy + test (full CI check) |
| `make mem-check` | Show available RAM and parallelism settings |
| `make install` | Install openfang binary via `cargo install` |
| `make start` | Start daemon in foreground |
| `make start-detach` | Start daemon in background (log: /tmp/openfang.log) |
| `make stop` | Stop the running daemon |
| `make restart` | Stop and restart the daemon |
| `make reinstall` | Stop, rebuild, install, and restart |
| `make kill-port` | Kill any process on port 4200 |
| `make clean` | Remove all build artifacts |
| `make docker-dev` | Build on host and run in Docker |
| `make docker-dev-up` | Start dev container (assumes binary built) |
| `make docker-dev-stop` | Stop dev container |
| `make docker-dev-restart` | Rebuild on host and restart container |
| `make docker-dev-logs` | Show dev container logs |
| `make docker-dev-clean` | Remove dev volumes |

### OOM Prevention
- `Cargo.toml` `[profile.dev]` uses `debug = "line-tables-only"` to keep test binaries ~200MB (not ~600MB)
- `.cargo/config.toml` uses mold linker and limits to 8 build jobs
- Makefile auto-scales JOBS and TEST_THREADS based on `/proc/meminfo`
- Docker containers are capped at 4GB to avoid competing with host builds
- Prereqs: `sudo apt install mold clang`; optionally enable zram for fast compressed swap

## MANDATORY: Live Integration Testing
**After implementing any new endpoint, feature, or wiring change, you MUST run live integration tests.** Unit tests alone are not enough — they can pass while the feature is actually dead code. Live tests catch:
- Missing route registrations in server.rs
- Config fields not being deserialized from TOML
- Type mismatches between kernel and API layers
- Endpoints that compile but return wrong/empty data

### How to Run Live Integration Tests

Tests run via `docker-compose.tests.yml`. Daemon container talks to host LM Studio at `host.docker.internal`. Pytest
runs in sibling container against `http://openfang-daemon:4200`. Exit code = pytest exit code.

#### Step 1: Free port 4200

Stop dev compose if running:
```bash
docker compose -f docker-compose.dev.yml down
```

#### Step 2: Build host release binary
```bash
make build-release
```

Test daemon mounts `target/release/openfang` read-only.

#### Step 3: Run the test stack
```bash
docker compose -f docker-compose.tests.yml up \
    --build --abort-on-container-exit --exit-code-from openfang-tests
```

Wait for daemon healthcheck (`/api/health`), then pytest runs. Daemon stops after pytest exits.

#### Step 4: Manual probes (optional, daemon still up)

While the stack runs, hit endpoints from host:
```bash
curl -s http://127.0.0.1:4200/api/health
curl -s http://127.0.0.1:4200/api/<new-endpoint>
curl -s -X POST http://127.0.0.1:4200/api/<endpoint> \
  -H "Content-Type: application/json" -d '{"field": "value"}'
```

For LLM call: get agent id from `/api/agents`, POST `/api/agents/<id>/message`. Verify side effects via `/api/budget`,
`/api/budget/agents`. Verify dashboard wiring via `curl -s http://127.0.0.1:4200/ | grep -c "newComponentName"`.

#### Step 5: Cleanup
```bash
docker compose -f docker-compose.tests.yml down -v
```

Note: tests set `OPENFANG_ALLOW_NO_AUTH=1` (sibling container is non-loopback). Never set this in prod.

### Key API Endpoints for Testing
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/health` | GET | Basic health check |
| `/api/agents` | GET | List all agents |
| `/api/agents/{id}/message` | POST | Send message (triggers LLM) |
| `/api/budget` | GET/PUT | Global budget status/update |
| `/api/budget/agents` | GET | Per-agent cost ranking |
| `/api/budget/agents/{id}` | GET | Single agent budget detail |
| `/api/network/status` | GET | OFP network status |
| `/api/peers` | GET | Connected OFP peers |
| `/api/a2a/agents` | GET | External A2A agents |
| `/api/a2a/discover` | POST | Discover A2A agent at URL |
| `/api/a2a/send` | POST | Send task to external A2A agent |
| `/api/a2a/tasks/{id}/status` | GET | Check external A2A task status |

## Architecture Notes
- **Don't touch `openfang-cli`** — user is actively building the interactive CLI
- `KernelHandle` trait avoids circular deps between runtime and kernel
- `AppState` in `server.rs` bridges kernel to API routes
- New routes must be registered in `server.rs` router AND implemented in `routes.rs`
- Dashboard is Alpine.js SPA in `static/index_body.html` — new tabs need both HTML and JS data/methods
- Config fields need: struct field + `#[serde(default)]` + Default impl entry + Serialize/Deserialize derives

## Common Gotchas

- Binary may be locked if dev compose is running — `docker compose -f docker-compose.dev.yml down` (or `make build`
  lib-only) first
- Port 4200 conflict: dev and tests both bind 4200 — bring one down before starting the other
- `PeerRegistry` is `Option<PeerRegistry>` on kernel but `Option<Arc<PeerRegistry>>` on `AppState` — wrap with `.as_ref().map(|r| Arc::new(r.clone()))`
- Config fields added to `KernelConfig` struct MUST also be added to the `Default` impl or build fails
- `AgentLoopResult` field is `.response` not `.response_text`
- CLI command to start daemon is `start` not `daemon`
