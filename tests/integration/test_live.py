"""Live integration tests against a running openfang daemon.

Mirrors the manual procedure in CLAUDE.md "MANDATORY: Live Integration Testing":
hits real endpoints (no mocks), drives a real LLM round-trip via LM Studio,
checks side effects (budget tracking) and dashboard markup.
"""
from __future__ import annotations

import httpx
import pytest


# ── Health & metadata ─────────────────────────────────────────────────────────


def test_health(client: httpx.Client) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200


def test_version(client: httpx.Client) -> None:
    r = client.get("/api/version")
    assert r.status_code == 200


def test_status(client: httpx.Client) -> None:
    r = client.get("/api/status")
    assert r.status_code == 200


# ── Permissive read endpoints (default require_auth_for_reads = false) ────────


@pytest.mark.parametrize(
    "path",
    [
        "/api/agents",
        "/api/budget",
        "/api/budget/agents",
        "/api/hands",
        "/api/hands/active",
        "/api/skills",
        "/api/sessions",
    ],
)
def test_dashboard_read_endpoint(client: httpx.Client, path: str) -> None:
    r = client.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}: {r.text[:300]}"


# ── Cron endpoint (upstream replaced custom scheduler with cron) ──────────────


def test_cron_jobs_endpoint(client: httpx.Client) -> None:
    r = client.get("/api/cron/jobs")
    assert r.status_code == 200


# ── Real LLM round-trip via LM Studio ─────────────────────────────────────────


def test_llm_roundtrip(client: httpx.Client, first_agent_id: str) -> None:
    """Send a real message; the daemon must call LM Studio and reply."""
    r = client.post(
        f"/api/agents/{first_agent_id}/message",
        json={"message": "Reply with exactly the word PONG."},
        timeout=120.0,
    )
    assert r.status_code == 200, f"message failed: {r.status_code} {r.text[:400]}"
    body = r.json()
    # Body shape varies by build; check that some response payload came back.
    assert any(k in body for k in ("response", "content", "message", "text")), (
        f"unexpected response shape: {body!r}"
    )


def test_budget_reflects_llm_usage(
    client: httpx.Client, first_agent_id: str
) -> None:
    """Local cost-tracking should populate the per-agent budget endpoint after a turn."""
    # Drive a turn first so there's something to meter.
    client.post(
        f"/api/agents/{first_agent_id}/message",
        json={"message": "say hi"},
        timeout=120.0,
    )
    r = client.get(f"/api/budget/agents/{first_agent_id}")
    assert r.status_code == 200, f"budget endpoint failed: {r.status_code}"
    # Whatever shape it returns, it must be non-empty JSON.
    assert r.json() not in (None, {}, [])


# ── Pro-Researcher hand discovery ─────────────────────────────────────────────


def test_pro_researcher_hand_registered(client: httpx.Client) -> None:
    """pro-researcher must be in the bundled-hands list with delegation +
    workspace tools. web_search/web_fetch/shell_exec are listed only so the
    kernel's privilege-subset rule lets the orchestrator delegate children
    that use them; the system prompt forbids the orchestrator from calling
    them directly, and the HAND.toml [exec_policy] restricts shell_exec to
    `yt-dlp` only (commit 6ef8481)."""
    r = client.get("/api/hands")
    assert r.status_code == 200
    data = r.json()
    items = data if isinstance(data, list) else data.get("hands", [])
    pro = next((h for h in items if h.get("id") == "pro-researcher"), None)
    assert pro is not None, f"pro-researcher hand missing from /api/hands; got {[h.get('id') for h in items]}"
    tools = pro.get("tools") or []
    for needed in (
        "agent_delegate",
        "file_read",
        "file_write",
        "file_list",
        "memory_store",
        "web_search",
        "web_fetch",
        "shell_exec",
    ):
        assert needed in tools, f"pro-researcher missing required tool {needed}; tools={tools}"
    # long_running flag must be surfaced so demiurg can route via async-poll.
    assert pro.get("long_running") is True, (
        f"pro-researcher must report long_running=true in /api/hands; got {pro.get('long_running')!r}"
    )


def test_demiurg_hand_has_async_dispatch_tools(client: httpx.Client) -> None:
    """Demiurg must carry agent_send_async + delegation_await so it can dispatch
    long_running hands (e.g. pro-researcher) via the async-poll path instead of
    the 5-minute sync timeout cliff."""
    r = client.get("/api/hands")
    assert r.status_code == 200
    data = r.json()
    items = data if isinstance(data, list) else data.get("hands", [])
    demiurg = next((h for h in items if h.get("id") == "demiurg"), None)
    assert demiurg is not None, "demiurg hand missing from /api/hands"
    tools = demiurg.get("tools") or []
    for needed in ("agent_send", "agent_send_async", "agent_delegate_async", "delegation_await"):
        assert needed in tools, f"demiurg missing {needed}; tools={tools}"
    # Demiurg itself is NOT long_running — it orchestrates short-lived dispatches.
    assert demiurg.get("long_running") is False, (
        f"demiurg should not flag long_running; got {demiurg.get('long_running')!r}"
    )


# ── Hand lifecycle (multi-instance + named uniqueness) ────────────────────────


def _pick_hand_id(client: httpx.Client) -> str | None:
    r = client.get("/api/hands")
    if r.status_code != 200:
        return None
    data = r.json()
    items = data if isinstance(data, list) else data.get("hands", [])
    # Avoid hands with heavy non-optional requirements (browser needs chromium,
    # clip needs ffmpeg) so the test stays portable.
    skip = {"browser", "clip"}
    candidates = [h for h in items if h.get("id") not in skip]
    pool = candidates or items
    return pool[0].get("id") if pool else None


def test_hand_unnamed_multi_instance_allowed(client: httpx.Client) -> None:
    """Local: unnamed activations of the same hand may coexist."""
    hand_id = _pick_hand_id(client)
    if hand_id is None:
        pytest.skip("no bundled hands available")
    r1 = client.post(f"/api/hands/{hand_id}/activate", json={})
    r2 = client.post(f"/api/hands/{hand_id}/activate", json={})
    assert r1.status_code == 200 and r2.status_code == 200, (
        f"unnamed activations should succeed; got {r1.status_code}/{r2.status_code}"
    )


def test_hand_named_uniqueness_enforced(client: httpx.Client) -> None:
    """Upstream: same (hand_id, name) twice → reject."""
    hand_id = _pick_hand_id(client)
    if hand_id is None:
        pytest.skip("no bundled hands available")
    name = "live-test-named-instance"
    first = client.post(
        f"/api/hands/{hand_id}/activate", json={"instance_name": name}
    )
    assert first.status_code == 200, f"first named activate failed: {first.text[:300]}"
    dup = client.post(f"/api/hands/{hand_id}/activate", json={"instance_name": name})
    assert dup.status_code != 200, (
        f"duplicate named instance should be rejected, got {dup.status_code}"
    )


# ── Dashboard HTML carries local-only nav items ───────────────────────────────


def test_dashboard_has_evolution_nav(client: httpx.Client) -> None:
    html = client.get("/").text
    assert "navigate('evolution')" in html, "Evolution nav item missing from dashboard"


def test_dashboard_has_tools_nav(client: httpx.Client) -> None:
    html = client.get("/").text
    assert "navigate('tools')" in html, "Tools nav item missing from dashboard"


# ── Editable per-model overrides (PUT /api/models/{id}) ───────────────────────


def _pick_model_for_edit_test(client: httpx.Client) -> tuple[str, dict] | None:
    """Pick a stable builtin model to edit-and-revert; returns (id, original entry)."""
    r = client.get("/api/models")
    if r.status_code != 200:
        return None
    models = r.json().get("models", [])
    # Anthropic Sonnet is in every build; lets the test work without provider keys.
    for m in models:
        if m.get("id") == "claude-sonnet-4-20250514":
            return m["id"], m
    return None


def test_models_response_exposes_max_output_and_overridden(
    client: httpx.Client,
) -> None:
    """list_models must surface max_output_tokens and an overridden flag per row."""
    r = client.get("/api/models")
    assert r.status_code == 200
    models = r.json().get("models", [])
    assert models, "expected at least one model in catalog"
    sample = models[0]
    assert "max_output_tokens" in sample, sample
    assert "overridden" in sample, sample
    assert isinstance(sample["overridden"], bool)


def test_update_model_creates_then_updates_then_resets(client: httpx.Client) -> None:
    """PUT /api/models/{id} adds a Custom shadow; second PUT reports 'updated';
    DELETE /api/models/custom/{id} unmasks the original entry."""
    picked = _pick_model_for_edit_test(client)
    if picked is None:
        pytest.skip("no stable builtin model available")
    model_id, original = picked
    original_ctx = original["context_window"]
    original_max = original["max_output_tokens"]

    # 1st PUT — should create a Custom shadow.
    r = client.put(
        f"/api/models/{model_id}",
        json={"context_window": 12345, "max_output_tokens": 6789},
    )
    assert r.status_code == 200, f"first PUT failed: {r.status_code} {r.text[:300]}"
    assert r.json().get("status") == "added", r.json()

    # GET reflects new values + overridden=true.
    r = client.get(f"/api/models/{model_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["context_window"] == 12345, body
    assert body["max_output_tokens"] == 6789, body
    assert body["overridden"] is True, body
    assert body["tier"] == "custom", body

    # 2nd PUT (sparse — only context_window) — should report 'updated' and
    # preserve max_output_tokens from the prior shadow.
    r = client.put(f"/api/models/{model_id}", json={"context_window": 16384})
    assert r.status_code == 200
    assert r.json().get("status") == "updated", r.json()
    body = client.get(f"/api/models/{model_id}").json()
    assert body["context_window"] == 16384
    assert body["max_output_tokens"] == 6789, "sparse PUT must keep prior value"

    # Reset via existing DELETE — original values must reappear.
    r = client.delete(f"/api/models/custom/{model_id}")
    assert r.status_code == 200
    body = client.get(f"/api/models/{model_id}").json()
    assert body["context_window"] == original_ctx
    assert body["max_output_tokens"] == original_max
    assert body["overridden"] is False
    assert body["tier"] != "custom"


def test_update_model_unknown_id_returns_404(client: httpx.Client) -> None:
    r = client.put("/api/models/this-model-does-not-exist", json={"context_window": 1})
    assert r.status_code == 404


def test_dashboard_has_max_output_column(client: httpx.Client) -> None:
    html = client.get("/").text
    assert "Max Output" in html, "Max Output column missing from dashboard models table"


# ── A2A streaming: POST /a2a/tasks/sendSubscribe (SSE) ────────────────────────


def _parse_sse(body_iter):
    """Yield (event, json_payload) for each SSE frame on the wire.

    Frame shape per the W3C spec is `event: <name>\\ndata: <line>\\n\\n`. We
    only need the `event` and the JSON-decoded `data`, and the daemon emits
    single-line data payloads.
    """
    import json as _json

    event_name = None
    data_lines: list[str] = []
    for raw in body_iter:
        if raw is None:
            continue
        line = raw.rstrip("\r\n") if isinstance(raw, str) else raw.decode("utf-8", "replace").rstrip("\r\n")
        if line == "":
            if event_name is not None and data_lines:
                payload = "\n".join(data_lines)
                try:
                    yield event_name, _json.loads(payload)
                except _json.JSONDecodeError:
                    pass
            event_name = None
            data_lines = []
            continue
        if line.startswith(":"):
            continue  # comment / keepalive
        if line.startswith("event:"):
            event_name = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())


def test_a2a_send_task_subscribe_streams_updates(base_url: str) -> None:
    """sendSubscribe must emit ≥1 non-final TaskStatusUpdate and exactly one
    final frame with state ∈ {completed, failed}. Polling GET /a2a/tasks/{id}
    after the stream closes must observe the same terminal state."""
    payload = {
        "params": {
            "message": {
                "parts": [{"type": "text", "text": "Reply with exactly the word PONG."}]
            }
        }
    }
    frames: list[tuple[str, dict]] = []
    task_id: str | None = None
    with httpx.Client(base_url=base_url, timeout=180.0) as c:
        with c.stream("POST", "/a2a/tasks/sendSubscribe", json=payload) as resp:
            assert resp.status_code == 200, f"sendSubscribe returned {resp.status_code}"
            for ev_name, data in _parse_sse(resp.iter_lines()):
                frames.append((ev_name, data))
                if task_id is None and isinstance(data, dict) and "id" in data:
                    task_id = data["id"]
                if isinstance(data, dict) and data.get("final") is True:
                    break

    assert task_id is not None, "no task id surfaced from any frame"
    assert any(
        ev == "TaskStatusUpdate"
        and isinstance(d, dict)
        and d.get("status", {}).get("state") == "working"
        and d.get("final") is False
        for ev, d in frames
    ), f"expected ≥1 working frame; got events {[(e, d.get('status', {}).get('state')) for e, d in frames]}"

    terminals = [d for _ev, d in frames if isinstance(d, dict) and d.get("final") is True]
    assert len(terminals) == 1, f"expected exactly one final frame, got {len(terminals)}"
    terminal = terminals[0]
    assert terminal["status"]["state"] in ("completed", "failed"), terminal

    # Polling endpoint must agree with the terminal frame.
    with httpx.Client(base_url=base_url, timeout=30.0) as c:
        r = c.get(f"/a2a/tasks/{task_id}")
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        # status may be either bare string ("completed") or {"state": ...}
        status_obj = body.get("status")
        if isinstance(status_obj, dict):
            state = status_obj.get("state")
        else:
            state = status_obj
        assert state == terminal["status"]["state"], (state, terminal)


def test_a2a_send_task_subscribe_cancel_midstream(base_url: str) -> None:
    """Cancel mid-stream: terminal frame must carry state=cancelled when the
    cancel lands before the run finishes; otherwise the stream still produces
    a clean terminal frame and the task store reflects the same state."""
    import threading
    import time as _time

    payload = {
        "params": {
            "message": {
                "parts": [
                    {
                        "type": "text",
                        "text": "Write a 1000-word essay about the Roman empire.",
                    }
                ]
            }
        }
    }

    cancelled_fired = threading.Event()
    stream_done = threading.Event()
    task_id_holder: dict[str, str] = {}

    def fire_cancel_when_id_known() -> None:
        # Use a fresh client so its lifecycle is independent of the main thread.
        with httpx.Client(base_url=base_url, timeout=30.0) as cc:
            for _ in range(300):
                if stream_done.is_set():
                    return
                tid = task_id_holder.get("id")
                if tid is not None:
                    try:
                        cc.post(f"/a2a/tasks/{tid}/cancel")
                    except httpx.HTTPError:
                        pass
                    cancelled_fired.set()
                    return
                _time.sleep(0.1)

    canceller = threading.Thread(target=fire_cancel_when_id_known, daemon=True)
    canceller.start()

    terminal: dict | None = None
    try:
        with httpx.Client(base_url=base_url, timeout=180.0) as c:
            with c.stream("POST", "/a2a/tasks/sendSubscribe", json=payload) as resp:
                assert resp.status_code == 200
                for _ev, data in _parse_sse(resp.iter_lines()):
                    if isinstance(data, dict) and "id" in data and "id" not in task_id_holder:
                        task_id_holder["id"] = data["id"]
                    if isinstance(data, dict) and data.get("final") is True:
                        terminal = data
                        break
    finally:
        stream_done.set()
        canceller.join(timeout=2.0)

    assert "id" in task_id_holder, "stream never surfaced a task id"
    assert terminal is not None, "stream closed without a final frame"

    state = terminal["status"]["state"]
    # `cancelled` is the goal; `completed`/`failed` happen when the run
    # finishes before cancel lands or when the LLM upstream errors fast.
    assert state in ("cancelled", "completed", "failed"), terminal

    with httpx.Client(base_url=base_url, timeout=30.0) as c:
        r = c.get(f"/a2a/tasks/{task_id_holder['id']}")
        assert r.status_code == 200
        body = r.json()
        status_obj = body.get("status")
        poll_state = status_obj.get("state") if isinstance(status_obj, dict) else status_obj
        assert poll_state == state, (poll_state, state)


# ── A2A concurrency: parallel across sessions, serial within a session ───────


def test_a2a_concurrent_send_across_sessions_runs_in_parallel(base_url: str) -> None:
    """Three /a2a/tasks/send calls without a shared sessionId target the same
    demiurg agent but distinct sessions. They must execute concurrently — the
    wall-clock for all three should be on the order of a single task, not 3x.

    Single-task baseline is measured first to compute the parallel threshold.
    """
    import threading
    import time as _time

    payload = {
        "params": {
            "message": {"parts": [{"type": "text", "text": "Reply with exactly the word OK."}]}
        }
    }

    def _send_and_poll(c: httpx.Client) -> float:
        t0 = _time.monotonic()
        r = c.post("/a2a/tasks/send", json=payload)
        assert r.status_code == 200, f"send returned {r.status_code}: {r.text[:300]}"
        tid = r.json()["id"]
        # Poll until terminal.
        deadline = _time.monotonic() + 120.0
        while _time.monotonic() < deadline:
            g = c.get(f"/a2a/tasks/{tid}")
            assert g.status_code == 200, g.text[:200]
            body = g.json()
            status = body.get("status")
            state = status.get("state") if isinstance(status, dict) else status
            if state in ("completed", "failed", "cancelled"):
                assert state == "completed", f"task {tid} ended in {state}: {body}"
                return _time.monotonic() - t0
            _time.sleep(0.25)
        raise AssertionError(f"task {tid} did not terminate within 120s")

    # Baseline: one call alone.
    with httpx.Client(base_url=base_url, timeout=180.0) as c:
        baseline = _send_and_poll(c)

    # Fire 3 concurrent.
    elapsed: list[float] = []
    errors: list[BaseException] = []

    def _worker() -> None:
        try:
            with httpx.Client(base_url=base_url, timeout=180.0) as c:
                elapsed.append(_send_and_poll(c))
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(3)]
    parallel_start = _time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=240.0)
    parallel_wall = _time.monotonic() - parallel_start

    assert not errors, f"concurrent workers failed: {errors!r}"
    assert len(elapsed) == 3, f"expected 3 completions, got {len(elapsed)}"

    # If execution were strictly serial, parallel_wall ≈ 3 * baseline. With
    # per-session locking it should be roughly 1 * baseline plus scheduling
    # jitter. Allow generous margin: 2 * baseline is still strong evidence of
    # parallelism (one full serial run would be ≥ 3 * baseline).
    threshold = max(2.0 * baseline, baseline + 5.0)
    assert parallel_wall < threshold, (
        f"3 parallel A2A sends took {parallel_wall:.1f}s, expected < {threshold:.1f}s "
        f"(baseline single-call {baseline:.1f}s). Looks serial."
    )


def test_a2a_concurrent_sendSubscribe_same_session_serializes(base_url: str) -> None:
    """Two sendSubscribe calls pinned to the SAME sessionId must serialize at
    the per-session lock. Both must reach state=completed (broken history
    would cause the second call to fail with a malformed-message provider
    error). The second call's wall time should be ≥ the first call's, since
    it queues behind the first."""
    import threading
    import time as _time
    import uuid

    shared_session = str(uuid.uuid4())
    payload = {
        "params": {
            "sessionId": shared_session,
            "message": {"parts": [{"type": "text", "text": "Reply with exactly the word OK."}]},
        }
    }

    results: list[tuple[float, str]] = []
    errors: list[BaseException] = []

    def _worker() -> None:
        try:
            t0 = _time.monotonic()
            terminal: dict | None = None
            with httpx.Client(base_url=base_url, timeout=180.0) as c:
                with c.stream("POST", "/a2a/tasks/sendSubscribe", json=payload) as resp:
                    assert resp.status_code == 200
                    for _ev, data in _parse_sse(resp.iter_lines()):
                        if isinstance(data, dict) and data.get("final") is True:
                            terminal = data
                            break
            assert terminal is not None
            state = terminal["status"]["state"]
            results.append((_time.monotonic() - t0, state))
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=240.0)

    assert not errors, f"concurrent SSE workers failed: {errors!r}"
    assert len(results) == 2

    # Both must complete cleanly — corruption would surface as 'failed'.
    for elapsed, state in results:
        assert state == "completed", f"unexpected terminal state {state} ({elapsed:.1f}s)"


# ── Evolve batch-apply (dedup + scheduled apply pipeline) ─────────────────────


def test_evolve_batch_apply_routes_registered(client: httpx.Client) -> None:
    """POST /api/evolve/batch-apply/run + GET .../preview must be wired in server.rs."""
    # Engine usually disabled in test env → endpoint should respond with 400,
    # NOT 404. 404 would mean the route isn't registered at all.
    r = client.post("/api/evolve/batch-apply/run", json={})
    assert r.status_code != 404, f"batch-apply/run route missing: {r.status_code} {r.text[:200]}"
    r = client.get("/api/evolve/batch-apply/preview")
    assert r.status_code != 404, f"batch-apply/preview route missing: {r.status_code} {r.text[:200]}"


def test_evolve_config_accepts_schedules(client: httpx.Client) -> None:
    """PUT /api/evolve/config with analyze_schedule + apply_schedule must round-trip
    via /config GET and create matching cron jobs."""
    cur = client.get("/api/evolve/config")
    assert cur.status_code == 200, cur.text[:300]
    body = cur.json()
    body["analyze_schedule"] = {"kind": "cron", "expr": "*/15 * * * *", "tz": None}
    body["apply_schedule"] = {"kind": "cron", "expr": "0 6 * * *", "tz": None}
    body["dedup_enabled"] = True
    body["apply_max_per_run"] = 7

    r = client.put("/api/evolve/config", json=body)
    assert r.status_code == 200, f"PUT config failed: {r.status_code} {r.text[:300]}"

    after = client.get("/api/evolve/config").json()
    assert after.get("dedup_enabled") is True
    assert after.get("apply_max_per_run") == 7
    assert after.get("analyze_schedule", {}).get("expr") == "*/15 * * * *"
    assert after.get("apply_schedule", {}).get("expr") == "0 6 * * *"

    jobs = client.get("/api/cron/jobs").json()
    items = jobs if isinstance(jobs, list) else jobs.get("jobs", [])
    names = {j.get("name") for j in items}
    assert "evolve analyze sessions" in names, f"analyze cron not synced; got {names}"
    assert "evolve batch apply" in names, f"batch-apply cron not synced; got {names}"


def test_dashboard_wires_batch_apply(client: httpx.Client) -> None:
    """Dashboard SPA must reference the new batch-apply UI bindings so the page
    renders the controls when evolution.js mounts."""
    r = client.get("/")
    assert r.status_code == 200, r.status_code
    html = r.text
    for token in ("batchApply", "analyzeCronExpr", "applyCronExpr", "previewBatchApply"):
        assert token in html, f"dashboard markup missing '{token}'"


def test_dashboard_wires_unprocessable_status(client: httpx.Client) -> None:
    """Dashboard SPA must ship the new SuggestionStatus helpers + badge labels
    so deduped/declined/unprocessable rows render distinct UI from pending."""
    r = client.get("/")
    assert r.status_code == 200, r.status_code
    html = r.text
    for token in (
        "suggestionStatusLabel",
        "suggestionStatusClass",
        "suggestionIsPending",
        "Unprocessable",
        "Superseded",
        "Declined",
    ):
        assert token in html, f"dashboard markup missing '{token}'"


def test_batch_apply_preview_exposes_unprocessable_field(
    client: httpx.Client,
) -> None:
    """Preview endpoint must report the unprocessable count so the dashboard
    can surface structurally-invalid suggestions to the operator."""
    r = client.get("/api/evolve/batch-apply/preview")
    # Engine may be disabled in test env (400) or running concurrently (409).
    # When it succeeds (200) the body must include the new field.
    if r.status_code == 200:
        body = r.json()
        assert "unprocessable" in body, f"preview body missing 'unprocessable': {body}"
    else:
        assert r.status_code in (400, 409), (
            f"unexpected preview status {r.status_code}: {r.text[:200]}"
        )
