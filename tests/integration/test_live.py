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
