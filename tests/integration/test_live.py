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
