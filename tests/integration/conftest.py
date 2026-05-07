"""Shared pytest fixtures for live integration tests."""
from __future__ import annotations

import os

import httpx
import pytest


BASE_URL = os.environ.get("OPENFANG_BASE_URL", "http://openfang-daemon:4200")


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
def client(base_url: str) -> httpx.Client:
    with httpx.Client(base_url=base_url, timeout=120.0) as c:
        yield c


@pytest.fixture(scope="session")
def first_agent_id(client: httpx.Client) -> str:
    """Return the id of the first seeded agent, or skip the test."""
    r = client.get("/api/agents")
    r.raise_for_status()
    agents = r.json()
    if not agents:
        pytest.skip("daemon has no seeded agents to drive a real LLM call")
    return agents[0]["id"]
