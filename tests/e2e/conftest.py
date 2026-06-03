"""E2E fixtures: talk to the running Docker stack over HTTP.

These tests assume `make up` has started the stack (auth:8000, tenant_a:8001,
tenant_b:8002). The `stack` fixture waits briefly for health so a freshly-started
stack doesn't cause flakes, and skips with a clear message if it never comes up.
"""
import os
import time

import httpx
import pytest

AUTH = os.environ.get("AUTH_URL", "http://localhost:8000")
TENANT_A = os.environ.get("TENANT_A_URL", "http://localhost:8001")
TENANT_B = os.environ.get("TENANT_B_URL", "http://localhost:8002")


def _wait_healthy(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{url}/healthz", timeout=2).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    return False


@pytest.fixture(scope="session")
def stack():
    for url in (AUTH, TENANT_A, TENANT_B):
        if not _wait_healthy(url):
            pytest.skip(f"stack not reachable at {url} — run `make up` first")
    return {"auth": AUTH, "tenant_a": TENANT_A, "tenant_b": TENANT_B}


@pytest.fixture
def login(stack):
    def _login(email: str, password: str) -> httpx.Response:
        return httpx.post(
            f"{stack['auth']}/login",
            json={"email": email, "password": password},
            timeout=5,
        )

    return _login
