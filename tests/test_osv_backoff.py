"""Unit tests for GuardX's OSV 429 backoff in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_pwned_password.py`. The stub `FastMCP.tool()` returns the
decorated function unchanged, exactly like FastMCP 1.x does, so these
tests exercise the real `_osv_query` retry logic.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs
# ---------------------------------------------------------------------------

# Installed exactly once per pytest process: stub objects must be shared,
# otherwise a monkeypatch in one module misses the objects bound by another.
_STUB_SENTINEL = "__guardx_test_stubs_installed__"


def _install_stubs() -> None:
    if getattr(sys, _STUB_SENTINEL, False):
        return
    # --- httpx stub --------------------------------------------------------
    httpx = types.ModuleType("httpx")

    class RequestError(Exception):
        pass

    class AsyncClient:  # pragma: no cover - replaced by monkeypatching
        def __init__(self, *args, **kwargs):
            raise AssertionError("test must patch httpx.AsyncClient")

    httpx.RequestError = RequestError
    httpx.AsyncClient = AsyncClient
    sys.modules["httpx"] = httpx

    # --- mcp stub ----------------------------------------------------------
    mcp = types.ModuleType("mcp")
    server_pkg = types.ModuleType("mcp.server")
    fastmcp_mod = types.ModuleType("mcp.server.fastmcp")

    class FastMCP:
        def __init__(self, name: str):
            self.name = name

        def tool(self):
            def deco(fn):
                return fn  # FastMCP 1.x returns the function unchanged
            return deco

        def run(self):  # pragma: no cover
            raise AssertionError("tests must not start the server")

    fastmcp_mod.FastMCP = FastMCP
    server_pkg.fastmcp = fastmcp_mod
    mcp.server = server_pkg
    sys.modules["mcp"] = mcp
    sys.modules["mcp.server"] = server_pkg
    sys.modules["mcp.server.fastmcp"] = fastmcp_mod
    setattr(sys, _STUB_SENTINEL, True)


_install_stubs()

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("guardx_server", REPO_ROOT / "server.py")
assert _spec and _spec.loader
guardx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guardx)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None,
                 headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"vulns": []}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeClient:
    """Drop-in for httpx.AsyncClient with a scripted `.post()` sequence."""

    def __init__(self, *args, **kwargs):
        self.posts = []  # (url, payload) per call
        self.script = []  # FakeResponse (or Exception) per call, in order

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        item = self.script.pop(0) if self.script else FakeResponse()
        if isinstance(item, Exception):
            raise item
        return item

    @property
    def calls(self):
        return len(self.posts)


def run(coro):
    return asyncio.run(coro)


class SleepRecorder:
    """Async stand-in for asyncio.sleep that just records the waits."""

    def __init__(self):
        self.waits = []

    async def __call__(self, seconds: float):
        self.waits.append(seconds)


def patch_sleep(monkeypatch) -> SleepRecorder:
    recorder = SleepRecorder()
    monkeypatch.setattr(sys.modules["asyncio"], "sleep", recorder)
    return recorder


VULNS = [{"id": "CVE-2024-1234", "summary": "test vuln"}]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_200_first_try_no_sleep(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [FakeResponse(payload={"vulns": VULNS})]
    name, version, vulns = run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert (name, version, vulns) == ("requests", "2.28.0", VULNS)
    assert client.calls == 1
    assert sleeper.waits == []


def test_429_with_retry_after_honors_header(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [
        FakeResponse(status_code=429, headers={"retry-after": "5"}),
        FakeResponse(payload={"vulns": VULNS}),
    ]
    name, version, vulns = run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert vulns == VULNS
    assert client.calls == 2
    assert sleeper.waits == [5.0]


def test_429_without_header_uses_exponential_backoff(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [
        FakeResponse(status_code=429),
        FakeResponse(status_code=429),
        FakeResponse(payload={"vulns": []}),
    ]
    name, version, vulns = run(guardx._osv_query(client, "django", "4.0.0", "PyPI"))
    assert vulns == []
    assert client.calls == 3
    assert sleeper.waits == [1.0, 2.0]


def test_retry_after_is_clamped_to_max_wait(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [
        FakeResponse(status_code=429, headers={"retry-after": "300"}),
        FakeResponse(payload={"vulns": []}),
    ]
    run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert sleeper.waits == [guardx.OSV_MAX_RETRY_WAIT]


def test_malformed_retry_after_falls_back_to_backoff(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [
        # HTTP-date form is not parsed; falls back to exponential backoff.
        FakeResponse(status_code=429, headers={"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}),
        FakeResponse(payload={"vulns": []}),
    ]
    run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert sleeper.waits == [1.0]


def test_persistent_429_gives_up_after_max_attempts(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [FakeResponse(status_code=429)] * 10
    name, version, vulns = run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert (name, version, vulns) == ("requests", "2.28.0", None)
    assert client.calls == guardx.OSV_MAX_ATTEMPTS
    assert sleeper.waits == [1.0, 2.0, 4.0]  # no sleep after the final attempt


def test_non_429_non_200_fails_without_retry(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [FakeResponse(status_code=503)]
    name, version, vulns = run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert vulns is None
    assert client.calls == 1
    assert sleeper.waits == []


def test_network_error_still_returns_none_without_retry(monkeypatch):
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [sys.modules["httpx"].RequestError("boom")]
    name, version, vulns = run(guardx._osv_query(client, "requests", "2.28.0", "PyPI"))
    assert vulns is None
    assert client.calls == 1
    assert sleeper.waits == []


def test_retry_after_parsing():
    assert guardx._retry_after_seconds(None) is None
    assert guardx._retry_after_seconds("0") == 0.0
    assert guardx._retry_after_seconds("  12 ") == 12.0
    assert guardx._retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") is None
    assert guardx._retry_after_seconds("soon") is None
    assert guardx._retry_after_seconds("-3") is None


def test_audit_uses_backoff_end_to_end(monkeypatch, tmp_path):
    """A requirements.txt audit rides on the same retry path: two 429s then
    a hit, so the report names the vulnerability."""
    sleeper = patch_sleep(monkeypatch)
    client = FakeClient()
    client.script = [
        FakeResponse(status_code=429),
        FakeResponse(status_code=429, headers={"retry-after": "3"}),
        FakeResponse(payload={"vulns": VULNS}),
    ]

    class PatchedClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return client

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(sys.modules["httpx"], "AsyncClient", PatchedClient)
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")

    out = run(guardx.audit_dependencies(str(req)))
    assert "CVE-2024-1234" in out
    assert sleeper.waits == [1.0, 3.0]
    # the retried request kept the original payload
    assert all(payload["package"]["name"] == "requests" for _, payload in client.posts)
