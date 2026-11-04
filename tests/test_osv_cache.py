"""Unit tests for GuardX's per-run OSV response cache in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_osv_backoff.py`. The stub `FastMCP.tool()` returns the
decorated function unchanged, exactly like FastMCP 1.x does.
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

_STUB_SENTINEL = "__guardx_test_stubs_installed__"


def _install_stubs() -> None:
    if getattr(sys, _STUB_SENTINEL, False):
        return
    httpx = types.ModuleType("httpx")

    class RequestError(Exception):
        pass

    class AsyncClient:  # pragma: no cover - replaced by monkeypatching
        def __init__(self, *args, **kwargs):
            raise AssertionError("test must patch httpx.AsyncClient")

    httpx.RequestError = RequestError
    httpx.AsyncClient = AsyncClient
    sys.modules["httpx"] = httpx

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
    def __init__(self, payload: dict | None = None):
        self.status_code = 200
        self._payload = payload if payload is not None else {"vulns": []}
        self.headers = {}

    def json(self):
        return self._payload


class FakeClient:
    """Returns per-package vuln lists; records every POST for call counts."""

    def __init__(self, vulns_by_name=None):
        self.vulns_by_name = vulns_by_name or {}
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        if "queries" in json:
            # querybatch: one result per query, in query order.
            return FakeResponse(payload={"results": [
                {"vulns": self.vulns_by_name.get(q["package"]["name"], [])}
                for q in json["queries"]]})
        name = json["package"]["name"]
        return FakeResponse(payload={"vulns": self.vulns_by_name.get(name, [])})


def run(coro):
    return asyncio.run(coro)


def _audit(tmp_path, vulns_by_name, text):
    """Run audit_dependencies against a fake OSV client; return (report, client)."""
    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = FakeClient(vulns_by_name)

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text(text)
        return run(guardx.audit_dependencies(str(manifest))), PatchedClient.client
    finally:
        httpx_stub.AsyncClient = orig


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_dedupe_deps_keeps_first_seen_order():
    unique, hits = guardx._dedupe_deps(
        [("a", "1.0"), ("b", "2.0"), ("a", "1.0"), ("a", "1.1"), ("b", "2.0")]
    )
    assert unique == [("a", "1.0"), ("b", "2.0"), ("a", "1.1")]
    assert hits == 2


def test_dedupe_deps_no_duplicates():
    unique, hits = guardx._dedupe_deps([("a", "1.0"), ("b", "2.0")])
    assert unique == [("a", "1.0"), ("b", "2.0")]
    assert hits == 0


def test_duplicate_pin_queried_once_and_reported_once(tmp_path):
    vulns = {"requests": [{"id": "CVE-2024-1234", "summary": "test vuln"}]}
    out, client = _audit(
        tmp_path, vulns, "requests==2.28.0\nrequests==2.28.0\nurllib3==1.26.0\n"
    )
    assert len(client.posts) == 1  # one querybatch call for both deps
    assert [q["package"]["name"] for q in client.posts[0][1]["queries"]] == [
        "requests", "urllib3"]  # deduped: requests once, urllib3 once
    assert "Dependencies checked: 2" in out
    assert "OSV cache hits: 1" in out
    assert out.count("  [!] requests==2.28.0") == 1
    assert "Vulnerable packages: 1" in out


def test_same_name_different_version_queried_twice(tmp_path):
    out, client = _audit(
        tmp_path, {}, "requests==2.28.0\nrequests==2.31.0\n"
    )
    assert len(client.posts[0][1]["queries"]) == 2  # both versions, one batch
    assert "Dependencies checked: 2" in out
    assert "OSV cache hits" not in out
    assert "No known vulnerabilities found. [OK]" in out


def test_no_duplicates_no_cache_line(tmp_path):
    out, client = _audit(tmp_path, {}, "requests==2.28.0\nurllib3==1.26.0\n")
    assert len(client.posts) == 1  # one querybatch call for both deps
    assert len(client.posts[0][1]["queries"]) == 2
    assert "Dependencies checked: 2" in out
    assert "OSV cache hits" not in out
