"""Unit tests for GuardX's OSV querybatch support in
`audit_dependencies`: all distinct dependencies are queried in a
single `POST /v1/querybatch` call instead of one query per package,
with results aligned to queries by position.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic. No real OSV endpoint is
ever touched — the HTTP client is faked throughout.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path


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

_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_querybatch",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def run(coro):
    return asyncio.run(coro)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"results": []}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, script=None):
        self.script = list(script or [])
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        item = self.script.pop(0) if self.script else FakeResponse()
        if isinstance(item, Exception):
            raise item
        return item

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _audit(tmp_path, text, client):
    """Run audit_dependencies with `client` as the HTTP client."""
    class PatchedClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return client

        async def __aexit__(self, *exc):
            return False

    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text(text)
        return run(server.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig


class TestQuerybatch:
    def test_single_batch_call_for_many_deps(self, tmp_path):
        client = FakeClient([FakeResponse(payload={"results": [
            {"vulns": [{"id": "CVE-2024-1", "summary": "a"}]},
            {},
            {"vulns": []},
        ]})])
        out = _audit(tmp_path,
                     "requests==2.28.0\nurllib3==1.26.0\nclick==8.1.0\n",
                     client)
        assert len(client.posts) == 1
        url, payload = client.posts[0]
        assert url == "https://api.osv.dev/v1/querybatch"
        assert payload == {"queries": [
            {"version": "2.28.0",
             "package": {"name": "requests", "ecosystem": "PyPI"}},
            {"version": "1.26.0",
             "package": {"name": "urllib3", "ecosystem": "PyPI"}},
            {"version": "8.1.0",
             "package": {"name": "click", "ecosystem": "PyPI"}},
        ]}
        # Results align by position: requests vulnerable, urllib3 clean
        # (entry without a vulns key), click clean.
        assert "CVE-2024-1" in out
        assert "Vulnerable packages: 1" in out
        assert "Dependencies checked: 3" in out

    def test_batch_429_retries_then_succeeds(self, tmp_path, monkeypatch):
        waits = []

        async def fake_sleep(seconds):
            waits.append(seconds)

        monkeypatch.setattr(sys.modules["asyncio"], "sleep", fake_sleep)
        client = FakeClient([
            FakeResponse(status_code=429, headers={"retry-after": "2"}),
            FakeResponse(payload={"results": [
                {"vulns": [{"id": "CVE-2024-9", "summary": "b"}]}]}),
        ])
        out = _audit(tmp_path, "requests==2.28.0\n", client)
        assert "CVE-2024-9" in out
        assert waits == [2.0]
        assert len(client.posts) == 2  # one retry of the whole batch

    def test_batch_non_429_failure_counts_as_lookup_failure(self, tmp_path):
        client = FakeClient([FakeResponse(status_code=500)])
        out = _audit(tmp_path, "requests==2.28.0\nurllib3==1.26.0\n", client)
        assert "Lookups failed (network): 2" in out
        # Neither package is claimed clean: the header carries the
        # failure count instead of a clean verdict.

    def test_batch_network_error_counts_as_lookup_failure(self, tmp_path):
        # Raise the stub httpx module's RequestError, as server.py sees it.
        client = FakeClient([sys.modules["httpx"].RequestError("boom")])
        out = _audit(tmp_path, "requests==2.28.0\n", client)
        assert "Lookups failed (network): 1" in out

    def test_truncated_results_tail_is_a_lookup_failure(self, tmp_path):
        # Only one result for two queries: the second dep must not
        # read as clean.
        client = FakeClient([FakeResponse(payload={"results": [
            {"vulns": []}]} )])
        out = _audit(tmp_path, "requests==2.28.0\nurllib3==1.26.0\n", client)
        assert "Lookups failed (network): 1" in out

    def test_querybatch_helper_aligns_by_position(self, tmp_path):
        client = FakeClient([FakeResponse(payload={"results": [
            {"vulns": [{"id": "CVE-X"}]}, {"vulns": []}]})])
        results = run(server._osv_querybatch(
            client, [("a", "1.0"), ("b", "2.0")], "PyPI"))
        assert results == [("a", "1.0", [{"id": "CVE-X"}]), ("b", "2.0", [])]
