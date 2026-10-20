"""Unit tests for GuardX's `go.mod` support in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_pwned_password.py`. The stub `FastMCP.tool()` returns the
decorated function unchanged, exactly like FastMCP 1.x does, so these
tests exercise the real parsing and tool logic.
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


def run(coro):
    return asyncio.run(coro)


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
    """Drop-in for httpx.AsyncClient; records OSV payloads per package."""

    def __init__(self, *args, **kwargs):
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        return FakeResponse()


GO_MOD = """\
module example.com/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/crypto v0.17.0 // indirect
)

require golang.org/x/net v0.20.0

replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.0

retract v1.0.0

exclude example.com/old v1.0.0
"""


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_block_and_single_line_requires_parsed():
    deps = dict(guardx._parse_go_mod(GO_MOD))
    assert deps == {
        "github.com/gin-gonic/gin": "v1.9.1",
        "golang.org/x/crypto": "v0.17.0",
        "golang.org/x/net": "v0.20.0",
    }


def test_indirect_comment_stripped():
    deps = dict(guardx._parse_go_mod("require (\n\tgolang.org/x/text v0.14.0 // indirect\n)\n"))
    assert deps == {"golang.org/x/text": "v0.14.0"}


def test_non_require_directives_ignored():
    text = "module example.com/x\n\ngo 1.21\n\nreplace a.com/b => a.com/b v1.0.0\nretract v0.9.0\nexclude a.com/c v1.0.0\n"
    assert list(guardx._parse_go_mod(text)) == []


def test_empty_file_yields_nothing():
    assert list(guardx._parse_go_mod("")) == []


def test_version_keeps_v_prefix():
    deps = list(guardx._parse_go_mod("require example.com/mod v2.1.0+incompatible\n"))
    assert deps == [("example.com/mod", "v2.1.0+incompatible")]


# ---------------------------------------------------------------------------
# Tool wiring tests
# ---------------------------------------------------------------------------

def _audit(tmp_path, filename: str, text: str) -> tuple[str, FakeClient]:
    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = FakeClient()

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    import pytest
    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / filename
        manifest.write_text(text)
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    return out, PatchedClient.client


def test_go_mod_audit_queries_go_ecosystem(tmp_path):
    out, client = _audit(tmp_path, "go.mod", GO_MOD)
    assert "Ecosystem: Go" in out
    assert "Dependencies checked: 3" in out
    payloads = [p for _, p in client.posts]
    assert all(p["package"]["ecosystem"] == "Go" for p in payloads)
    by_name = {p["package"]["name"]: p["version"] for p in payloads}
    assert by_name["github.com/gin-gonic/gin"] == "v1.9.1"
    assert by_name["golang.org/x/net"] == "v0.20.0"
    assert "No known vulnerabilities found. [OK]" in out


def test_go_mod_vuln_reported(tmp_path):
    class VulnClient(FakeClient):
        async def post(self, url: str, json: dict):
            self.posts.append((url, json))
            vulns = [{"id": "GO-2024-1234", "summary": "test go vuln"}] \
                if json["package"]["name"] == "golang.org/x/crypto" else []
            return FakeResponse(payload={"vulns": vulns})

    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = VulnClient()

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / "go.mod"
        manifest.write_text(GO_MOD)
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    assert "golang.org/x/crypto==v0.17.0" in out
    assert "GO-2024-1234" in out
    assert "Vulnerable packages: 1" in out


def test_go_mod_without_requires_reports_cleanly(tmp_path):
    out, _ = _audit(tmp_path, "go.mod", "module example.com/empty\n\ngo 1.21\n")
    assert "No pinned dependencies found" in out


def test_unsupported_manifest_message_lists_go_mod(tmp_path):
    manifest = tmp_path / "Gemfile"
    manifest.write_text("gem 'rails'\n")
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "go.mod" in out
