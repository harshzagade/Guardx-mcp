"""Unit tests for `requirements.txt` extras/markers parsing in
`audit_dependencies`.

A pinned dep with extras (`requests[security]==2.28.0`) or an
environment marker (`package==1.0; python_version > "3.8"`) is a real
pinned dependency — the strict `==` regex used to skip both lines
entirely, so the package was never audited. The parser tests cover the
stripping directly; the audit test proves the lines reach OSV's
querybatch with the bare name and pinned version.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs (same pattern as tests/test_scan_secrets.py)
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

_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_req_extras",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
guardx = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guardx)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_extras_stripped_from_name():
    assert list(guardx._parse_requirements("requests[security]==2.28.0\n")) == [
        ("requests", "2.28.0")
    ]


def test_extras_with_space_and_multiple_names():
    assert list(guardx._parse_requirements("requests [security, socks]==2.31.0\n")) == [
        ("requests", "2.31.0")
    ]


def test_environment_marker_stripped():
    assert list(guardx._parse_requirements(
        'package==1.0; python_version > "3.8"\n')) == [("package", "1.0")]


def test_marker_without_spaces():
    assert list(guardx._parse_requirements(
        "package==1.0;python_version<'3.12'\n")) == [("package", "1.0")]


def test_extras_and_marker_together():
    assert list(guardx._parse_requirements(
        'requests[security]==2.28.0; sys_platform == "linux"\n')) == [
        ("requests", "2.28.0")
    ]


def test_plain_pin_unchanged():
    assert list(guardx._parse_requirements("flask==3.0.0\n")) == [
        ("flask", "3.0.0")
    ]


def test_extras_without_pin_still_skipped():
    assert list(guardx._parse_requirements("requests[security]\n")) == []


def test_range_and_bare_names_still_skipped():
    text = "django>=4.0\nnumpy\nrequests[security]>=2.28.0\n"
    assert list(guardx._parse_requirements(text)) == []


def test_options_and_includes_still_skipped():
    text = "-r base.txt\n--index-url https://example.com/simple\n"
    assert list(guardx._parse_requirements(text)) == []


def test_comment_after_extras_pin():
    assert list(guardx._parse_requirements(
        "requests[security]==2.28.0  # pinned for CVE-2023-32681\n")) == [
        ("requests", "2.28.0")
    ]


# ---------------------------------------------------------------------------
# Audit-level test: extras/marker lines actually reach OSV
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload=None):
        self.status_code = 200
        self._payload = payload if payload is not None else {"vulns": []}
        self.headers = {}

    def json(self):
        return self._payload


class FakeClient:
    """Records every POST; answers querybatch with no vulns."""

    def __init__(self):
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        return FakeResponse(payload={"results": [
            {"vulns": []} for _ in json.get("queries", [])]})


def run(coro):
    return asyncio.run(coro)


def test_extras_and_marker_lines_are_audited(tmp_path):
    text = (
        'requests[security]==2.28.0\n'
        'package==1.0; python_version > "3.8"\n'
        'flask==3.0.0\n'
    )
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(text)

    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = FakeClient()

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig

    client = PatchedClient.client
    assert len(client.posts) == 1
    queried = [(q["package"]["name"], q["version"])
               for q in client.posts[0][1]["queries"]]
    assert queried == [("requests", "2.28.0"), ("package", "1.0"),
                       ("flask", "3.0.0")]
    assert "Dependencies checked: 3" in out
