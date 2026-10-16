"""Unit tests for GuardX's `check_pwned_password` tool.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic: prefix/suffix splitting,
response parsing, privacy guarantees, and error paths.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs
# ---------------------------------------------------------------------------

# Installed exactly once per pytest process (this file may share the process
# with other GuardX test modules): stub objects must be shared, otherwise a
# monkeypatch in one module misses the objects bound by another.
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
# Fake HIBP transport
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


class FakeClient:
    """Drop-in for httpx.AsyncClient used as `async with` + `.get()`."""

    seen = []  # class-level log of constructed clients

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.requests = []
        FakeClient.seen.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url: str) -> FakeResponse:
        self.requests.append(url)
        return self.handler(url)

    # tests set this per-case
    handler = staticmethod(lambda url: FakeResponse())


def patch_client(monkeypatch, handler):
    FakeClient.seen.clear()
    FakeClient.handler = staticmethod(handler)
    monkeypatch.setattr(sys.modules["httpx"], "AsyncClient", FakeClient)


def run(coro):
    return asyncio.run(coro)


def sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _breached_body(password: str, count: int) -> str:
    suffix = sha1_upper(password)[5:]
    return f"0018A45C4D1DEF81644B54AB7F969B88D65:1\n{suffix}:{count}\n"


def test_empty_password_is_rejected():
    out = run(guardx.check_pwned_password(""))
    assert out == "Error: empty password."


def test_breached_password_reports_count(monkeypatch):
    pw = "correct horse battery staple"
    patch_client(monkeypatch, lambda url: FakeResponse(text=_breached_body(pw, 2266543)))
    out = run(guardx.check_pwned_password(pw))
    assert "appeared in known breaches 2,266,543 times" in out
    assert "[!]" in out
    assert pw not in out  # password itself must never appear in output


def test_clean_password(monkeypatch):
    pw = "xkq-9Z!mV2#unique-enough"
    patch_client(monkeypatch, lambda url: FakeResponse(text="0018A45C4D1DEF81644B54AB7F969B88D65:1\n"))
    out = run(guardx.check_pwned_password(pw))
    assert "NOT found in any known breach" in out
    assert "[OK]" in out


def test_only_hash_prefix_is_transmitted(monkeypatch):
    pw = "s3cr3t-hunter2"
    captured = []

    def handler(url):
        captured.append(url)
        return FakeResponse(text="")

    patch_client(monkeypatch, handler)
    run(guardx.check_pwned_password(pw))

    assert len(captured) == 1
    url = captured[0]
    expected_prefix = sha1_upper(pw)[:5]
    assert url == guardx.HIBP_RANGE + expected_prefix
    assert pw not in url
    assert sha1_upper(pw) not in url  # full hash never leaves the machine


def test_suffix_match_is_case_insensitive(monkeypatch):
    pw = "MixedCase-Password"
    suffix = sha1_upper(pw)[5:].lower()  # API may return lowercase
    patch_client(monkeypatch, lambda url: FakeResponse(text=f"{suffix}:7\n"))
    out = run(guardx.check_pwned_password(pw))
    assert "appeared in known breaches 7 times" in out


def test_network_failure_reports_gracefully(monkeypatch):
    def handler(url):
        raise sys.modules["httpx"].RequestError("boom")

    patch_client(monkeypatch, handler)
    out = run(guardx.check_pwned_password("anything"))
    assert out.startswith("Error: could not reach HIBP")


def test_non_200_status_reports_http_code(monkeypatch):
    patch_client(monkeypatch, lambda url: FakeResponse(status_code=503))
    out = run(guardx.check_pwned_password("anything"))
    assert out == "HIBP returned HTTP 503."


def test_add_padding_header_is_sent(monkeypatch):
    patch_client(monkeypatch, lambda url: FakeResponse(text=""))
    run(guardx.check_pwned_password("anything"))
    client = FakeClient.seen[0]
    assert client.kwargs.get("headers", {}).get("Add-Padding") == "true"


def test_user_agent_identifies_guardx(monkeypatch):
    patch_client(monkeypatch, lambda url: FakeResponse(text=""))
    run(guardx.check_pwned_password("anything"))
    client = FakeClient.seen[0]
    assert client.kwargs.get("headers", {}).get("User-Agent") == guardx.USER_AGENT


def test_malformed_body_lines_are_ignored(monkeypatch):
    pw = "definitely-not-breached-zzz"
    body = "not-a-hash-line\n\n" + _breached_body("someone-else", 3)
    patch_client(monkeypatch, lambda url: FakeResponse(text=body))
    out = run(guardx.check_pwned_password(pw))
    assert "NOT found" in out
