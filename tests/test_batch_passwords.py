"""Unit tests for GuardX's `check_pwned_passwords` batch tool.

Same stub setup as `test_pwned_password.py`: `mcp` and `httpx` are not
installed in this environment, so both modules are stubbed in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, so these tests exercise the
real batch logic: prefix grouping, per-password summary lines, and
the guarantee that no password ever appears in the output.
"""

from __future__ import annotations

import asyncio
import hashlib
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
                return fn
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


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


class FakeClient:
    seen = []

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

    handler = staticmethod(lambda url: FakeResponse())


def patch_client(monkeypatch, handler):
    FakeClient.seen.clear()
    FakeClient.handler = staticmethod(handler)
    monkeypatch.setattr(sys.modules["httpx"], "AsyncClient", FakeClient)


def run(coro):
    return asyncio.run(coro)


def sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def _breached_body(password: str, count: int) -> str:
    suffix = sha1_upper(password)[5:]
    return f"0018A45C4D1DEF81644B54AB7F969B88D65:1\n{suffix}:{count}\n"


def test_empty_list_is_rejected():
    assert run(guardx.check_pwned_passwords([])) == "Error: no passwords given."


def test_one_line_per_password_in_input_order(monkeypatch):
    breached = "correct horse battery staple"
    clean = "xkq-9Z!mV2#unique-enough"

    def handler(url):
        if url.endswith(sha1_upper(breached)[:5]):
            return FakeResponse(text=_breached_body(breached, 42))
        return FakeResponse(text="")

    patch_client(monkeypatch, handler)
    out = run(guardx.check_pwned_passwords([breached, clean]))
    lines = out.splitlines()
    assert lines[0] == "Password breach check: 2 checked (1 breached, 1 clean, 0 errors)"
    assert lines[1].startswith("Password 1: WARNING")
    assert "42 times" in lines[1]
    assert lines[2] == "Password 2: NOT found in any known breach. [OK]"
    assert breached not in out and clean not in out


def test_shared_prefix_is_queried_once(monkeypatch):
    # Two passwords whose SHA-1 hashes share a 5-char prefix are hard to
    # construct on demand, so duplicate passwords prove the same point:
    # identical hashes share a prefix, and the batch must fetch it once.
    pw = "same-password-twice"
    patch_client(monkeypatch, lambda url: FakeResponse(text=_breached_body(pw, 5)))
    out = run(guardx.check_pwned_passwords([pw, pw]))
    assert len(FakeClient.seen[0].requests) == 1
    assert out.splitlines()[1].startswith("Password 1: WARNING")
    assert out.splitlines()[2].startswith("Password 2: WARNING")


def test_empty_entry_gets_error_line_without_request(monkeypatch):
    patch_client(monkeypatch, lambda url: FakeResponse(text=""))
    out = run(guardx.check_pwned_passwords(["", "some-clean-password"]))
    lines = out.splitlines()
    assert lines[1] == "Password 1: Error: empty password."
    assert lines[2].endswith("[OK]")
    assert len(FakeClient.seen[0].requests) == 1  # only the non-empty entry


def test_prefix_failure_affects_only_its_lines(monkeypatch):
    bad = "network-down-password"
    good = "clean-password-here"

    def handler(url):
        if url.endswith(sha1_upper(bad)[:5]):
            raise sys.modules["httpx"].RequestError("down")
        return FakeResponse(text="")

    monkeypatch.setattr(guardx.random, "uniform", lambda a, b: 0.0)
    patch_client(monkeypatch, handler)
    out = run(guardx.check_pwned_passwords([bad, good]))
    lines = out.splitlines()
    assert lines[0] == "Password breach check: 2 checked (0 breached, 1 clean, 1 errors)"
    assert lines[1].startswith("Password 1: Error: could not reach HIBP")
    assert lines[2].endswith("[OK]")


def test_non_200_status_reported_per_line(monkeypatch):
    patch_client(monkeypatch, lambda url: FakeResponse(status_code=503))
    out = run(guardx.check_pwned_passwords(["anything"]))
    assert "Password 1: HIBP returned HTTP 503." in out
    assert "0 breached, 0 clean, 1 errors" in out
