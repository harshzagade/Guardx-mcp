"""Unit tests for GuardX's in-memory HIBP prefix cache.

Successful HIBP range responses are cached per hash prefix for
`HIBP_CACHE_TTL_SECONDS`, so repeated checks of passwords sharing a
prefix skip the network entirely until the entry expires. Error
responses are never cached.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, exactly like the other
GuardX test modules.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import sys
import time
import types
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module stubs (shared, installed once per pytest process)
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
# Fake HIBP transport
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


class FakeClient:
    """Drop-in for httpx.AsyncClient used as `async with` + `.get()`."""

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.requests = []

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
    FakeClient.handler = staticmethod(handler)
    monkeypatch.setattr(sys.modules["httpx"], "AsyncClient", FakeClient)


def run(coro):
    return asyncio.run(coro)


def sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def _breached_body(password: str, count: int) -> str:
    suffix = sha1_upper(password)[5:]
    return f"0018A45C4D1DEF81644B54AB7F969B88D65:1\n{suffix}:{count}\n"


@pytest.fixture(autouse=True)
def _clear_cache():
    guardx._HIBP_PREFIX_CACHE.clear()
    yield
    guardx._HIBP_PREFIX_CACHE.clear()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_repeated_check_uses_cache(monkeypatch):
    pw = "correct horse battery staple"
    calls = {"n": 0}

    def handler(url):
        calls["n"] += 1
        return FakeResponse(text=_breached_body(pw, 2266543))

    patch_client(monkeypatch, handler)
    first = run(guardx.check_pwned_password(pw))
    second = run(guardx.check_pwned_password(pw))
    assert first == second
    assert "2,266,543 times" in first
    assert calls["n"] == 1  # second check served from cache, no network


def test_distinct_prefixes_each_fetched_once(monkeypatch):
    calls = {"n": 0}

    def handler(url):
        calls["n"] += 1
        return FakeResponse(text="0018A45C4D1DEF81644B54AB7F969B88D65:1\n")

    patch_client(monkeypatch, handler)
    run(guardx.check_pwned_password("first-password-abc"))
    run(guardx.check_pwned_password("second-password-xyz"))
    assert calls["n"] == 2


def test_preseeded_fresh_entry_is_honoured(monkeypatch):
    pw = "cached-password-example"
    sha1 = sha1_upper(pw)
    guardx._HIBP_PREFIX_CACHE[sha1[:5]] = (
        time.monotonic() + 300, {sha1[5:]: 42})

    def handler(url):
        raise AssertionError("cache hit must not reach the network")

    patch_client(monkeypatch, handler)
    out = run(guardx.check_pwned_password(pw))
    assert "appeared in known breaches 42 times" in out


def test_expired_entry_is_refetched(monkeypatch):
    pw = "expired-cache-password"
    sha1 = sha1_upper(pw)
    # Stale entry claims a different count; a refetch must replace it.
    guardx._HIBP_PREFIX_CACHE[sha1[:5]] = (
        time.monotonic() - 1, {sha1[5:]: 999})
    calls = {"n": 0}

    def handler(url):
        calls["n"] += 1
        return FakeResponse(text=_breached_body(pw, 3))

    patch_client(monkeypatch, handler)
    out = run(guardx.check_pwned_password(pw))
    assert "appeared in known breaches 3 times" in out
    assert calls["n"] == 1
    # The fresh entry replaced the stale one in the cache.
    assert guardx._HIBP_PREFIX_CACHE[sha1[:5]][1][sha1[5:]] == 3


def test_error_response_is_not_cached(monkeypatch):
    calls = {"n": 0}

    def handler(url):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(status_code=503)
        return FakeResponse(text="")

    patch_client(monkeypatch, handler)
    first = run(guardx.check_pwned_password("flaky-hibp-password"))
    assert first == "HIBP returned HTTP 503."
    second = run(guardx.check_pwned_password("flaky-hibp-password"))
    assert "NOT found in any known breach" in second
    assert calls["n"] == 2  # the 503 was not cached, so it refetched


def test_batch_result_is_reused_by_later_call(monkeypatch):
    pw = "batch-then-single-password"
    calls = {"n": 0}

    def handler(url):
        calls["n"] += 1
        return FakeResponse(text=_breached_body(pw, 5))

    patch_client(monkeypatch, handler)
    out = run(guardx.check_pwned_passwords([pw]))
    assert "Password 1: WARNING" in out
    assert "5 times" in out
    single = run(guardx.check_pwned_password(pw))
    assert "appeared in known breaches 5 times" in single
    assert calls["n"] == 1  # the batch's lookup served the single check
