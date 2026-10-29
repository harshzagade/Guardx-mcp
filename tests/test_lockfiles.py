"""Unit tests for GuardX's lockfile support in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern
as `tests/test_go_mod.py`. OSV queries are faked — no network is used.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json as jsonlib
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
_spec = importlib.util.spec_from_file_location("guardx_server_lockfiles", REPO_ROOT / "server.py")
assert _spec and _spec.loader
guardx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guardx)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload=None):
        self.status_code = 200
        self._payload = payload if payload is not None else {"vulns": []}
        self.headers = {}

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        return FakeResponse()


def _audit(tmp_path, filename: str, text: str):
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
        manifest = tmp_path / filename
        manifest.write_text(text)
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    return out, PatchedClient.client


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------

PACKAGE_LOCK = jsonlib.dumps({
    "name": "demo",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/express": {"version": "4.18.2"},
        "node_modules/@scope/pkg": {"version": "2.0.1"},
        "node_modules/express/node_modules/debug": {"version": "4.3.4"},
        "node_modules/no-version": {},
    },
    "dependencies": {
        "express": {"version": "4.18.2", "dependencies": {"debug": {"version": "4.3.4"}}},
    },
})


def test_package_lock_packages_map_parsed():
    deps = dict(guardx._parse_package_lock(PACKAGE_LOCK))
    assert deps == {
        "express": "4.18.2",
        "@scope/pkg": "2.0.1",
        "debug": "4.3.4",
    }


def test_package_lock_root_and_versionless_skipped():
    deps = list(guardx._parse_package_lock(PACKAGE_LOCK))
    names = [n for n, _ in deps]
    assert "demo" not in names  # root "" entry is the project itself
    assert "no-version" not in names
    assert len(deps) == len(set(deps))  # v2+v3 duplicate maps deduped


def test_package_lock_v1_legacy_tree_parsed():
    text = jsonlib.dumps({
        "dependencies": {
            "lodash": {"version": "4.17.20",
                       "dependencies": {"chalk": {"version": "2.4.2"}}},
        },
    })
    assert dict(guardx._parse_package_lock(text)) == {
        "lodash": "4.17.20", "chalk": "2.4.2",
    }


def test_package_lock_bad_json_yields_nothing():
    assert list(guardx._parse_package_lock("{not json")) == []


def test_package_lock_audit_queries_npm(tmp_path):
    out, client = _audit(tmp_path, "package-lock.json", PACKAGE_LOCK)
    assert "Ecosystem: npm" in out
    assert "Dependencies checked: 3" in out
    by_name = {p["package"]["name"]: p["version"]
               for _, p in client.posts}
    assert by_name["@scope/pkg"] == "2.0.1"
    assert all(p["package"]["ecosystem"] == "npm" for _, p in client.posts)


# ---------------------------------------------------------------------------
# poetry.lock / Cargo.lock (shared TOML parser)
# ---------------------------------------------------------------------------

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.28.0"
description = "Python HTTP for Humans."

[package.dependencies]
urllib3 = ">=1.21.1,<1.27"

[[package]]
name = "urllib3"
version = "1.26.0"
description = "HTTP client."

[[metadata]]
lock-version = "2.0"
"""

CARGO_LOCK = """\
[[package]]
name = "serde"
version = "1.0.163"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "serde_derive"
version = "1.0.163"
dependencies = [
 "proc-macro2",
 "quote",
 "serde",
 "syn",
]

[[metadata]]
"checksum serde 1.0.163 (registry+https://github.com/rust-lang/crates.io-index)" = "abc123"
"""


def test_poetry_lock_parsed_and_subtables_ignored():
    assert list(guardx._parse_toml_lock(POETRY_LOCK)) == [
        ("requests", "2.28.0"), ("urllib3", "1.26.0"),
    ]


def test_cargo_lock_parsed_and_dependency_lists_ignored():
    assert list(guardx._parse_toml_lock(CARGO_LOCK)) == [
        ("serde", "1.0.163"), ("serde_derive", "1.0.163"),
    ]


def test_toml_lock_empty_yields_nothing():
    assert list(guardx._parse_toml_lock("")) == []
    assert list(guardx._parse_toml_lock("[metadata]\nlock-version = \"2.0\"\n")) == []


def test_poetry_lock_audit_queries_pypi(tmp_path):
    out, client = _audit(tmp_path, "poetry.lock", POETRY_LOCK)
    assert "Ecosystem: PyPI" in out
    assert "Dependencies checked: 2" in out
    assert all(p["package"]["ecosystem"] == "PyPI" for _, p in client.posts)


def test_cargo_lock_audit_queries_crates_io(tmp_path):
    out, client = _audit(tmp_path, "Cargo.lock", CARGO_LOCK)
    assert "Ecosystem: crates.io" in out
    assert "Dependencies checked: 2" in out
    by_name = {p["package"]["name"]: p["version"] for _, p in client.posts}
    assert by_name["serde_derive"] == "1.0.163"


def test_empty_lock_reports_cleanly(tmp_path):
    out, _ = _audit(tmp_path, "poetry.lock", "")
    assert "No pinned dependencies found" in out


def test_unsupported_manifest_message_lists_lockfiles(tmp_path):
    manifest = tmp_path / "Gemfile"
    manifest.write_text("gem 'rails'\n")
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "package-lock.json" in out
    assert "poetry.lock" in out
    assert "Cargo.lock" in out
