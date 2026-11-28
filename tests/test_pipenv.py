"""Unit tests for GuardX's Pipenv support in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern
as `tests/test_lockfiles.py`. OSV queries are faked — no network is used.
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
_spec = importlib.util.spec_from_file_location("guardx_server_pipenv", REPO_ROOT / "server.py")
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
        if "queries" in json:
            # querybatch: one empty result per query, in query order.
            return FakeResponse(payload={"results": [
                {"vulns": []} for _ in json["queries"]]})
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
# Pipfile.lock
# ---------------------------------------------------------------------------

PIPFILE_LOCK = jsonlib.dumps({
    "_meta": {
        "hash": {"sha256": "deadbeef"},
        "pipfile-spec": 6,
        "requires": {"python_version": "3.11"},
        "sources": [{"url": "https://pypi.org/simple", "verify_ssl": True, "name": "pypi"}],
    },
    "default": {
        "requests": {"version": "==2.28.0", "hashes": ["sha256:abc"], "index": "pypi"},
        "flask": {"version": "==2.2.2"},
        "unpinned": {"version": "*"},
        "local-pkg": {"editable": True, "git": "https://github.com/example/pkg", "ref": "main"},
        "no-version": {"hashes": ["sha256:def"]},
    },
    "develop": {
        "pytest": {"version": "==7.2.0"},
        "requests": {"version": "==2.28.0"},  # same pin as default: deduped
    },
})


def test_pipfile_lock_default_and_develop_parsed():
    deps = dict(guardx._parse_pipfile_lock(PIPFILE_LOCK))
    assert deps == {
        "requests": "2.28.0",
        "flask": "2.2.2",
        "pytest": "7.2.0",
    }


def test_pipfile_lock_unpinned_editable_git_skipped():
    deps = dict(guardx._parse_pipfile_lock(PIPFILE_LOCK))
    assert "unpinned" not in deps  # "*" is not a pin
    assert "local-pkg" not in deps  # editable git install, no version
    assert "no-version" not in deps  # entry without a version field


def test_pipfile_lock_duplicate_pins_deduped():
    deps = list(guardx._parse_pipfile_lock(PIPFILE_LOCK))
    names = [n for n, _ in deps]
    assert names.count("requests") == 1
    assert len(deps) == len(set(deps))


def test_pipfile_lock_bad_json_yields_nothing():
    assert list(guardx._parse_pipfile_lock("{not json")) == []
    assert list(guardx._parse_pipfile_lock("[1, 2, 3]")) == []
    assert list(guardx._parse_pipfile_lock("")) == []


def test_pipfile_lock_missing_sections_yields_nothing():
    text = jsonlib.dumps({"_meta": {"hash": {"sha256": "deadbeef"}}})
    assert list(guardx._parse_pipfile_lock(text)) == []


def test_pipfile_lock_audit_queries_pypi(tmp_path):
    out, client = _audit(tmp_path, "Pipfile.lock", PIPFILE_LOCK)
    assert "Ecosystem: PyPI" in out
    assert "Dependencies checked: 3" in out
    by_name = {q["package"]["name"]: q["version"]
               for _, p in client.posts for q in p["queries"]}
    assert by_name == {
        "requests": "2.28.0",
        "flask": "2.2.2",
        "pytest": "7.2.0",
    }
    assert all(q["package"]["ecosystem"] == "PyPI"
               for _, p in client.posts for q in p["queries"])


# ---------------------------------------------------------------------------
# Pipfile
# ---------------------------------------------------------------------------

PIPFILE = """\
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "==2.28.0"
flask = {version = "==2.2.2", extras = ["dotenv"]}
toolz = {extras = ["x"], version = "==0.12.0"}  # version need not come first
django = "*"
my-pkg = {git = "https://github.com/example/pkg", ref = "main"}
local = {path = "./vendor/local", editable = true}

[dev-packages]
pytest = '==7.2.0'

[requires]
python_version = "3.11"

[scripts]
test = "pytest"
"""


def test_pipfile_string_pins_parsed():
    deps = dict(guardx._parse_pipfile(PIPFILE))
    assert deps["requests"] == "2.28.0"
    assert deps["pytest"] == "7.2.0"  # single quotes work too


def test_pipfile_table_pins_parsed():
    deps = dict(guardx._parse_pipfile(PIPFILE))
    assert deps["flask"] == "2.2.2"  # extras ignored, pin kept
    assert deps["toolz"] == "0.12.0"  # version after extras still found


def test_pipfile_unpinned_and_git_skipped():
    deps = dict(guardx._parse_pipfile(PIPFILE))
    assert "django" not in deps  # "*" is not a pin
    assert "my-pkg" not in deps  # git entry, no version
    assert "local" not in deps  # path/editable entry, no version


def test_pipfile_other_sections_ignored():
    # Only [packages] / [dev-packages] are read: [source], [requires]
    # and [scripts] entries must never surface as dependencies.
    deps = dict(guardx._parse_pipfile(PIPFILE))
    assert set(deps) == {"requests", "flask", "toolz", "pytest"}
    assert "test" not in deps
    assert "python_version" not in deps
    assert list(guardx._parse_pipfile("")) == []
    assert list(guardx._parse_pipfile("[packages]\n# nothing pinned\n")) == []


def test_pipfile_audit_queries_pypi(tmp_path):
    out, client = _audit(tmp_path, "Pipfile", PIPFILE)
    assert "Ecosystem: PyPI" in out
    assert "Dependencies checked: 4" in out
    by_name = {q["package"]["name"]: q["version"]
               for _, p in client.posts for q in p["queries"]}
    assert by_name == {
        "requests": "2.28.0",
        "flask": "2.2.2",
        "toolz": "0.12.0",
        "pytest": "7.2.0",
    }


def test_pipfile_lock_empty_reports_cleanly(tmp_path):
    text = jsonlib.dumps({"default": {}, "develop": {}})
    out, _ = _audit(tmp_path, "Pipfile.lock", text)
    assert "No pinned dependencies found" in out


def test_unsupported_manifest_message_lists_pipenv(tmp_path):
    manifest = tmp_path / "Gemfile"
    manifest.write_text("gem 'rails'\n")
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "Pipfile.lock" in out
    assert "Pipfile" in out
