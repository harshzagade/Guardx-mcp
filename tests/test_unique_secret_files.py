"""Unit tests for the unique-secret file listing in `scan_secrets`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic. Scans run against `tmp_path`
fixtures — no real target is ever touched.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs (same shape as tests/test_scan_secrets.py)
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

# Load under a module name unique to this file so re-executing server.py
# cannot clobber another test module's copy in sys.modules.
_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_unique_files",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path, name, content):
    fp = tmp_path / name
    fp.write_text(content, encoding="utf-8")
    return str(fp)


# ---------------------------------------------------------------------------
# Unique-secret file listing
# ---------------------------------------------------------------------------

class TestUniqueSecretFiles:
    def test_same_secret_lists_both_files(self, tmp_path):
        secret = "ghp_" + "e" * 36
        a = _write(tmp_path, "a.py", f'TOKEN = "{secret}"\n')
        b = _write(tmp_path, "b.py", f'API_KEY = "{secret}"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Unique secrets by file:" in report
        block = report.split("Unique secrets by file:")[1].split("\n\n")[0]
        lines = [ln.strip() for ln in block.strip().splitlines()]
        assert len(lines) == 1
        assert server._mask(secret) in lines[0]
        assert "[HIGH GitHub Token]" in lines[0]
        assert a in lines[0] and b in lines[0]
        assert "(2 findings)" in lines[0]
        # The raw secret never appears in the listing.
        assert secret not in report

    def test_most_copied_secret_listed_first(self, tmp_path):
        shared = "ghp_" + "a" * 36
        lone = "ghp_" + "b" * 36
        _write(tmp_path, "a.py", f'A = "{shared}"\n')
        _write(tmp_path, "b.py", f'B = "{shared}"\n')
        _write(tmp_path, "c.py", f'C = "{lone}"\n')
        report = server.scan_secrets(str(tmp_path))
        block = report.split("Unique secrets by file:")[1].split("\n\n")[0]
        lines = [ln.strip() for ln in block.strip().splitlines()]
        assert len(lines) == 2
        assert server._mask(shared) in lines[0]
        assert "(2 findings)" in lines[0]
        assert server._mask(lone) in lines[1]
        assert "(1 finding)" in lines[1]

    def test_same_secret_twice_in_one_file_lists_file_once(self, tmp_path):
        secret = "ghp_" + "f" * 36
        fp = _write(
            tmp_path, "a.py",
            f'TOKEN = "{secret}"\nKEY = "{secret}"\n',
        )
        report = server.scan_secrets(str(tmp_path))
        block = report.split("Unique secrets by file:")[1].split("\n\n")[0]
        lines = [ln.strip() for ln in block.strip().splitlines()]
        assert len(lines) == 1
        assert lines[0].count(fp) == 1
        assert "(2 findings)" in lines[0]

    def test_identical_masks_still_list_separately(self, tmp_path):
        # Two secrets sharing first 4 / last 2 chars (and length) mask
        # identically; the listing must keep them apart.
        s1 = "ghp_" + "a" * 34 + "ZZ"
        s2 = "ghp_" + "b" * 34 + "ZZ"
        assert server._mask(s1) == server._mask(s2)
        _write(tmp_path, "a.py", f'A = "{s1}"\n')
        _write(tmp_path, "b.py", f'B = "{s2}"\n')
        report = server.scan_secrets(str(tmp_path))
        block = report.split("Unique secrets by file:")[1].split("\n\n")[0]
        lines = [ln.strip() for ln in block.strip().splitlines()]
        assert len(lines) == 2

    def test_clean_scan_has_no_listing_block(self, tmp_path):
        fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
        report = server.scan_secrets(fp)
        assert "Unique secrets by file:" not in report

    def test_json_carries_unique_secret_files(self, tmp_path):
        import json as jsonlib
        secret = "ghp_" + "2" * 36
        a = _write(tmp_path, "a.py", f'A = "{secret}"\n')
        b = _write(tmp_path, "b.py", f'B = "{secret}"\n')
        payload = jsonlib.loads(
            server.scan_secrets(str(tmp_path), json_output=True)
        )
        assert payload["unique_secret_files"] == [{
            "match": server._mask(secret),
            "type": "GitHub Token",
            "severity": "HIGH",
            "files": sorted([a, b]),
            "findings": 2,
        }]
        assert secret not in jsonlib.dumps(payload)

    def test_json_clean_scan_listing_is_empty(self, tmp_path):
        import json as jsonlib
        fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
        payload = jsonlib.loads(server.scan_secrets(fp, json_output=True))
        assert payload["unique_secret_files"] == []
