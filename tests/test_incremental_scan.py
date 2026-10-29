"""Unit tests for GuardX's incremental `scan_secrets(since=...)` mode.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_scan_secrets.py`. Scans run against `tmp_path` fixtures —
including throwaway git repos created with the local git binary — so no
real target is ever touched. Secrets below are deliberately fake
formats the patterns recognise, never real credentials.
"""

from __future__ import annotations

import importlib.util
import json as jsonlib
import os
import subprocess
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

_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_incremental", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _init_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    _git("init", cwd=str(tmp_path))
    _git("config", "user.email", "test@example.com", cwd=str(tmp_path))
    _git("config", "user.name", "Test", cwd=str(tmp_path))
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    _git("add", ".", cwd=str(tmp_path))
    _git("commit", "-m", "initial", cwd=str(tmp_path))
    return tmp_path


def _secret_line(tag: str = "a") -> str:
    # Built by concatenation so this test file itself never holds a
    # literal full token string.
    return 'TOKEN = "ghp_' + tag * 36 + '"\n'


# ---------------------------------------------------------------------------
# Git-ref mode
# ---------------------------------------------------------------------------

def test_only_modified_file_scanned_since_head(tmp_path):
    repo = _init_repo(tmp_path, {
        "app.py": _secret_line("a"),
        "clean.py": 'print("hello")\n',
    })
    (repo / "app.py").write_text(_secret_line("a") + _secret_line("b"))
    report = server.scan_secrets(str(repo), since="HEAD")
    assert "Files scanned: 1" in report
    assert "Findings: 2" in report
    assert "Incremental scan: only files changed since HEAD" in report
    assert "clean.py" not in report


def test_nothing_changed_scans_nothing(tmp_path):
    repo = _init_repo(tmp_path, {"app.py": _secret_line("a")})
    report = server.scan_secrets(str(repo), since="HEAD")
    assert "Files scanned: 0" in report
    assert "No hardcoded secrets detected. [OK]" in report


def test_untracked_new_file_is_scanned(tmp_path):
    repo = _init_repo(tmp_path, {"clean.py": 'print("hello")\n'})
    (repo / "new.py").write_text(_secret_line("c"))
    report = server.scan_secrets(str(repo), since="HEAD")
    assert "Files scanned: 1" in report
    assert "[HIGH] GitHub Token" in report


def test_json_carries_since_value(tmp_path):
    repo = _init_repo(tmp_path, {"app.py": _secret_line("a")})
    (repo / "app.py").write_text(_secret_line("a") + _secret_line("b"))
    payload = jsonlib.loads(server.scan_secrets(str(repo), since="HEAD", json_output=True))
    assert payload["since"] == "HEAD"
    assert payload["files_scanned"] == 1
    assert payload["findings_count"] == 2


# ---------------------------------------------------------------------------
# Timestamp mode
# ---------------------------------------------------------------------------

def test_timestamp_mode_scans_only_newer_files(tmp_path):
    old = tmp_path / "old.py"
    old.write_text(_secret_line("d"))
    os.utime(old, (1577836800, 1577836800))  # 2020-01-01
    new = tmp_path / "new.py"
    new.write_text(_secret_line("e"))
    report = server.scan_secrets(str(tmp_path), since="2025-01-01")
    assert "Files scanned: 1" in report
    assert "new.py" in report
    assert "old.py" not in report


def test_date_falls_back_when_not_a_git_ref(tmp_path):
    # Inside a git repo, a date is not a ref, so timestamp mode applies
    # and both freshly written files are scanned.
    repo = _init_repo(tmp_path, {
        "a.py": _secret_line("f"),
        "b.py": _secret_line("g"),
    })
    report = server.scan_secrets(str(repo), since="2025-01-01")
    assert "Files scanned: 2" in report


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def test_invalid_since_is_an_error(tmp_path):
    (tmp_path / "app.py").write_text(_secret_line("h"))
    report = server.scan_secrets(str(tmp_path), since="not-a-ref-or-date")
    assert report.startswith("Error: since must be a git ref")
    payload = jsonlib.loads(
        server.scan_secrets(str(tmp_path), since="not-a-ref-or-date", json_output=True)
    )
    assert "since must be a git ref" in payload["error"]


def test_parse_since_timestamp_variants():
    assert server._parse_since_timestamp("2026-10-01") is not None
    assert server._parse_since_timestamp("2026-10-01T09:30:00Z") is not None
    assert server._parse_since_timestamp("1700000000") == 1700000000.0
    assert server._parse_since_timestamp("not-a-date") is None
    assert server._parse_since_timestamp("") is None
