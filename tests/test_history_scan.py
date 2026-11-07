"""Unit tests for GuardX's git-history `scan_secrets(history=True)` mode.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_incremental_scan.py`. Scans run against throwaway git repos
created with the local git binary in `tmp_path`, so no real target is
ever touched. Secrets below are deliberately fake formats the patterns
recognise, never real credentials.
"""

from __future__ import annotations

import importlib.util
import json as jsonlib
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
# Throwaway git repos
# ---------------------------------------------------------------------------

def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


def _init_repo(tmp_path: Path) -> Path:
    _git("init", cwd=str(tmp_path))
    _git("config", "user.email", "test@example.com", cwd=str(tmp_path))
    _git("config", "user.name", "Test", cwd=str(tmp_path))
    return tmp_path


def _commit(repo: Path, message: str) -> str:
    _git("add", "-A", cwd=str(repo))
    _git("commit", "-q", "-m", message, cwd=str(repo))
    return _git("rev-parse", "--short", "HEAD", cwd=str(repo)).stdout.strip()


def _secret_line(tag: str = "a") -> str:
    # Built by concatenation so this test file itself never holds a
    # literal full token string.
    return 'TOKEN = "ghp_' + tag * 36 + '"\n'


# ---------------------------------------------------------------------------
# History mode
# ---------------------------------------------------------------------------

def test_history_finds_secret_removed_from_head(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text(_secret_line("a") + 'print("hello")\n')
    first = _commit(repo, "add token")
    (repo / "app.py").write_text('print("hello")\n')
    _commit(repo, "remove token")

    # The working tree is clean now — a plain scan sees nothing.
    assert "No hardcoded secrets detected" in guardx.scan_secrets(str(repo))

    out = guardx.scan_secrets(str(repo), history=True)
    assert "git history" in out
    assert "2 commit(s) scanned" in out
    assert "Findings: 1" in out
    assert "GitHub" in out or "TOKEN" in out or "Personal Access Token" in out
    assert f"(commit {first})" in out
    assert "rewritten" in out  # history note: removing from HEAD is not enough


def test_history_attributes_finding_to_the_right_commit(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "old.py").write_text(_secret_line("a"))
    first = _commit(repo, "old secret")
    (repo / "new.py").write_text('print("clean")\n')
    second = _commit(repo, "clean file")

    out = guardx.scan_secrets(str(repo), history=True)
    assert "Findings: 1" in out
    assert f"(commit {first})" in out
    assert f"(commit {second})" not in out
    assert "old.py" in out


def test_history_clean_repo_reports_no_findings(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text('print("hello")\n')
    _commit(repo, "initial")
    out = guardx.scan_secrets(str(repo), history=True)
    assert "No hardcoded secrets detected" in out
    assert "1 commit(s) scanned" in out


def test_history_requires_git_repo(tmp_path):
    (tmp_path / "app.py").write_text(_secret_line("a"))
    out = guardx.scan_secrets(str(tmp_path), history=True)
    assert out.startswith("Error: history scan needs a git repository")


def test_history_and_since_conflict(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text('print("hello")\n')
    _commit(repo, "initial")
    out = guardx.scan_secrets(str(repo), history=True, since="HEAD~1")
    assert out.startswith("Error: history and since cannot be combined")


def test_history_json_carries_commits_and_commit_per_finding(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text(_secret_line("b"))
    first = _commit(repo, "add token")
    (repo / "app.py").write_text('print("hello")\n')
    _commit(repo, "remove token")

    out = guardx.scan_secrets(str(repo), history=True, json_output=True)
    report = jsonlib.loads(out)
    assert report["history"] == {"commits_scanned": 2, "truncated": False}
    assert report["findings_count"] == 1
    assert report["findings"][0]["commit"] == first
    assert report["files_scanned"] == 1


def test_history_truncation_is_reported(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text(_secret_line("c"))
    _commit(repo, "add token")
    (repo / "app.py").write_text('print("hello")\n')
    _commit(repo, "remove token")

    monkeypatch.setattr(guardx, "MAX_HISTORY_COMMITS", 1)
    out = guardx.scan_secrets(str(repo), history=True)
    assert "1 commit(s) scanned" in out
    assert "limited to the 1 most recent" in out
    # The newest commit removed the token, so the truncated scan is clean.
    assert "No hardcoded secrets detected" in out


def test_history_respects_exclude(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "key.pem").write_text(_secret_line("d"))
    _commit(repo, "add key")
    (repo / "key.pem").write_text("clean\n")
    _commit(repo, "remove key")

    out = guardx.scan_secrets(str(repo), history=True, exclude="*.pem")
    assert "No hardcoded secrets detected" in out


def test_history_single_file_path(tmp_path):
    repo = _init_repo(tmp_path)
    target = repo / "app.py"
    target.write_text(_secret_line("e"))
    first = _commit(repo, "add token")
    target.write_text('print("hello")\n')
    _commit(repo, "remove token")

    out = guardx.scan_secrets(str(target), history=True)
    assert "Findings: 1" in out
    assert f"(commit {first})" in out


def test_history_finds_secrets_across_files_and_commits(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text(_secret_line("a"))
    first = _commit(repo, "secret a")
    (repo / "b.py").write_text(_secret_line("b"))
    second = _commit(repo, "secret b")
    out = guardx.scan_secrets(str(repo), history=True)
    assert "Findings: 2" in out
    assert f"(commit {first})" in out
    assert f"(commit {second})" in out
    assert "a.py" in out and "b.py" in out
