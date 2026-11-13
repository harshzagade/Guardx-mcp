"""Unit tests for the `examples/pre-commit` hook.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before the hook loads `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real scanner through the real hook. The hook
runs against throwaway git repos under `tmp_path` — no real target is
ever touched.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
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

# Load the hook (no .py extension) under a unique module name.
_REPO = Path(__file__).resolve().parent.parent
_loader = importlib.machinery.SourceFileLoader(
    "guardx_pre_commit_hook", str(_REPO / "examples" / "pre-commit")
)
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
hook = importlib.util.module_from_spec(_spec)
_loader.exec_module(hook)


def _git(*args, cwd):
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"
    return proc


def _repo(tmp_path, monkeypatch):
    """Init a throwaway repo, point the hook at this checkout, cd into it."""
    _git("init", "-q", cwd=tmp_path)
    _git("config", "user.email", "test@example.com", cwd=tmp_path)
    _git("config", "user.name", "Test", cwd=tmp_path)
    monkeypatch.setenv("GUARDX_HOME", str(_REPO))
    monkeypatch.delenv("GUARDX_STRICT", raising=False)
    monkeypatch.chdir(tmp_path)


def _write(tmp_path, name, content, stage=True):
    fp = tmp_path / name
    fp.write_text(content, encoding="utf-8")
    if stage:
        _git("add", name, cwd=tmp_path)
    return fp


# ---------------------------------------------------------------------------
# Pre-commit hook
# ---------------------------------------------------------------------------

class TestPreCommitHook:
    def test_clean_staged_file_passes(self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        _write(tmp_path, "app.py", 'print("hello world")\n')
        assert hook.main([]) == 0

    def test_staged_high_secret_blocks_and_names_file(
            self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        secret = "ghp_" + "e" * 36
        _write(tmp_path, "app.py", f'TOKEN = "{secret}"\n')
        assert hook.main([]) == 1
        err = capsys.readouterr().err
        assert "commit blocked" in err
        assert "app.py:1" in err
        assert "GitHub Token" in err
        assert secret not in err  # masked preview only

    def test_unstaged_secret_does_not_block(
            self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        _write(tmp_path, "clean.py", 'print("hello")\n')
        secret = "ghp_" + "f" * 36
        _write(tmp_path, "dirty.py", f'TOKEN = "{secret}"\n', stage=False)
        assert hook.main([]) == 0

    def test_med_finding_warns_but_passes(
            self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        _write(tmp_path, "app.py", 'db_password = "hunter2-hunter2"\n')
        assert hook.main([]) == 0
        err = capsys.readouterr().err
        assert "[MED]" in err
        assert "warning only" in err

    def test_strict_mode_blocks_med_finding(
            self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        monkeypatch.setenv("GUARDX_STRICT", "1")
        _write(tmp_path, "app.py", 'db_password = "hunter2-hunter2"\n')
        assert hook.main([]) == 1

    def test_nothing_staged_passes(self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        assert hook.main([]) == 0

    def test_missing_server_blocks_with_hint(
            self, tmp_path, monkeypatch, capsys):
        _repo(tmp_path, monkeypatch)
        monkeypatch.setenv("GUARDX_HOME", str(tmp_path / "no-such-dir"))
        _write(tmp_path, "app.py", 'print("hello")\n')
        assert hook.main([]) == 1
        err = capsys.readouterr().err
        assert "GUARDX_HOME" in err

    def test_not_a_git_repo_skips(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("GUARDX_HOME", str(_REPO))
        monkeypatch.chdir(tmp_path)
        assert hook.main([]) == 0
        assert "not a git repository" in capsys.readouterr().err
