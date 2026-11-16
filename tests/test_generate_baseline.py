"""Unit tests for GuardX's `generate_baseline` helper.

`generate_baseline(path)` runs the same collection phase as
`scan_secrets` and returns the finding hashes for the current scan —
one SHA-256 hash per line, sorted and deduplicated — so a team can
acknowledge a reviewed batch without hand-computing hashes. No baseline
is applied while generating, so a regenerated baseline stays complete.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic. Scans run against `tmp_path`
fixtures — no real target is ever touched.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs
# ---------------------------------------------------------------------------

# Stub objects are shared across the whole suite and installed exactly once
# per pytest process (see the sentinel below): a monkeypatch in one module
# must hit the same objects `server.py` bound in every module.
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

# Load under a module name unique to this file so re-executing server.py
# cannot clobber another test module's copy in sys.modules.
_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_baseline_gen",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path, name, content):
    fp = tmp_path / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    return str(fp)


FAKE_KEY = "AKIA" + "A" * 16  # format-valid, not a real credential


def _token(tag="a"):
    # Built by concatenation so this test file itself never holds a
    # literal full token string.
    return "ghp_" + tag * 36


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


def _init_repo(tmp_path):
    _git("init", cwd=str(tmp_path))
    _git("config", "user.email", "test@example.com", cwd=str(tmp_path))
    _git("config", "user.name", "Test", cwd=str(tmp_path))
    return tmp_path


def _commit(repo, message):
    _git("add", "-A", cwd=str(repo))
    _git("commit", "-q", "-m", message, cwd=str(repo))


class TestGenerateBaseline:
    def test_hashes_match_finding_hash(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "other.py", f'TOKEN = "{_token()}"\n')
        out = server.generate_baseline(str(tmp_path))
        expected = sorted([
            server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY),
            server._finding_hash("other.py", "GitHub Token", _token()),
        ])
        assert out == "\n".join(expected) + "\n"

    def test_same_secret_twice_in_one_file_collapses(self, tmp_path):
        _write(tmp_path, "app.py",
               f'KEY = "{FAKE_KEY}"\nKEY2 = "{FAKE_KEY}"\n')
        out = server.generate_baseline(str(tmp_path))
        assert out == (
            server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
            + "\n"
        )

    def test_same_secret_in_two_files_is_two_hashes(self, tmp_path):
        _write(tmp_path, "a.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "b.py", f'KEY = "{FAKE_KEY}"\n')
        out = server.generate_baseline(str(tmp_path))
        assert out.count("\n") == 2
        assert server._finding_hash("a.py", "AWS Access Key ID", FAKE_KEY) in out
        assert server._finding_hash("b.py", "AWS Access Key ID", FAKE_KEY) in out

    def test_clean_scan_returns_empty_string(self, tmp_path):
        _write(tmp_path, "app.py", 'print("hello")\n')
        assert server.generate_baseline(str(tmp_path)) == ""

    def test_round_trip_suppresses_everything(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "other.py", f'TOKEN = "{_token()}"\n')
        baseline = server.generate_baseline(str(tmp_path))
        (tmp_path / ".guardx-baseline").write_text(baseline)
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 0 (HIGH: 0, MED: 0, LOW: 0)" in report
        assert "Suppressed: 2 acknowledged" in report

    def test_existing_baseline_does_not_hide_generation(self, tmp_path):
        # Acknowledge the AWS key, then add a second secret: regeneration
        # must include the acknowledged one, or the new baseline would
        # silently drop it.
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        digest = server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
        (tmp_path / ".guardx-baseline").write_text(digest + "\n")
        _write(tmp_path, "other.py", f'TOKEN = "{_token()}"\n')
        out = server.generate_baseline(str(tmp_path))
        assert digest in out
        assert server._finding_hash("other.py", "GitHub Token", _token()) in out

    def test_exclude_applies(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "fixtures/data.py", f'KEY = "{FAKE_KEY}"\n')
        out = server.generate_baseline(str(tmp_path), exclude="fixtures/*")
        assert out == (
            server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
            + "\n"
        )

    def test_config_exclude_and_entropy_apply(self, tmp_path):
        _write(tmp_path, "app.py", 'misc = "aB3xK9mQ2vZ8pL5wR7tY"\n')
        _write(tmp_path, "fixtures/data.py", f'KEY = "{FAKE_KEY}"\n')
        # 4.322-entropy string: caught at the default 4.0, missed at 4.5.
        out_default = server.generate_baseline(str(tmp_path))
        assert out_default.count("\n") == 2  # entropy hit + AWS key
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nexclude = "fixtures/*"\n'
               "entropy_threshold = 4.5\n")
        out = server.generate_baseline(str(tmp_path))
        assert out == ""

    def test_history_mode_generates_commit_findings(self, tmp_path):
        repo = _init_repo(tmp_path)
        (repo / "app.py").write_text(f'TOKEN = "{_token()}"\n')
        _commit(repo, "add token")
        (repo / "app.py").write_text('print("hello")\n')
        _commit(repo, "remove token")
        out = server.generate_baseline(str(repo), history=True)
        assert out == (
            server._finding_hash("app.py", "GitHub Token", _token()) + "\n"
        )

    def test_missing_path_is_error(self, tmp_path):
        out = server.generate_baseline(str(tmp_path / "nope"))
        assert out.startswith("Error: path does not exist:")

    def test_history_and_since_rejected(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        out = server.generate_baseline(str(tmp_path), since="2026-01-01",
                                       history=True)
        assert out.startswith("Error: history and since cannot be combined")

    def test_max_findings_caps_generation(self, tmp_path):
        for i in range(3):
            _write(tmp_path, f"f{i}.py", f'KEY = "{FAKE_KEY}"\n')
        out = server.generate_baseline(str(tmp_path), max_findings=2)
        assert out.count("\n") == 2
