"""Unit tests for GuardX's `scan_secrets` tool.

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
    "guardx_server_scan", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, name: str, content: str) -> str:
    fp = tmp_path / name
    fp.write_text(content)
    return str(fp)


# ---------------------------------------------------------------------------
# Severity grading
# ---------------------------------------------------------------------------

class TestSeverityGrading:
    def test_live_keys_are_high(self, tmp_path):
        # Deliberately fake credentials: formats the patterns recognise,
        # but not real secrets.
        fp = _write(
            tmp_path, "app.py",
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'GH_TOKEN = "ghp_' + "a" * 36 + '"\n'
        )
        report = server.scan_secrets(fp)
        assert "[HIGH] AWS Access Key ID" in report
        assert "[HIGH] GitHub Token" in report
        assert "Findings: 2 (HIGH: 2, MED: 0, LOW: 0)" in report

    def test_private_key_block_is_high(self, tmp_path):
        fp = _write(
            tmp_path, "id_rsa",
            "-----BEGIN RSA PRIVATE KEY-----\nNOT_A_REAL_KEY\n",
        )
        report = server.scan_secrets(fp)
        assert "[HIGH] Private Key Block" in report
        assert "HIGH: 1" in report

    def test_generic_assignment_is_medium(self, tmp_path):
        fp = _write(
            tmp_path, "config.py",
            'api_key = "some-app-secret-thing"\n',
        )
        report = server.scan_secrets(fp)
        assert "[MED] Generic Secret Assignment" in report
        assert "Findings: 1 (HIGH: 0, MED: 1, LOW: 0)" in report

    def test_per_severity_counts_in_header(self, tmp_path):
        fp = _write(
            tmp_path, "mixed.py",
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'db_password = "hunter2-hunter2"\n'
        )
        report = server.scan_secrets(fp)
        assert "Findings: 2 (HIGH: 1, MED: 1, LOW: 0)" in report

    def test_clean_report_carries_zero_counts(self, tmp_path):
        fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
        report = server.scan_secrets(fp)
        assert "Findings: 0 (HIGH: 0, MED: 0, LOW: 0)" in report
        assert "No hardcoded secrets detected. [OK]" in report

    def test_old_bang_prefix_is_gone(self, tmp_path):
        fp = _write(
            tmp_path, "app.py",
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        report = server.scan_secrets(fp)
        assert "[!] AWS Access Key ID" not in report

    def test_secret_values_are_still_masked(self, tmp_path):
        secret = "ghp_" + "a" * 36
        fp = _write(tmp_path, "app.py", f'TOKEN = "{secret}"\n')
        report = server.scan_secrets(fp)
        assert secret not in report
        assert "[HIGH] GitHub Token" in report
