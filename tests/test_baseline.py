"""Unit tests for GuardX's `scan_secrets` baseline suppression.

A `.guardx-baseline` file at the scan root lists SHA-256 hashes of
acknowledged findings (see `server._finding_hash`); matching findings
are suppressed from the report and counted, so CI stays green on
reviewed false positives without hiding new findings.

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
    "guardx_server_baseline", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path, name, content):
    fp = tmp_path / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    return str(fp)


FAKE_KEY = "AKIA" + "A" * 16  # format-valid, not a real credential


def _baseline_for(tmp_path, rel, finding_type, secret):
    digest = server._finding_hash(rel, finding_type, secret)
    (tmp_path / ".guardx-baseline").write_text(digest + "\n")
    return digest


class TestBaseline:
    def test_suppressed_finding_hidden_and_counted(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _baseline_for(tmp_path, "app.py", "AWS Access Key ID", FAKE_KEY)
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 0 (HIGH: 0, MED: 0, LOW: 0)" in report
        assert "Suppressed: 1 acknowledged finding(s) via .guardx-baseline" in report
        assert "AWS Access Key ID" not in report

    def test_unlisted_finding_still_reported(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "other.py", f'TOKEN = "ghp_{"b" * 36}"\n')
        # Baseline acknowledges only the AWS key; the GitHub token stays.
        _baseline_for(tmp_path, "app.py", "AWS Access Key ID", FAKE_KEY)
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 1" in report
        assert "Suppressed: 1 acknowledged" in report
        assert "GitHub Token" in report

    def test_hash_stable_across_line_shifts(self, tmp_path):
        # Same finding, pushed down by a comment line: line numbers are
        # excluded from the hash, so suppression survives the edit.
        fp = _write(tmp_path, "app.py",
                    "# header\n" + f'KEY = "{FAKE_KEY}"\n')
        _baseline_for(tmp_path, "app.py", "AWS Access Key ID", FAKE_KEY)
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 0" in report
        assert "Suppressed: 1" in report

    def test_json_carries_suppressed_count(self, tmp_path):
        import json
        fp = _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _baseline_for(tmp_path, "app.py", "AWS Access Key ID", FAKE_KEY)
        data = json.loads(server.scan_secrets(str(tmp_path), json_output=True))
        assert data["findings_count"] == 0
        assert data["suppressed_count"] == 1
        assert data["findings"] == []

    def test_explicit_baseline_path_and_missing_is_error(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        base = tmp_path / "my-baseline.txt"
        base.write_text(server._finding_hash("app.py", "AWS Access Key ID",
                                             FAKE_KEY) + "\n")
        assert "Findings: 0" in server.scan_secrets(str(tmp_path),
                                                    baseline=str(base))
        missing = server.scan_secrets(str(tmp_path),
                                      baseline=str(tmp_path / "nope.txt"))
        assert missing.startswith("Error: baseline does not exist")

    def test_comments_blanks_and_malformed_lines_ignored(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        (tmp_path / ".guardx-baseline").write_text(
            "# reviewed 2026-10-28\n\nnot-a-hash\n"
            + server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
            + "\n")
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 0" in report
        assert "Suppressed: 1" in report

    def test_no_baseline_file_means_no_suppression(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 1" in report
        assert "Suppressed" not in report

    def test_single_file_scan_uses_its_own_directory_baseline(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _baseline_for(tmp_path, "app.py", "AWS Access Key ID", FAKE_KEY)
        report = server.scan_secrets(fp)
        assert "Findings: 0" in report
        assert "Suppressed: 1" in report

    def test_baseline_file_itself_is_not_scanned(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _baseline_for(tmp_path, "app.py", "AWS Access Key ID", FAKE_KEY)
        report = server.scan_secrets(str(tmp_path))
        # Only the one acknowledged finding exists; the baseline file
        # (bare hex digests) must not add findings of its own.
        assert "Files scanned: 1" in report
