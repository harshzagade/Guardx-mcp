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


# ---------------------------------------------------------------------------
# Long-line sliding window
# ---------------------------------------------------------------------------

class TestLongLineSlidingWindow:
    def test_secret_buried_in_long_line_is_found(self, tmp_path):
        # Old behaviour skipped lines >2000 chars outright; a secret 4000
        # chars into a minified bundle must now be caught.
        secret = "ghp_" + "b" * 36
        line = "x" * 4000 + f' TOKEN="{secret}" ' + "y" * 4000 + "\n"
        assert len(line) > 2000
        fp = _write(tmp_path, "bundle.min.js", line)
        report = server.scan_secrets(fp)
        assert "[HIGH] GitHub Token" in report
        assert secret not in report  # still masked
        assert "Findings: 1" in report

    def test_secret_straddling_window_boundary_is_caught(self, tmp_path):
        # The 500-char overlap must catch a secret sitting across the
        # 2000-char window edge (window 1: 0-2000, window 2: 1500-3500).
        secret = "ghp_" + "c" * 36
        line = "x" * 1990 + f'"{secret}"' + "y" * 3000 + "\n"
        assert 1990 < 2000 < 1990 + len(secret) + 2  # truly straddles
        fp = _write(tmp_path, "bundle.min.js", line)
        report = server.scan_secrets(fp)
        assert "[HIGH] GitHub Token" in report

    def test_long_line_reports_only_one_finding(self, tmp_path):
        # The same secret appearing in two windows of one line is still a
        # single finding (one finding per line).
        secret = "ghp_" + "d" * 36
        line = f'"{secret}"' + "x" * 3000 + f'"{secret}"' + "\n"
        fp = _write(tmp_path, "bundle.min.js", line)
        report = server.scan_secrets(fp)
        assert "Findings: 1 (HIGH: 1, MED: 0, LOW: 0)" in report

    def test_clean_long_line_stays_clean(self, tmp_path):
        line = "var x = " + "9" * 5000 + ";\n"
        fp = _write(tmp_path, "bundle.min.js", line)
        report = server.scan_secrets(fp)
        assert "No hardcoded secrets detected. [OK]" in report

    def test_line_windows_overlap_and_cover(self):
        # Direct unit check of the chunking: full coverage, 500-char overlap.
        line = "a" * 5000
        windows = list(server._line_windows(line))
        assert windows[0] == line[:2000]
        assert windows[1] == line[1500:3500]
        assert windows[-1].endswith("a" * 500)
        # Every offset of the line appears in at least one window.
        covered = set()
        for i, w in enumerate(windows):
            start = i * server.LONG_LINE_STEP
            covered.update(range(start, start + len(w)))
        assert covered == set(range(5000))

    def test_short_lines_use_single_window(self):
        line = "short line\n"
        assert list(server._line_windows(line)) == [line]


# ---------------------------------------------------------------------------
# Repo-wide secret dedup
# ---------------------------------------------------------------------------

class TestSecretDedup:
    def test_same_secret_in_two_files_counts_once(self, tmp_path):
        secret = "ghp_" + "e" * 36
        _write(tmp_path, "a.py", f'TOKEN = "{secret}"\n')
        _write(tmp_path, "b.py", f'API_KEY = "{secret}"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 2 (HIGH: 2, MED: 0, LOW: 0)" in report
        assert "Unique secrets: 1" in report
        # Per-file reporting is preserved: both occurrences are still shown.
        assert "a.py:1" in report
        assert "b.py:1" in report

    def test_same_secret_twice_in_one_file_counts_once(self, tmp_path):
        secret = "ghp_" + "f" * 36
        fp = _write(
            tmp_path, "a.py",
            f'TOKEN = "{secret}"\nKEY = "{secret}"\n',
        )
        report = server.scan_secrets(fp)
        assert "Findings: 2" in report
        assert "Unique secrets: 1" in report

    def test_different_secrets_each_count(self, tmp_path):
        _write(
            tmp_path, "a.py",
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'GH_TOKEN = "ghp_' + "a" * 36 + '"\n'
        )
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 2" in report
        assert "Unique secrets: 2" in report

    def test_dedup_compares_raw_values_not_masked_previews(self, tmp_path):
        # Two secrets sharing the same first 4 / last 2 characters (and
        # length) have identical masked previews; they must still count
        # as two secrets.
        s1 = "ghp_" + "a" * 34 + "ZZ"
        s2 = "ghp_" + "b" * 34 + "ZZ"
        assert server._mask(s1) == server._mask(s2)
        _write(tmp_path, "a.py", f'A = "{s1}"\n')
        _write(tmp_path, "b.py", f'B = "{s2}"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Unique secrets: 2" in report

    def test_clean_scan_shows_zero_unique(self, tmp_path):
        fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
        report = server.scan_secrets(fp)
        assert "Unique secrets: 0" in report
        assert "No hardcoded secrets detected. [OK]" in report


# ---------------------------------------------------------------------------
# JSON output mode
# ---------------------------------------------------------------------------

class TestJSONOutput:
    def test_json_mode_is_valid_json(self, tmp_path):
        import json as jsonlib
        fp = _write(tmp_path, "app.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        payload = jsonlib.loads(server.scan_secrets(fp, json_output=True))
        assert payload["tool"] == "scan_secrets"
        assert payload["path"] == fp
        assert payload["files_scanned"] == 1
        assert payload["findings_count"] == 1
        assert payload["unique_secrets"] == 1
        assert payload["severity_counts"] == {"HIGH": 1, "MED": 0, "LOW": 0}

    def test_json_findings_carry_masked_preview(self, tmp_path):
        import json as jsonlib
        secret = "ghp_" + "1" * 36
        fp = _write(tmp_path, "app.py", f'TOKEN = "{secret}"\n')
        payload = jsonlib.loads(server.scan_secrets(fp, json_output=True))
        finding = payload["findings"][0]
        assert finding["file"] == fp
        assert finding["line"] == 1
        assert finding["type"] == "GitHub Token"
        assert finding["severity"] == "HIGH"
        assert secret not in jsonlib.dumps(payload)  # raw value never leaks
        assert finding["match"] == server._mask(secret)

    def test_json_mode_includes_dedup_count(self, tmp_path):
        import json as jsonlib
        secret = "ghp_" + "2" * 36
        _write(tmp_path, "a.py", f'A = "{secret}"\n')
        _write(tmp_path, "b.py", f'B = "{secret}"\n')
        payload = jsonlib.loads(
            server.scan_secrets(str(tmp_path), json_output=True)
        )
        assert payload["findings_count"] == 2
        assert payload["unique_secrets"] == 1

    def test_json_clean_scan_is_valid_json(self, tmp_path):
        import json as jsonlib
        fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
        payload = jsonlib.loads(server.scan_secrets(fp, json_output=True))
        assert payload["findings"] == []
        assert payload["findings_count"] == 0
        assert payload["unique_secrets"] == 0

    def test_json_error_is_a_json_object(self, tmp_path):
        import json as jsonlib
        missing = str(tmp_path / "nope.py")
        payload = jsonlib.loads(server.scan_secrets(missing, json_output=True))
        assert payload["error"] == f"path does not exist: {missing}"

    def test_default_output_is_still_text(self, tmp_path):
        fp = _write(tmp_path, "app.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        report = server.scan_secrets(fp)
        assert report.startswith("Secret scan of")
