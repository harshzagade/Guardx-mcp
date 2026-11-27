"""Unit tests for GuardX's `fail_on` severity gate in `scan_secrets`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_scan_secrets.py`. The stub `FastMCP.tool()` returns the
decorated function unchanged, exactly like FastMCP 1.x does, so these
tests exercise the real tool logic. Scans run against `tmp_path`
fixtures — no real target is ever touched.

Secret-shaped fixtures are built by string concatenation, never as
literals: GitHub push protection rejects blobs containing
secret-shaped strings even in obvious test fixtures.
"""

from __future__ import annotations

import importlib.util
import json
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
    "guardx_server_fail_on", str(Path(__file__).resolve().parent.parent / "server.py")
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


# A HIGH finding: a GitHub token, built by concatenation so the literal
# never appears in the file.
HIGH_TOKEN = "ghp_" + "a" * 36
# A MED finding: a generic credential assignment.
MED_LINE = 'api_key = "some-app-secret-thing"\n'
# A LOW finding: a mixed-alphabet custom token no known pattern matches
# (Shannon entropy ~4.95 bits/char, above the 4.0 threshold); the
# variable name carries no credential keyword, so the generic
# assignment pattern cannot fire either. The characters stay inside
# the quoted-token charset the entropy heuristic scans.
LOW_TOKEN = "9fK2-vQ7xLm4.pR8sT1wZ6bN3cD5eF0"


def _mixed(tmp_path):
    return _write(
        tmp_path, "mixed.py",
        f'TOKEN = "{HIGH_TOKEN}"\n{MED_LINE}misc = "{LOW_TOKEN}"\n',
    )


# ---------------------------------------------------------------------------
# Text verdicts
# ---------------------------------------------------------------------------

def test_high_gate_fails_on_high_finding(tmp_path):
    fp = _mixed(tmp_path)
    report = server.scan_secrets(fp, fail_on="HIGH")
    assert "Verdict: FAIL" in report
    assert "1 finding(s) at or above HIGH" in report


def test_high_gate_passes_without_high_finding(tmp_path):
    fp = _write(tmp_path, "app.py", MED_LINE + f'misc = "{LOW_TOKEN}"\n')
    report = server.scan_secrets(fp, fail_on="HIGH")
    assert "Verdict: PASS" in report
    assert "no findings at or above HIGH" in report
    assert "Verdict: FAIL" not in report


def test_med_gate_fails_on_med_finding(tmp_path):
    fp = _write(tmp_path, "app.py", MED_LINE)
    report = server.scan_secrets(fp, fail_on="MED")
    assert "Verdict: FAIL" in report
    assert "1 finding(s) at or above MED" in report


def test_med_gate_passes_on_low_only(tmp_path):
    fp = _write(tmp_path, "app.py", f'misc = "{LOW_TOKEN}"\n')
    report = server.scan_secrets(fp, fail_on="MED")
    assert "Verdict: PASS" in report
    assert "no findings at or above MED" in report


def test_low_gate_fails_on_any_finding(tmp_path):
    fp = _write(tmp_path, "app.py", f'misc = "{LOW_TOKEN}"\n')
    report = server.scan_secrets(fp, fail_on="LOW")
    assert "Verdict: FAIL" in report
    assert "1 finding(s) at or above LOW" in report


def test_clean_scan_passes(tmp_path):
    fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
    report = server.scan_secrets(fp, fail_on="HIGH")
    assert "Verdict: PASS" in report
    assert "No hardcoded secrets detected. [OK]" in report


def test_fail_count_covers_every_finding_at_or_above(tmp_path):
    fp = _mixed(tmp_path)
    report = server.scan_secrets(fp, fail_on="MED")
    # HIGH + MED both sit at or above MED; the LOW one does not.
    assert "Verdict: FAIL" in report
    assert "2 finding(s) at or above MED" in report


def test_medium_alias_and_case_insensitive(tmp_path):
    fp = _write(tmp_path, "app.py", MED_LINE)
    assert "Verdict: FAIL" in server.scan_secrets(fp, fail_on="MEDIUM")
    assert "Verdict: FAIL" in server.scan_secrets(fp, fail_on="med")
    report = server.scan_secrets(fp, fail_on="medium")
    assert "at or above MED" in report  # canonical scan label in output
    high_fp = _write(tmp_path, "high.py", f'TOKEN = "{HIGH_TOKEN}"\n')
    assert "Verdict: FAIL" in server.scan_secrets(high_fp, fail_on=" high ")


def test_no_gate_means_no_verdict(tmp_path):
    fp = _mixed(tmp_path)
    report = server.scan_secrets(fp)
    assert "Verdict:" not in report


# ---------------------------------------------------------------------------
# Invalid values
# ---------------------------------------------------------------------------

def test_unknown_fail_on_is_an_error(tmp_path):
    fp = _mixed(tmp_path)
    report = server.scan_secrets(fp, fail_on="CRITICAL")
    assert report.startswith("Error: unknown fail_on:")
    assert "LOW, MEDIUM (or MED), or HIGH" in report


def test_unknown_fail_on_json_error_object(tmp_path):
    fp = _mixed(tmp_path)
    payload = json.loads(
        server.scan_secrets(fp, fail_on="banana", json_output=True)
    )
    assert payload["tool"] == "scan_secrets"
    assert "unknown fail_on" in payload["error"]


def test_non_string_fail_on_is_an_error(tmp_path):
    fp = _mixed(tmp_path)
    report = server.scan_secrets(fp, fail_on=3)
    assert report.startswith("Error: fail_on must be a severity string")


# ---------------------------------------------------------------------------
# JSON and SARIF verdicts
# ---------------------------------------------------------------------------

def test_json_carries_fail_on_and_verdict(tmp_path):
    fp = _mixed(tmp_path)
    payload = json.loads(
        server.scan_secrets(fp, fail_on="HIGH", json_output=True)
    )
    assert payload["fail_on"] == "HIGH"
    assert payload["verdict"] == "FAIL"


def test_json_pass_verdict_without_findings(tmp_path):
    fp = _write(tmp_path, "clean.py", 'print("hello world")\n')
    payload = json.loads(
        server.scan_secrets(fp, fail_on="HIGH", json_output=True)
    )
    assert payload["fail_on"] == "HIGH"
    assert payload["verdict"] == "PASS"
    assert payload["findings_count"] == 0


def test_json_without_gate_has_no_verdict_keys(tmp_path):
    fp = _mixed(tmp_path)
    payload = json.loads(server.scan_secrets(fp, json_output=True))
    assert "fail_on" not in payload
    assert "verdict" not in payload


def test_sarif_carries_fail_on_and_verdict(tmp_path):
    fp = _mixed(tmp_path)
    payload = json.loads(
        server.scan_secrets(fp, fail_on="HIGH", sarif_output=True)
    )
    props = payload["runs"][0]["properties"]
    assert props["failOn"] == "HIGH"
    assert props["verdict"] == "FAIL"


def test_sarif_pass_verdict(tmp_path):
    fp = _write(tmp_path, "app.py", MED_LINE)
    payload = json.loads(
        server.scan_secrets(fp, fail_on="HIGH", sarif_output=True)
    )
    props = payload["runs"][0]["properties"]
    assert props["failOn"] == "HIGH"
    assert props["verdict"] == "PASS"
