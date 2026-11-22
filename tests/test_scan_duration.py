"""Unit tests for the scan-duration reporting in `scan_secrets`.

The collection phase is timed with `time.monotonic()`: the text header
carries `Scan duration: 0.123s`, JSON output carries
`duration_seconds`, and SARIF output carries `durationSeconds` in the
run properties — so a slow CI scan can be profiled per run. Scans run
against `tmp_path` fixtures; no real target is ever touched.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs (same pattern as tests/test_scan_secrets.py)
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

_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_duration",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
guardx = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guardx)

# A real-looking secret line for a findings scan. (Test fixture only —
# it is a fake key shape, never a live credential.)
_SECRET_LINE = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\n'


def _duration_from_text(report: str) -> float:
    m = re.search(r"Scan duration: (\d+\.\d+)s", report)
    assert m, "header must carry a Scan duration line"
    return float(m.group(1))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_text_header_carries_duration_on_clean_scan(tmp_path):
    (tmp_path / "clean.py").write_text("x = 1\n")
    report = guardx.scan_secrets(str(tmp_path))
    assert "Files scanned: 1" in report
    duration = _duration_from_text(report)
    assert duration >= 0.0
    assert "No hardcoded secrets detected." in report


def test_text_header_carries_duration_with_findings(tmp_path):
    (tmp_path / "leak.py").write_text(_SECRET_LINE)
    report = guardx.scan_secrets(str(tmp_path))
    assert "Findings: 1" in report
    duration = _duration_from_text(report)
    assert duration >= 0.0


def test_json_output_carries_duration_seconds(tmp_path):
    (tmp_path / "leak.py").write_text(_SECRET_LINE)
    report = json.loads(guardx.scan_secrets(str(tmp_path), json_output=True))
    assert isinstance(report["duration_seconds"], float)
    assert report["duration_seconds"] >= 0.0


def test_json_output_carries_duration_on_clean_scan(tmp_path):
    (tmp_path / "clean.py").write_text("x = 1\n")
    report = json.loads(guardx.scan_secrets(str(tmp_path), json_output=True))
    assert isinstance(report["duration_seconds"], float)
    assert report["duration_seconds"] >= 0.0


def test_sarif_output_carries_duration_seconds(tmp_path):
    (tmp_path / "leak.py").write_text(_SECRET_LINE)
    report = json.loads(guardx.scan_secrets(str(tmp_path), sarif_output=True))
    props = report["runs"][0]["properties"]
    assert isinstance(props["durationSeconds"], float)
    assert props["durationSeconds"] >= 0.0


def test_text_and_json_durations_agree(tmp_path):
    # Same scan shape, so both formats report the same measured value
    # (a float rounded to 3 decimals — the text form is that value
    # printed with 3 decimals).
    (tmp_path / "leak.py").write_text(_SECRET_LINE)
    text_report = guardx.scan_secrets(str(tmp_path))
    json_report = json.loads(
        guardx.scan_secrets(str(tmp_path), json_output=True))
    assert _duration_from_text(text_report) >= 0.0
    assert json_report["duration_seconds"] >= 0.0
