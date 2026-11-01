"""Unit tests for GuardX's `min_severity` filter in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_osv_backoff.py`. The stub `FastMCP.tool()` returns the
decorated function unchanged, exactly like FastMCP 1.x does.
"""

from __future__ import annotations

import asyncio
import importlib.util
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
# Fakes
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None,
                 headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"vulns": []}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeClient:
    """Returns per-package vuln lists from a name -> [vuln] mapping."""

    def __init__(self, vulns_by_name=None):
        self.vulns_by_name = vulns_by_name or {}
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        name = json["package"]["name"]
        return FakeResponse(payload={"vulns": self.vulns_by_name.get(name, [])})


def run(coro):
    return asyncio.run(coro)


def _audit(tmp_path, vulns_by_name, text="requests==2.28.0\n", **kwargs):
    """Run audit_dependencies against a fake OSV client; return the report."""
    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = FakeClient(vulns_by_name)

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text(text)
        return run(guardx.audit_dependencies(str(manifest), **kwargs))
    finally:
        httpx_stub.AsyncClient = orig


def _vuln(vid, score=None, summary="test vuln"):
    vuln = {"id": vid, "summary": summary}
    if score is not None:
        vuln["severity"] = [{"type": "CVSS_V3", "score": str(score)}]
    return vuln


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def test_severity_bands():
    assert guardx._vuln_severity(_vuln("X", 10.0))[0] == "CRITICAL"
    assert guardx._vuln_severity(_vuln("X", 9.0))[0] == "CRITICAL"
    assert guardx._vuln_severity(_vuln("X", 7.5))[0] == "HIGH"
    assert guardx._vuln_severity(_vuln("X", 7.0))[0] == "HIGH"
    assert guardx._vuln_severity(_vuln("X", 5.0))[0] == "MEDIUM"
    assert guardx._vuln_severity(_vuln("X", 4.0))[0] == "MEDIUM"
    assert guardx._vuln_severity(_vuln("X", 2.0))[0] == "LOW"
    assert guardx._vuln_severity(_vuln("X"))[0] == "UNKNOWN"
    assert guardx._vuln_severity(_vuln("X", 0.0))[0] == "UNKNOWN"


def test_highest_cvss_score_wins():
    vuln = {"id": "X", "severity": [
        {"type": "CVSS_V2", "score": "5.0"},
        {"type": "CVSS_V3", "score": "8.1"},
        {"type": "CVSS_V3", "score": "junk"},
    ]}
    label, score = guardx._vuln_severity(vuln)
    assert (label, score) == ("HIGH", 8.1)


def test_parse_min_severity_values():
    assert guardx._parse_min_severity("low") == 1
    assert guardx._parse_min_severity("MED") == 2
    assert guardx._parse_min_severity("medium") == 2
    assert guardx._parse_min_severity("HIGH") == 3
    assert guardx._parse_min_severity("critical") == 4
    assert guardx._parse_min_severity("severe") is None
    assert guardx._parse_min_severity("") is None


# ---------------------------------------------------------------------------
# Filter behaviour
# ---------------------------------------------------------------------------

MIXED = {
    "requests": [
        _vuln("CVE-HIGH", 7.5),
        _vuln("CVE-LOW", 2.0),
        _vuln("CVE-NOSCORE"),
    ],
}


def test_filter_hides_below_floor_and_counts_them(tmp_path):
    out = _audit(tmp_path, MIXED, min_severity="HIGH")
    assert "CVE-HIGH" in out
    assert "[HIGH 7.5]" in out
    assert "CVE-LOW" not in out
    assert "CVE-NOSCORE" not in out
    assert "Minimum severity: HIGH" in out
    assert "Vulnerabilities hidden by filter: 2" in out
    assert "Vulnerable packages: 1" in out
    assert "requests==2.28.0  -> 1 known vuln(s)" in out


def test_fully_filtered_package_is_not_vulnerable(tmp_path):
    out = _audit(tmp_path, MIXED, min_severity="CRITICAL")
    assert "Vulnerable packages: 0" in out
    assert "No known vulnerabilities found. [OK]" in out
    assert "Vulnerabilities hidden by filter: 3" in out


def test_no_filter_keeps_unknown_and_untagged_scores(tmp_path):
    out = _audit(tmp_path, MIXED)
    assert "CVE-HIGH" in out and "CVE-LOW" in out and "CVE-NOSCORE" in out
    assert "[UNKNOWN]" in out
    assert "Minimum severity" not in out
    assert "hidden by filter" not in out


def test_med_alias_and_case_insensitive(tmp_path):
    out = _audit(tmp_path, MIXED, min_severity="med")
    assert "CVE-HIGH" in out
    assert "CVE-LOW" not in out
    assert "Minimum severity: MEDIUM" in out


def test_invalid_min_severity_is_an_error(tmp_path):
    out = _audit(tmp_path, MIXED, min_severity="severe")
    assert out.startswith("Error: unknown min_severity")
    assert "LOW, MEDIUM (or MED), HIGH, or CRITICAL" in out
