"""Unit tests for GuardX's fixed-version guidance in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_min_severity.py`. The stub `FastMCP.tool()` returns the
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
        if "queries" in json:
            # querybatch: one result per query, in query order.
            return FakeResponse(payload={"results": [
                {"vulns": self.vulns_by_name.get(q["package"]["name"], [])}
                for q in json["queries"]]})
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


def _range(events, rtype="ECOSYSTEM"):
    return {"type": rtype, "events": events}


def _vuln(vid, affected=None, score=None, summary="test vuln"):
    vuln = {"id": vid, "summary": summary}
    if affected is not None:
        vuln["affected"] = affected
    if score is not None:
        vuln["severity"] = [{"type": "CVSS_V3", "score": str(score)}]
    return vuln


def _affected(ranges, ecosystem="PyPI"):
    return [{"package": {"ecosystem": ecosystem, "name": "requests"},
             "ranges": ranges}]


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def test_version_cmp_numeric_runs():
    assert guardx._version_cmp("1.9.0", "1.10.0") == -1
    assert guardx._version_cmp("1.10.0", "1.9.0") == 1
    assert guardx._version_cmp("2.0", "2.0.0") == -1  # shorter prefix sorts first
    assert guardx._version_cmp("1.2.3", "1.2.3") == 0
    assert guardx._version_cmp("1.2", "1.2.3") == -1


def test_version_cmp_v_prefix_and_prerelease():
    assert guardx._version_cmp("v1.2.3", "1.2.4") == -1
    assert guardx._version_cmp("1.2.3rc1", "1.2.3") == -1
    assert guardx._version_cmp("1.2.3", "1.2.3rc1") == 1
    assert guardx._version_cmp("1.0.0-alpha", "1.0.0") == -1


# ---------------------------------------------------------------------------
# Fixed-version extraction
# ---------------------------------------------------------------------------

def test_single_range_fixed_version():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"fixed": "1.2.4"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == ["1.2.4"]
    assert unfixed is False


def test_already_fixed_version_has_no_guidance():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"fixed": "1.2.4"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.4", "PyPI")
    assert fixed == []
    assert unfixed is False


def test_version_before_introduced_is_not_affected():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "2.0"}, {"fixed": "2.1"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.5", "PyPI")
    assert fixed == []
    assert unfixed is False


def test_last_affected_only_is_unfixed():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"last_affected": "1.2.3"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == []
    assert unfixed is True


def test_multiple_ranges_take_highest_fix():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"fixed": "1.2.4"}]),
        _range([{"introduced": "0"}, {"fixed": "1.3.0"}]),
    ]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == ["1.2.4", "1.3.0"]
    assert unfixed is False


def test_mixed_fixed_and_unfixed_ranges():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"fixed": "1.2.4"}]),
        _range([{"introduced": "1.0"}, {"last_affected": "1.2.3"}]),
    ]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == ["1.2.4"]
    assert unfixed is True


def test_no_affected_entries():
    fixed, unfixed = guardx._vuln_fixed_versions(_vuln("GHSA-1"), "1.2.3", "PyPI")
    assert fixed == []
    assert unfixed is False


def test_affected_without_ranges_carries_no_guidance():
    vuln = _vuln("GHSA-1", [{"package": {"ecosystem": "PyPI", "name": "requests"},
                             "versions": ["1.2.3"]}])
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == []
    assert unfixed is False


def test_other_ecosystem_entries_skipped():
    vuln = _vuln("GHSA-1", [
        {"package": {"ecosystem": "Go", "name": "requests"},
         "ranges": [_range([{"introduced": "1.0"}, {"fixed": "9.9.9"}])]},
        {"package": {"ecosystem": "PyPI", "name": "requests"},
         "ranges": [_range([{"introduced": "1.0"}, {"fixed": "1.2.4"}])]},
    ])
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == ["1.2.4"]


def test_no_introduced_event_means_affected_from_start():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"fixed": "1.2.4"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.2.3", "PyPI")
    assert fixed == ["1.2.4"]
    assert unfixed is False


def test_reintroduced_after_fix_is_unfixed():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"fixed": "1.5"},
                {"introduced": "2.0"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "2.1", "PyPI")
    assert fixed == []
    assert unfixed is True


def test_version_in_fixed_gap_is_not_affected():
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "1.0"}, {"fixed": "1.5"},
                {"introduced": "2.0"}, {"fixed": "2.1"}])]))
    fixed, unfixed = guardx._vuln_fixed_versions(vuln, "1.7", "PyPI")
    assert fixed == []
    assert unfixed is False


# ---------------------------------------------------------------------------
# End-to-end report lines
# ---------------------------------------------------------------------------

def test_report_line_carries_upgrade_guidance(tmp_path):
    vuln = _vuln("GHSA-1", _affected([
        _range([{"introduced": "2.0"}, {"fixed": "2.28.1"}]),
        _range([{"introduced": "0"}, {"fixed": "2.29.0"}]),
    ]), score=7.5)
    out = _audit(tmp_path, {"requests": [vuln]})
    assert "GHSA-1" in out
    # Highest fixed version closes every affected range.
    assert "upgrade to >= 2.29.0" in out


def test_report_line_notes_unfixed_vuln(tmp_path):
    vuln = _vuln("GHSA-2", _affected([
        _range([{"introduced": "2.0"}, {"last_affected": "2.28.0"}])]),
        score=5.0)
    out = _audit(tmp_path, {"requests": [vuln]})
    assert "GHSA-2" in out
    assert "no fixed version released" in out


def test_report_line_without_range_data_has_no_guidance(tmp_path):
    vuln = _vuln("GHSA-3", score=9.0)
    out = _audit(tmp_path, {"requests": [vuln]})
    assert "GHSA-3" in out
    assert "upgrade to >=" not in out
    assert "no fixed version released" not in out
