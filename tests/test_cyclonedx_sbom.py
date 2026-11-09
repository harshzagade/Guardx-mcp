"""Unit tests for GuardX's CycloneDX SBOM support in
`audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_go_mod.py`. The stub `FastMCP.tool()` returns the
decorated function unchanged, exactly like FastMCP 1.x does, so these
tests exercise the real parsing and tool logic. No real OSV endpoint is
ever touched — the HTTP client is faked throughout.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs
# ---------------------------------------------------------------------------

# Installed exactly once per pytest process: stub objects must be shared,
# otherwise a monkeypatch in one module misses the objects bound by another.
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

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("guardx_server", REPO_ROOT / "server.py")
assert _spec and _spec.loader
guardx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guardx)


def run(coro):
    return asyncio.run(coro)


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
    """Drop-in for httpx.AsyncClient; records OSV payloads per package."""

    def __init__(self, *args, **kwargs):
        self.posts = []

    async def post(self, url: str, json: dict):
        self.posts.append((url, json))
        if "queries" in json:
            # querybatch: one empty result per query, in query order.
            return FakeResponse(payload={"results": [
                {"vulns": []} for _ in json["queries"]]})
        return FakeResponse()


SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "myapp",
            "version": "1.0.0",
            "purl": "pkg:npm/myapp@1.0.0",
        }
    },
    "components": [
        {
            "type": "library",
            "name": "commons-lang3",
            "group": "org.apache.commons",
            "version": "3.12.0",
            "purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
        },
        {
            "type": "library",
            "name": "core",
            "group": "@angular",
            "version": "16.0.0",
            "purl": "pkg:npm/%40angular/core@16.0.0",
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.28.0",
            "purl": "pkg:pypi/requests@2.28.0",
        },
        {
            "type": "library",
            "name": "gin",
            "version": "v1.9.1",
            "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        },
        {
            "type": "library",
            "name": "serde",
            "version": "1.0.0",
            "purl": "pkg:cargo/serde@1.0.0",
        },
        # No purl: skipped, not guessed at.
        {"type": "library", "name": "mystery-lib", "version": "0.1.0"},
        # Unsupported purl ecosystem: skipped.
        {
            "type": "library",
            "name": "rails",
            "version": "7.0.0",
            "purl": "pkg:gem/rails@7.0.0",
        },
        # Version-less purl: skipped.
        {
            "type": "library",
            "name": "no-version",
            "purl": "pkg:npm/no-version",
        },
        # Qualifiers and subpath do not affect identity.
        {
            "type": "library",
            "name": "urllib3",
            "version": "1.26.0",
            "purl": "pkg:pypi/urllib3@1.26.0?foo=bar#sub/path",
        },
    ],
}


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_mixed_ecosystem_components_parsed():
    deps = list(guardx._parse_cyclonedx_sbom(SBOM))
    assert deps == [
        ("org.apache.commons:commons-lang3", "3.12.0", "Maven"),
        ("lodash", "4.17.21", "npm"),
        ("@angular/core", "16.0.0", "npm"),
        ("requests", "2.28.0", "PyPI"),
        ("github.com/gin-gonic/gin", "v1.9.1", "Go"),
        ("serde", "1.0.0", "crates.io"),
        ("urllib3", "1.26.0", "PyPI"),
    ]


def test_root_component_not_audited():
    deps = list(guardx._parse_cyclonedx_sbom(SBOM))
    assert all(name != "myapp" for name, _, _ in deps)


def test_purl_parsing():
    parse = guardx._parse_purl
    assert parse("pkg:maven/org.apache.commons/commons-lang3@3.12.0") == (
        "org.apache.commons:commons-lang3", "3.12.0", "Maven")
    assert parse("pkg:npm/%40angular/core@16.0.0") == (
        "@angular/core", "16.0.0", "npm")
    assert parse("pkg:golang/github.com/gin-gonic/gin@v1.9.1") == (
        "github.com/gin-gonic/gin", "v1.9.1", "Go")
    assert parse("pkg:pypi/urllib3@1.26.0?x=1#y") == (
        "urllib3", "1.26.0", "PyPI")


def test_purl_rejects_bad_inputs():
    parse = guardx._parse_purl
    assert parse("not-a-purl") is None
    assert parse("pkg:gem/rails@7.0.0") is None  # unsupported ecosystem
    assert parse("pkg:npm/no-version") is None  # no version
    assert parse("pkg:npm/@") is None  # empty version
    assert parse("pkg:npm") is None  # no path
    assert parse(None) is None
    assert parse(123) is None


def test_non_sbom_data_yields_nothing():
    assert list(guardx._parse_cyclonedx_sbom({})) == []
    assert list(guardx._parse_cyclonedx_sbom({"components": "nope"})) == []
    assert list(guardx._parse_cyclonedx_sbom(None)) == []
    assert list(guardx._parse_cyclonedx_sbom({"components": ["nope", 42]})) == []


def test_is_cyclonedx_detection():
    assert guardx._is_cyclonedx({"bomFormat": "CycloneDX"}, "report.json")
    assert guardx._is_cyclonedx({"bomFormat": "cyclonedx"}, "report.json")
    assert guardx._is_cyclonedx({"components": []}, "sbom.json")
    assert guardx._is_cyclonedx({"components": []}, "cyclonedx.json")
    assert guardx._is_cyclonedx({"components": []}, "bom.json")
    assert guardx._is_cyclonedx({"components": []}, "deps.cdx.json")
    # A package.json with an incidental components key is not an SBOM.
    assert not guardx._is_cyclonedx({"components": []}, "package.json")
    assert not guardx._is_cyclonedx({"name": "x"}, "report.json")
    assert not guardx._is_cyclonedx({"components": "nope"}, "sbom.json")
    assert not guardx._is_cyclonedx("nope", "sbom.json")


# ---------------------------------------------------------------------------
# Tool wiring tests
# ---------------------------------------------------------------------------

def _audit(tmp_path, filename: str, text: str) -> tuple[str, FakeClient]:
    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = FakeClient()

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    import pytest
    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / filename
        manifest.write_text(text)
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    return out, PatchedClient.client


def test_sbom_audit_queries_each_ecosystem(tmp_path):
    out, client = _audit(tmp_path, "sbom.json", json.dumps(SBOM))
    assert "Ecosystems: Maven, npm, PyPI, Go, crates.io" in out
    assert "Dependencies checked: 7" in out
    # One querybatch call per ecosystem, not one per package.
    assert len(client.posts) == 5
    by_eco = {}
    for _, payload in client.posts:
        for q in payload["queries"]:
            by_eco.setdefault(q["package"]["ecosystem"], []).append(q)
    assert [q["package"]["name"] for q in by_eco["Maven"]] == [
        "org.apache.commons:commons-lang3"]
    assert [q["package"]["name"] for q in by_eco["npm"]] == [
        "lodash", "@angular/core"]
    assert [q["package"]["name"] for q in by_eco["PyPI"]] == [
        "requests", "urllib3"]
    assert by_eco["Go"][0]["version"] == "v1.9.1"
    assert "No known vulnerabilities found. [OK]" in out


def test_sbom_detected_by_bomformat_under_any_name(tmp_path):
    out, _ = _audit(tmp_path, "report.json", json.dumps(SBOM))
    assert "Ecosystems: Maven, npm, PyPI, Go, crates.io" in out
    assert "Dependencies checked: 7" in out


def test_sbom_detected_by_filename_without_bomformat(tmp_path):
    data = dict(SBOM)
    del data["bomFormat"]
    out, _ = _audit(tmp_path, "cyclonedx.json", json.dumps(data))
    assert "Dependencies checked: 7" in out


def test_sbom_vuln_reported_with_correct_ecosystem(tmp_path):
    vuln = {
        "id": "CVE-2023-1234",
        "summary": "test sbom vuln",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "urllib3"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"},
                {"fixed": "1.26.18"},
            ]}],
        }],
    }

    class VulnClient(FakeClient):
        async def post(self, url: str, json: dict):
            self.posts.append((url, json))
            if "queries" in json:
                return FakeResponse(payload={"results": [
                    {"vulns": ([vuln] if q["package"]["name"] == "urllib3"
                               else [])}
                    for q in json["queries"]]})
            return FakeResponse()

    class PatchedClient:
        client = None

        def __init__(self, *args, **kwargs):
            PatchedClient.client = VulnClient()

        async def __aenter__(self):
            return PatchedClient.client

        async def __aexit__(self, *exc):
            return False

    httpx_stub = sys.modules["httpx"]
    orig = httpx_stub.AsyncClient
    httpx_stub.AsyncClient = PatchedClient
    try:
        manifest = tmp_path / "sbom.json"
        manifest.write_text(json.dumps(SBOM))
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    assert "urllib3==1.26.0" in out
    assert "CVE-2023-1234" in out
    assert "upgrade to >= 1.26.18" in out
    assert "Vulnerable packages: 1" in out


def test_sbom_without_components_reports_cleanly(tmp_path):
    out, _ = _audit(tmp_path, "sbom.json", json.dumps(
        {"bomFormat": "CycloneDX", "components": []}))
    assert "No pinned dependencies found" in out


def test_plain_json_without_bomformat_is_unsupported(tmp_path):
    manifest = tmp_path / "data.json"
    manifest.write_text(json.dumps({"name": "x", "version": "1.0.0"}))
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "Unsupported manifest" in out
    assert "CycloneDX" in out


def test_malformed_json_is_unsupported(tmp_path):
    manifest = tmp_path / "sbom.json"
    manifest.write_text("{not json")
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "Unsupported manifest" in out
