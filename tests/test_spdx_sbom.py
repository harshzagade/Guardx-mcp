"""Unit tests for GuardX's SPDX SBOM support in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_cyclonedx_sbom.py`. The stub `FastMCP.tool()` returns the
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


def _purl_ref(purl: str) -> dict:
    return {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": purl,
    }


SBOM = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "myapp",
    "documentNamespace": "https://example.com/spdx/myapp-1.0.0",
    "creationInfo": {"created": "2026-11-27T00:00:00Z",
                     "creators": ["Tool: example-1.0"]},
    "documentDescribes": ["SPDXRef-Package-myapp"],
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-myapp",
            "name": "myapp",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:npm/myapp@1.0.0")],
        },
        {
            "SPDXID": "SPDXRef-Package-commons-lang3",
            "name": "commons-lang3",
            "versionInfo": "3.12.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {"referenceCategory": "SECURITY",
                 "referenceType": "cpe23Type",
                 "referenceLocator": "cpe:2.3:a:apache:commons_lang3:3.12.0:*:*:*:*:*:*:*"},
                _purl_ref("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-lodash",
            "name": "lodash",
            "versionInfo": "4.17.21",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:npm/lodash@4.17.21")],
        },
        {
            "SPDXID": "SPDXRef-Package-core",
            "name": "core",
            "versionInfo": "16.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:npm/%40angular/core@16.0.0")],
        },
        {
            "SPDXID": "SPDXRef-Package-requests",
            "name": "requests",
            "versionInfo": "2.28.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:pypi/requests@2.28.0")],
        },
        {
            "SPDXID": "SPDXRef-Package-gin",
            "name": "gin",
            "versionInfo": "v1.9.1",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:golang/github.com/gin-gonic/gin@v1.9.1")],
        },
        {
            "SPDXID": "SPDXRef-Package-serde",
            "name": "serde",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:cargo/serde@1.0.0")],
        },
        # No purl (only a CPE ref): skipped, not guessed at.
        {
            "SPDXID": "SPDXRef-Package-mystery-lib",
            "name": "mystery-lib",
            "versionInfo": "0.1.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {"referenceCategory": "SECURITY",
                 "referenceType": "cpe23Type",
                 "referenceLocator": "cpe:2.3:a:example:mystery_lib:0.1.0:*:*:*:*:*:*:*"},
            ],
        },
        # Unsupported purl ecosystem: skipped.
        {
            "SPDXID": "SPDXRef-Package-rails",
            "name": "rails",
            "versionInfo": "7.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:gem/rails@7.0.0")],
        },
        # Version-less purl: skipped.
        {
            "SPDXID": "SPDXRef-Package-no-version",
            "name": "no-version",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:npm/no-version")],
        },
        # Qualifiers and subpath do not affect identity.
        {
            "SPDXID": "SPDXRef-Package-urllib3",
            "name": "urllib3",
            "versionInfo": "1.26.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [_purl_ref("pkg:pypi/urllib3@1.26.0?foo=bar#sub/path")],
        },
    ],
}


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_mixed_ecosystem_packages_parsed():
    deps = list(guardx._parse_spdx_sbom(SBOM))
    assert deps == [
        ("org.apache.commons:commons-lang3", "3.12.0", "Maven"),
        ("lodash", "4.17.21", "npm"),
        ("@angular/core", "16.0.0", "npm"),
        ("requests", "2.28.0", "PyPI"),
        ("github.com/gin-gonic/gin", "v1.9.1", "Go"),
        ("serde", "1.0.0", "crates.io"),
        ("urllib3", "1.26.0", "PyPI"),
    ]


def test_described_package_not_audited():
    deps = list(guardx._parse_spdx_sbom(SBOM))
    assert all(name != "myapp" for name, _, _ in deps)


def test_described_package_audited_when_not_listed():
    data = dict(SBOM)
    del data["documentDescribes"]
    deps = list(guardx._parse_spdx_sbom(data))
    assert ("myapp", "1.0.0", "npm") in deps


def test_non_purl_refs_do_not_yield():
    # A package whose only externalRefs are CPE/SWID is skipped.
    data = {"packages": [
        {"SPDXID": "SPDXRef-Package-x", "name": "x",
         "externalRefs": [
             {"referenceCategory": "SECURITY",
              "referenceType": "cpe23Type",
              "referenceLocator": "cpe:2.3:a:example:x:1.0:*:*:*:*:*:*:*"},
         ]},
    ]}
    assert list(guardx._parse_spdx_sbom(data)) == []


def test_non_sbom_data_yields_nothing():
    assert list(guardx._parse_spdx_sbom({})) == []
    assert list(guardx._parse_spdx_sbom({"packages": "nope"})) == []
    assert list(guardx._parse_spdx_sbom(None)) == []
    assert list(guardx._parse_spdx_sbom({"packages": ["nope", 42]})) == []
    assert list(guardx._parse_spdx_sbom(
        {"packages": [{"SPDXID": "SPDXRef-Package-x"}]})) == []


def test_is_spdx_detection():
    assert guardx._is_spdx({"spdxVersion": "SPDX-2.3"}, "report.json")
    assert guardx._is_spdx({"spdxVersion": "SPDX-2.2"}, "report.json")
    assert guardx._is_spdx({"spdxVersion": "spdx-2.3"}, "report.json")
    assert guardx._is_spdx({"packages": []}, "spdx.json")
    assert guardx._is_spdx({"packages": []}, "deps.spdx.json")
    # SPDX-3.x is a different major version, not claimed here.
    assert not guardx._is_spdx({"spdxVersion": "SPDX-3.0"}, "report.json")
    # A random JSON file with an incidental packages key is not an SBOM.
    assert not guardx._is_spdx({"packages": []}, "package.json")
    assert not guardx._is_spdx({"name": "x"}, "report.json")
    assert not guardx._is_spdx({"packages": "nope"}, "spdx.json")
    assert not guardx._is_spdx("nope", "spdx.json")


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


def test_sbom_detected_by_spdx_version_under_any_name(tmp_path):
    out, _ = _audit(tmp_path, "report.json", json.dumps(SBOM))
    assert "Ecosystems: Maven, npm, PyPI, Go, crates.io" in out
    assert "Dependencies checked: 7" in out


def test_sbom_detected_by_filename_without_spdx_version(tmp_path):
    data = dict(SBOM)
    del data["spdxVersion"]
    out, _ = _audit(tmp_path, "spdx.json", json.dumps(data))
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
        manifest = tmp_path / "sbom.spdx.json"
        manifest.write_text(json.dumps(SBOM))
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    assert "CVE-2023-1234" in out
    assert "urllib3==1.26.0" in out
    assert "upgrade to >= 1.26.18" in out


def test_non_sbom_json_still_unsupported(tmp_path):
    out, _ = _audit(tmp_path, "data.json", json.dumps({"packages": []}))
    assert "Unsupported manifest" in out
    assert "SPDX" in out
