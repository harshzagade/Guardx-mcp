"""Unit tests for GuardX's Maven `pom.xml` support in
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


POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>

  <properties>
    <spring.version>5.3.30</spring.version>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.example</groupId>
        <artifactId>managed-only</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unversioned</artifactId>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unresolvable</artifactId>
      <version>${no.such.property}</version>
    </dependency>
  </dependencies>
</project>
"""


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_namespaced_pom_parsed_with_group_artifact_names():
    deps = dict(guardx._parse_pom_xml(POM))
    assert deps == {
        "org.apache.commons:commons-lang3": "3.12.0",
        "org.springframework:spring-core": "5.3.30",
        "com.fasterxml.jackson.core:jackson-databind": "2.15.2",
    }


def test_dependency_management_entries_skipped():
    deps = dict(guardx._parse_pom_xml(POM))
    assert "org.example:managed-only" not in deps


def test_unversioned_and_unresolvable_entries_skipped():
    deps = dict(guardx._parse_pom_xml(POM))
    assert "org.example:unversioned" not in deps
    assert "org.example:unresolvable" not in deps


def test_property_reference_resolved_from_properties_block():
    text = """<project><properties><lib.version>1.2.3</lib.version></properties>
<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
<version>${lib.version}</version></dependency></dependencies></project>"""
    assert list(guardx._parse_pom_xml(text)) == [("g:a", "1.2.3")]


def test_namespace_free_pom_parses_the_same():
    text = """<project><dependencies><dependency><groupId>g</groupId>
<artifactId>a</artifactId><version>0.1.0</version></dependency>
</dependencies></project>"""
    assert list(guardx._parse_pom_xml(text)) == [("g:a", "0.1.0")]


def test_malformed_xml_yields_nothing():
    assert list(guardx._parse_pom_xml("<project><dependencies>")) == []
    assert list(guardx._parse_pom_xml("")) == []


def test_empty_dependencies_yields_nothing():
    assert list(guardx._parse_pom_xml("<project></project>")) == []


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


def test_pom_audit_queries_maven_ecosystem(tmp_path):
    out, client = _audit(tmp_path, "pom.xml", POM)
    assert "Ecosystem: Maven" in out
    assert "Dependencies checked: 3" in out
    queries = [q for _, p in client.posts for q in p["queries"]]
    assert len(client.posts) == 1  # one querybatch call, not one per package
    assert all(q["package"]["ecosystem"] == "Maven" for q in queries)
    by_name = {q["package"]["name"]: q["version"] for q in queries}
    assert by_name["org.apache.commons:commons-lang3"] == "3.12.0"
    assert by_name["org.springframework:spring-core"] == "5.3.30"
    assert "No known vulnerabilities found. [OK]" in out


def test_pom_vuln_reported(tmp_path):
    class VulnClient(FakeClient):
        async def post(self, url: str, json: dict):
            self.posts.append((url, json))
            if "queries" in json:
                return FakeResponse(payload={"results": [
                    {"vulns": ([{"id": "GHSA-xxxx-yyyy-zzzz",
                                 "summary": "test maven vuln"}]
                               if q["package"]["name"]
                               == "com.fasterxml.jackson.core:jackson-databind"
                               else [])}
                    for q in json["queries"]]})
            vulns = [{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "test maven vuln"}] \
                if json["package"]["name"] == "com.fasterxml.jackson.core:jackson-databind" \
                else []
            return FakeResponse(payload={"vulns": vulns})

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
        manifest = tmp_path / "pom.xml"
        manifest.write_text(POM)
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    assert "com.fasterxml.jackson.core:jackson-databind==2.15.2" in out
    assert "GHSA-xxxx-yyyy-zzzz" in out
    assert "Vulnerable packages: 1" in out


def test_pom_without_dependencies_reports_cleanly(tmp_path):
    out, _ = _audit(tmp_path, "pom.xml", "<project></project>")
    assert "No pinned dependencies found" in out


def test_unsupported_manifest_message_lists_pom_xml(tmp_path):
    manifest = tmp_path / "Gemfile"
    manifest.write_text("gem 'rails'\n")
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "pom.xml" in out
