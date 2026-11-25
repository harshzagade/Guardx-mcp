"""Unit tests for GuardX's Gradle (`build.gradle` / `build.gradle.kts`)
support in `audit_dependencies`.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`, following the same pattern as
`tests/test_maven_pom.py`. The stub `FastMCP.tool()` returns the
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


GROOVY = """\
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation "org.apache.commons:commons-lang3:3.12.0"
    api 'com.google.code.gson:gson:2.10.1'
    compileOnly "org.projectlombok:lombok:1.18.30"
    runtimeOnly 'com.h2database:h2:2.2.220'
    testImplementation "org.junit.jupiter:junit-jupiter:5.10.0"
    testImplementation group: 'org.mockito', name: 'mockito-core', version: '5.5.0'
    // implementation "org.skipped:commented-out:9.9.9"
    implementation libs.spring.core
    implementation project(':shared')
    implementation platform("org.springframework.boot:spring-boot-dependencies:3.1.0")
    implementation "com.example:dynamic:1.+"
    implementation "com.example:latest:latest.release"
    implementation "com.example:interp:${libVersion}"
    implementation files('libs/local.jar')
}
"""

KOTLIN = """\
plugins {
    kotlin("jvm") version "1.9.0"
}

dependencies {
    implementation("org.apache.commons:commons-lang3:3.12.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    implementation(group = "org.jetbrains.kotlin", name = "kotlin-stdlib", version = "1.9.0")
    implementation("org.example:snapshot:1.0.0-SNAPSHOT")
    implementation(libs.spring.core)
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.1.0"))
}
"""


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_groovy_dsl_parsed_with_group_artifact_names():
    deps = dict(guardx._parse_gradle(GROOVY))
    assert deps == {
        "org.apache.commons:commons-lang3": "3.12.0",
        "com.google.code.gson:gson": "2.10.1",
        "org.projectlombok:lombok": "1.18.30",
        "com.h2database:h2": "2.2.220",
        "org.junit.jupiter:junit-jupiter": "5.10.0",
        "org.mockito:mockito-core": "5.5.0",
    }


def test_kotlin_dsl_parsed_with_group_artifact_names():
    deps = dict(guardx._parse_gradle(KOTLIN))
    assert deps == {
        "org.apache.commons:commons-lang3": "3.12.0",
        "org.junit.jupiter:junit-jupiter": "5.10.0",
        "org.jetbrains.kotlin:kotlin-stdlib": "1.9.0",
        "org.example:snapshot": "1.0.0-SNAPSHOT",
    }


def test_version_catalog_project_platform_and_files_skipped():
    deps = dict(guardx._parse_gradle(GROOVY))
    assert "org.springframework.boot:spring-boot-dependencies" not in deps
    assert not any(name.startswith("libs.") for name in deps)
    assert not any(":shared" in name for name in deps)
    assert "libs/local.jar" not in deps


def test_dynamic_and_interpolated_versions_skipped():
    deps = dict(guardx._parse_gradle(GROOVY))
    assert "com.example:dynamic" not in deps
    assert "com.example:latest" not in deps
    assert "com.example:interp" not in deps


def test_commented_out_dependency_skipped():
    deps = dict(guardx._parse_gradle(GROOVY))
    assert "org.skipped:commented-out" not in deps


def test_buildscript_classpath_parsed():
    text = """buildscript {
    dependencies {
        classpath "com.gradle:gradle-enterprise:3.13.4"
    }
}
"""
    assert list(guardx._parse_gradle(text)) == [
        ("com.gradle:gradle-enterprise", "3.13.4")]


def test_non_dependency_lines_ignored():
    text = """plugins {
    id 'java'
}
group = 'com.example'
version = '1.0.0'
description "org.foo:bar:1.2.3"
"""
    assert list(guardx._parse_gradle(text)) == []


def test_empty_build_file_yields_nothing():
    assert list(guardx._parse_gradle("")) == []
    assert list(guardx._parse_gradle("dependencies {\n}\n")) == []


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


def test_gradle_audit_queries_maven_ecosystem(tmp_path):
    out, client = _audit(tmp_path, "build.gradle", GROOVY)
    assert "Ecosystem: Maven" in out
    assert "Dependencies checked: 6" in out
    queries = [q for _, p in client.posts for q in p["queries"]]
    assert len(client.posts) == 1  # one querybatch call, not one per package
    assert all(q["package"]["ecosystem"] == "Maven" for q in queries)
    by_name = {q["package"]["name"]: q["version"] for q in queries}
    assert by_name["org.apache.commons:commons-lang3"] == "3.12.0"
    assert by_name["com.google.code.gson:gson"] == "2.10.1"
    assert "No known vulnerabilities found. [OK]" in out


def test_gradle_kts_audit_queries_maven_ecosystem(tmp_path):
    out, client = _audit(tmp_path, "build.gradle.kts", KOTLIN)
    assert "Ecosystem: Maven" in out
    assert "Dependencies checked: 4" in out
    queries = [q for _, p in client.posts for q in p["queries"]]
    assert all(q["package"]["ecosystem"] == "Maven" for q in queries)


def test_gradle_vuln_reported(tmp_path):
    class VulnClient(FakeClient):
        async def post(self, url: str, json: dict):
            self.posts.append((url, json))
            if "queries" in json:
                return FakeResponse(payload={"results": [
                    {"vulns": ([{"id": "GHSA-xxxx-yyyy-zzzz",
                                 "summary": "test gradle vuln"}]
                               if q["package"]["name"]
                               == "com.google.code.gson:gson"
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
        manifest = tmp_path / "build.gradle"
        manifest.write_text(GROOVY)
        out = run(guardx.audit_dependencies(str(manifest)))
    finally:
        httpx_stub.AsyncClient = orig
    assert "com.google.code.gson:gson==2.10.1" in out
    assert "GHSA-xxxx-yyyy-zzzz" in out
    assert "Vulnerable packages: 1" in out


def test_gradle_without_dependencies_reports_cleanly(tmp_path):
    out, _ = _audit(tmp_path, "build.gradle", "dependencies {\n}\n")
    assert "No pinned dependencies found" in out


def test_unsupported_manifest_message_lists_gradle(tmp_path):
    manifest = tmp_path / "Gemfile"
    manifest.write_text("gem 'rails'\n")
    out = run(guardx.audit_dependencies(str(manifest)))
    assert "build.gradle" in out
