"""Unit tests for GuardX's `scan_secrets` config-file
credential heuristic: credential-named keys with real-looking
values in .env / YAML / JSON / INI files are MED findings even
when no known pattern matches (unquoted values, `:` assignments).

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
    "guardx_server_config", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path, name, content):
    fp = tmp_path / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    return str(fp)


class TestConfigCredentials:
    def test_env_unquoted_password_flagged(self, tmp_path):
        fp = _write(tmp_path, ".env", "DB_PASSWORD=hunter2\n")
        report = server.scan_secrets(fp)
        assert "[MED] Config Credential" in report
        assert "MED: 1" in report

    def test_yaml_colon_assignment_flagged(self, tmp_path):
        fp = _write(tmp_path, "config.yaml", "db_password: hunter2\n")
        assert "[MED] Config Credential" in server.scan_secrets(fp)

    def test_json_quoted_key_value_flagged(self, tmp_path):
        fp = _write(tmp_path, "settings.json",
                    '{\n  "api_token": "hunter2"\n}\n')
        assert "[MED] Config Credential" in server.scan_secrets(fp)

    def test_ini_section_assignment_flagged(self, tmp_path):
        fp = _write(tmp_path, "app.ini", "[db]\npassword = hunter2\n")
        assert "[MED] Config Credential" in server.scan_secrets(fp)

    def test_code_file_same_line_not_flagged(self, tmp_path):
        # The heuristic is config-files only: the same unquoted
        # assignment in a .py file stays clean.
        fp = _write(tmp_path, "app.py", "DB_PASSWORD=hunter2\n")
        report = server.scan_secrets(fp)
        assert "Config Credential" not in report
        assert "No hardcoded secrets detected" in report

    def test_placeholder_and_reference_values_skipped(self, tmp_path):
        fp = _write(tmp_path, ".env",
                    "DB_PASSWORD=changeme\n"
                    "API_TOKEN=${API_TOKEN}\n"
                    "SESSION_SECRET=********\n"
                    "OTHER_SECRET=\n")
        assert "No hardcoded secrets detected" in server.scan_secrets(fp)

    def test_non_credential_key_names_stay_clean(self, tmp_path):
        fp = _write(tmp_path, ".env",
                    "PASSWORD_LENGTH=12\n"
                    "SECRET_SANTA=alice\n"
                    "APP_NAME=myapp\n")
        assert "No hardcoded secrets detected" in server.scan_secrets(fp)

    def test_known_pattern_wins_over_config_heuristic(self, tmp_path):
        # A quoted generic assignment matches the pattern suite first,
        # so the finding keeps its pattern name, not Config Credential.
        fp = _write(tmp_path, ".env", 'api_key = "longsecretvalue"\n')
        report = server.scan_secrets(fp)
        assert "Generic Secret Assignment" in report
        assert "Config Credential" not in report

    def test_config_finding_masked_in_json(self, tmp_path):
        import json
        fp = _write(tmp_path, ".env", "DB_PASSWORD=hunter2\n")
        data = json.loads(server.scan_secrets(fp, json_output=True))
        assert data["findings"][0]["type"] == "Config Credential"
        assert "hunter2" not in json.dumps(data)
