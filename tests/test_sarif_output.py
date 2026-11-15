"""Unit tests for the SARIF 2.1.0 output mode of `scan_secrets`.

With `sarif_output=True` the report is emitted as SARIF JSON (one rule
per finding type, one result per finding, HIGH→error / MED→warning /
LOW→note) for GitHub code scanning and other SARIF consumers. `mcp` and
`httpx` are stubbed exactly like the other suites — no packages are
installed to run these tests.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs (same shape as tests/test_scan_secrets.py)
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

# Load under a module name unique to this file so re-executing server.py
# cannot clobber another test module's copy in sys.modules.
_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_sarif",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _token(tag: str = "A") -> str:
    # Built by concatenation so no literal secret-shaped string lands
    # in this file (GitHub push protection rejects those even in tests).
    return "ghp_" + tag * 36


def _sarif(tmp_path, **kwargs):
    return json.loads(server.scan_secrets(str(tmp_path), sarif_output=True, **kwargs))


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


class TestSarifOutput:
    def test_shape_levels_and_locations(self, tmp_path):
        token = _token()
        (tmp_path / "a.py").write_text(f'TOKEN = "{token}"\n')
        # MED: generic secret assignment; LOW: long high-entropy string
        # (28 distinct chars, ~4.8 bits/char — above the 4.0 threshold).
        (tmp_path / "b.py").write_text(
            'password = "abcdefgh"\n'
            'x = "aB3dF7hJ2kL9mN4pQ6rS8tU1vW5"\n'
        )
        doc = _sarif(tmp_path)
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "GuardX"
        assert len(run["results"]) == 3
        by_rule = {r["ruleId"]: r for r in run["results"]}
        assert by_rule["GitHub Token"]["level"] == "error"
        assert by_rule["Generic Secret Assignment"]["level"] == "warning"
        assert by_rule["High-Entropy String"]["level"] == "note"
        # Masked preview in the message, raw secret nowhere in the SARIF.
        assert server._mask(token) in by_rule["GitHub Token"]["message"]["text"]
        assert token not in json.dumps(doc)
        # Locations are relative to the scan root with a 1-based line.
        loc = by_rule["GitHub Token"]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "a.py"
        assert loc["region"]["startLine"] == 1
        loc_b = by_rule["Generic Secret Assignment"]["locations"][0]["physicalLocation"]
        assert loc_b["artifactLocation"]["uri"] == "b.py"
        assert loc_b["region"]["startLine"] == 1
        # Run properties carry the scan counts.
        props = run["properties"]
        assert props["filesScanned"] == 2
        assert props["findingsCount"] == 3
        assert props["uniqueSecrets"] == 3
        assert props["suppressedCount"] == 0
        assert props["skippedLargeFiles"] == 0

    def test_one_rule_per_type(self, tmp_path):
        (tmp_path / "a.py").write_text(
            f'A = "{_token("A")}"\nB = "{_token("B")}"\n'
        )
        doc = _sarif(tmp_path)
        run = doc["runs"][0]
        assert len(run["results"]) == 2
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "GitHub Token"
        assert rules[0]["defaultConfiguration"]["level"] == "error"

    def test_clean_scan_is_valid_empty_sarif(self, tmp_path):
        (tmp_path / "a.py").write_text("print('clean')\n")
        doc = _sarif(tmp_path)
        run = doc["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
        assert run["properties"]["filesScanned"] == 1
        assert run["properties"]["findingsCount"] == 0

    def test_json_and_sarif_conflict(self, tmp_path):
        (tmp_path / "a.py").write_text("print('clean')\n")
        out = server.scan_secrets(
            str(tmp_path), json_output=True, sarif_output=True
        )
        parsed = json.loads(out)
        assert "json_output and sarif_output" in parsed["error"]

    def test_skipped_large_files_in_properties(self, tmp_path):
        (tmp_path / "small.py").write_text("print('clean')\n")
        line = f'TOKEN = "{_token()}"\n'.encode()
        (tmp_path / "big.py").write_bytes(
            line + b"x" * (server.MAX_FILE_BYTES + 10)
        )
        doc = _sarif(tmp_path)
        props = doc["runs"][0]["properties"]
        assert props["skippedLargeFiles"] == 1
        assert props["filesScanned"] == 1

    def test_history_finding_carries_commit(self, tmp_path):
        _git("init", cwd=str(tmp_path))
        _git("config", "user.email", "test@example.com", cwd=str(tmp_path))
        _git("config", "user.name", "Test", cwd=str(tmp_path))
        (tmp_path / "app.py").write_text(f'TOKEN = "{_token()}"\n')
        _git("add", "-A", cwd=str(tmp_path))
        _git("commit", "-q", "-m", "add token", cwd=str(tmp_path))
        short = _git("rev-parse", "--short", "HEAD", cwd=str(tmp_path)).stdout.strip()
        (tmp_path / "app.py").write_text('print("clean")\n')
        _git("add", "-A", cwd=str(tmp_path))
        _git("commit", "-q", "-m", "remove token", cwd=str(tmp_path))

        doc = _sarif(tmp_path, history=True)
        run = doc["runs"][0]
        assert len(run["results"]) == 1
        assert run["results"][0]["properties"]["commit"] == short
        assert run["properties"]["history"]["commits_scanned"] == 2
