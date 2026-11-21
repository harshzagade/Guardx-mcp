"""Unit tests for GuardX's same-secret-same-file collapse in
`scan_secrets`: the same secret pasted on several lines of one file
is a single finding listing every line number, instead of one
finding per line.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic. Scans run against `tmp_path`
fixtures — no real target is ever touched. Secrets below are deliberately
fake formats the patterns recognise, never real credentials.
"""

from __future__ import annotations

import importlib.util
import json as jsonlib
import subprocess
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
    "guardx_server_collapse", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path, name, content):
    fp = tmp_path / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    return str(fp)


def _token(tag="a"):
    # Built by concatenation so this test file itself never holds a
    # literal full token string.
    return "ghp_" + tag * 36


# ---------------------------------------------------------------------------
# Same-secret-same-file collapse
# ---------------------------------------------------------------------------

class TestSameSecretCollapse:
    def test_collapsed_finding_lists_all_lines(self, tmp_path):
        secret = _token()
        fp = _write(
            tmp_path, "a.py",
            f'TOKEN = "{secret}"\n'
            'print("x")\n'
            f'KEY = "{secret}"\n'
            'print("y")\n'
            f'AGAIN = "{secret}"\n',
        )
        report = server.scan_secrets(fp)
        assert "Findings: 1 (HIGH: 1, MED: 0, LOW: 0)" in report
        assert "Unique secrets: 1" in report
        # All three occurrences are listed on the one finding.
        assert "a.py:1, 3, 5" in report
        # Per-file counts count the collapsed finding once (full path,
        # like the existing per-file tests).
        assert f"{fp}: 1" in report

    def test_json_carries_lines_array(self, tmp_path):
        secret = _token()
        fp = _write(
            tmp_path, "a.py",
            f'TOKEN = "{secret}"\nKEY = "{secret}"\n',
        )
        payload = jsonlib.loads(server.scan_secrets(fp, json_output=True))
        assert payload["findings_count"] == 1
        finding = payload["findings"][0]
        assert finding["line"] == 1  # first line, for existing consumers
        assert finding["lines"] == [1, 2]
        assert secret not in jsonlib.dumps(payload)

    def test_sarif_carries_lines_property(self, tmp_path):
        secret = _token()
        fp = _write(
            tmp_path, "a.py",
            f'TOKEN = "{secret}"\nKEY = "{secret}"\n',
        )
        doc = jsonlib.loads(server.scan_secrets(fp, sarif_output=True))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        result = results[0]
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
        assert result["properties"]["lines"] == [1, 2]

    def test_single_line_finding_has_no_sarif_lines_property(self, tmp_path):
        fp = _write(tmp_path, "a.py", f'TOKEN = "{_token()}"\n')
        doc = jsonlib.loads(server.scan_secrets(fp, sarif_output=True))
        result = doc["runs"][0]["results"][0]
        assert "properties" not in result

    def test_different_secrets_stay_separate(self, tmp_path):
        fp = _write(
            tmp_path, "a.py",
            f'A = "{_token("a")}"\nB = "{_token("b")}"\n',
        )
        report = server.scan_secrets(fp)
        assert "Findings: 2" in report
        assert "a.py:1" in report and "a.py:2" in report

    def test_same_secret_in_two_files_stays_two_findings(self, tmp_path):
        secret = _token()
        _write(tmp_path, "a.py", f'TOKEN = "{secret}"\n')
        _write(tmp_path, "b.py", f'KEY = "{secret}"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 2" in report
        assert "a.py:1" in report
        assert "b.py:1" in report

    def test_max_findings_counts_collapsed_finding_once(self, tmp_path):
        # The cap counts distinct findings: a secret pasted on two
        # lines is one finding, so a second distinct secret still
        # fits under a cap of 2 — and the folded line is listed,
        # because the scan had not hit the cap when it was read.
        secret = _token()
        fp = _write(
            tmp_path, "a.py",
            f'TOKEN = "{secret}"\n'
            f'KEY = "{secret}"\n'
            f'OTHER = "{_token("b")}"\n'
            f'THIRD = "{_token("c")}"\n',
        )
        payload = jsonlib.loads(
            server.scan_secrets(fp, json_output=True, max_findings=2)
        )
        assert payload["findings_count"] == 2
        assert payload["findings"][0]["lines"] == [1, 2]
        assert payload["findings"][1]["line"] == 3


# ---------------------------------------------------------------------------
# History mode: collapse is per commit
# ---------------------------------------------------------------------------

def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


def _init_repo(tmp_path: Path) -> Path:
    _git("init", cwd=str(tmp_path))
    _git("config", "user.email", "test@example.com", cwd=str(tmp_path))
    _git("config", "user.name", "Test", cwd=str(tmp_path))
    return tmp_path


def _commit(repo: Path, message: str) -> str:
    _git("add", "-A", cwd=str(repo))
    _git("commit", "-q", "-m", message, cwd=str(repo))
    return _git("rev-parse", "--short", "HEAD", cwd=str(repo)).stdout.strip()


class TestHistoryCollapse:
    def test_collapse_within_one_commit_only(self, tmp_path):
        repo = _init_repo(tmp_path)
        secret = _token()
        (repo / "a.py").write_text(
            f'TOKEN = "{secret}"\nKEY = "{secret}"\n'
        )
        first = _commit(repo, "secret twice")
        with open(repo / "a.py", "a") as fh:
            fh.write(f'AGAIN = "{secret}"\n')
        second = _commit(repo, "secret again")
        payload = jsonlib.loads(
            server.scan_secrets(str(repo), history=True, json_output=True)
        )
        # The two occurrences from the first commit collapse; the
        # re-added occurrence in the second commit is its own finding.
        assert payload["findings_count"] == 2
        by_commit = {f["commit"]: f for f in payload["findings"]}
        assert by_commit[first]["lines"] == [1, 2]
        assert by_commit[second]["lines"] == [3]
