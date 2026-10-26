"""Unit tests for GuardX's entropy-based LOW findings in `scan_secrets`.

Lines no known pattern matches are checked for long high-entropy quoted
strings (a catch for custom token formats). `mcp` and `httpx` are stubbed
exactly like the other GuardX suites; scans run against `tmp_path`
fixtures — no real target is ever touched.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


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
    "guardx_server_entropy", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path: Path, name: str, content: str) -> str:
    fp = tmp_path / name
    fp.write_text(content)
    return str(fp)


# A mixed-alphabet custom token no known pattern matches (Shannon
# entropy ~4.86 bits/char, well above the 4.0 threshold). The variable
# name deliberately carries no credential keyword, so the generic
# assignment pattern cannot fire either.
CUSTOM_TOKEN = "Xk9mQ2zR7vT4wY8aB1cD3eF5gH6jK"


class TestEntropyFindings:
    def test_high_entropy_custom_token_is_low(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'misc = "{CUSTOM_TOKEN}"\n')
        report = server.scan_secrets(fp)
        assert "[LOW] High-Entropy String" in report
        assert "Findings: 1 (HIGH: 0, MED: 0, LOW: 1)" in report
        assert CUSTOM_TOKEN not in report  # still masked

    def test_entropy_helper_fires_where_patterns_do_not(self, tmp_path):
        line = f'misc = "{CUSTOM_TOKEN}"\n'
        assert server._match_line(line) is None
        hit = server._entropy_hit(line)
        assert hit is not None
        assert hit[0] == "High-Entropy String" and hit[1] == "LOW"
        assert hit[2] == CUSTOM_TOKEN

    def test_known_pattern_takes_precedence(self, tmp_path):
        # One finding per line: a real GitHub token stays HIGH, the
        # entropy fallback never upgrades or duplicates it.
        secret = "ghp_" + "a" * 36
        fp = _write(tmp_path, "app.py", f'TOKEN = "{secret}"\n')
        report = server.scan_secrets(fp)
        assert "[HIGH] GitHub Token" in report
        assert "High-Entropy String" not in report
        assert "Findings: 1" in report

    def test_low_entropy_long_string_stays_clean(self, tmp_path):
        # Plain English, 29 chars, entropy ~3.78 — below the threshold.
        fp = _write(
            tmp_path, "app.py", 'misc = "thisisaverylongpasswordstring"\n'
        )
        report = server.scan_secrets(fp)
        assert "No hardcoded secrets detected. [OK]" in report

    def test_pure_hex_hash_stays_clean(self, tmp_path):
        # An MD5 hex digest (32 chars, entropy ~3.39) is a hash, not a
        # token: the threshold deliberately leaves it alone.
        fp = _write(
            tmp_path, "app.py",
            'misc = "d41d8cd98f00b204e9800998ecf8427e"\n',
        )
        report = server.scan_secrets(fp)
        assert "No hardcoded secrets detected. [OK]" in report

    def test_short_random_string_stays_clean(self, tmp_path):
        fp = _write(tmp_path, "app.py", 'misc = "Xk9mQ2zR7vT4"\n')
        report = server.scan_secrets(fp)
        assert "No hardcoded secrets detected. [OK]" in report

    def test_repeated_char_string_stays_clean(self, tmp_path):
        fp = _write(tmp_path, "app.py", 'misc = "' + "a" * 30 + '"\n')
        report = server.scan_secrets(fp)
        assert "No hardcoded secrets detected. [OK]" in report

    def test_one_finding_per_line_even_with_two_tokens(self, tmp_path):
        # Two high-entropy quoted strings on one line still yield a
        # single finding (the one-finding-per-line rule).
        other = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1x"
        fp = _write(
            tmp_path, "app.py",
            f'misc = "{CUSTOM_TOKEN}"; other = "{other}"\n',
        )
        report = server.scan_secrets(fp)
        assert "Findings: 1" in report

    def test_json_carries_entropy_finding_masked(self, tmp_path):
        import json as jsonlib
        fp = _write(tmp_path, "app.py", f'misc = "{CUSTOM_TOKEN}"\n')
        payload = jsonlib.loads(server.scan_secrets(fp, json_output=True))
        finding = payload["findings"][0]
        assert finding["type"] == "High-Entropy String"
        assert finding["severity"] == "LOW"
        assert CUSTOM_TOKEN not in jsonlib.dumps(payload)
        assert finding["match"] == server._mask(CUSTOM_TOKEN)
