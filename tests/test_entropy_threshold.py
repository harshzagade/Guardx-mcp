"""Unit tests for the tunable entropy threshold in `scan_secrets`.

`scan_secrets(entropy_threshold=...)` lets a noisy codebase raise (or
lower) the high-entropy bar per run instead of disabling the check
outright. `mcp` and `httpx` are stubbed exactly like the other GuardX
suites; scans run against `tmp_path` fixtures — no real target is ever
touched.
"""

from __future__ import annotations

import importlib.util
import json as jsonlib
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
    "guardx_server_entropy_threshold",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path: Path, name: str, content: str) -> str:
    fp = tmp_path / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    return str(fp)


# 20 chars, Shannon entropy 4.322: caught at the default 4.0 threshold,
# missed when the bar is raised to 4.5.
HIGH_ENTROPY = "aB3xK9mQ2vZ8pL5wR7tY"
# 20 chars, Shannon entropy 3.322: missed at the default 4.0 threshold,
# caught when the bar is lowered to 3.0.
LOW_ENTROPY = "aabbccddeeffgghhiijj"


class TestEntropyThresholdArgument:
    def test_default_threshold_unchanged(self, tmp_path):
        high = _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        low = _write(tmp_path, "other.py", f'misc = "{LOW_ENTROPY}"\n')
        assert "High-Entropy String" in server.scan_secrets(high)
        assert "High-Entropy String" not in server.scan_secrets(low)

    def test_raised_threshold_suppresses_borderline_string(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        report = server.scan_secrets(fp, entropy_threshold=4.5)
        assert "No hardcoded secrets detected. [OK]" in report

    def test_lowered_threshold_catches_borderline_string(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'misc = "{LOW_ENTROPY}"\n')
        report = server.scan_secrets(fp, entropy_threshold=3.0)
        assert "[LOW] High-Entropy String" in report
        assert "Findings: 1 (HIGH: 0, MED: 0, LOW: 1)" in report

    def test_invalid_threshold_is_error(self, tmp_path):
        fp = _write(tmp_path, "app.py", "x = 1\n")
        for bad in (-1, 0, 8.5, "high", True):
            report = server.scan_secrets(fp, entropy_threshold=bad)
            assert report == (
                "Error: entropy_threshold must be a number "
                "between 0 and 8"
            ), bad

    def test_invalid_threshold_is_json_error(self, tmp_path):
        fp = _write(tmp_path, "app.py", "x = 1\n")
        payload = jsonlib.loads(
            server.scan_secrets(fp, entropy_threshold=9, json_output=True)
        )
        assert payload["error"] == (
            "entropy_threshold must be a number between 0 and 8"
        )

    def test_boundary_thresholds_accepted(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        # 8 is the top of the range: accepted, and nothing this
        # high-entropy is ever flagged.
        report = server.scan_secrets(fp, entropy_threshold=8)
        assert "No hardcoded secrets detected. [OK]" in report
        # Just above 0: accepted, and the 3.322-entropy string is caught.
        low = _write(tmp_path, "other.py", f'misc = "{LOW_ENTROPY}"\n')
        assert "High-Entropy String" in server.scan_secrets(
            low, entropy_threshold=0.1
        )

    def test_explicit_argument_beats_config(self, tmp_path):
        _write(tmp_path, "app.py", f'misc = "{LOW_ENTROPY}"\n')
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\nentropy_threshold = 4.5\n")
        # Config alone would miss the 3.322 string; the explicit 3.0
        # wins and catches it.
        assert "High-Entropy String" in server.scan_secrets(
            str(tmp_path), entropy_threshold=3.0
        )
        _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\nentropy_threshold = 3.0\n")
        # Config alone would catch the 4.322 string; the explicit 4.5
        # wins and misses it.
        assert "High-Entropy String" not in server.scan_secrets(
            str(tmp_path), entropy_threshold=4.5
        )

    def test_json_config_reports_effective_threshold(self, tmp_path):
        _write(tmp_path, "app.py", f'misc = "{LOW_ENTROPY}"\n')
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\nentropy_threshold = 4.5\n")
        payload = jsonlib.loads(server.scan_secrets(
            str(tmp_path), entropy_threshold=3.0, json_output=True
        ))
        assert payload["config"]["entropy_threshold"] == 3.0
        assert payload["findings"][0]["type"] == "High-Entropy String"

    def test_generate_baseline_honors_threshold(self, tmp_path):
        _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        digest = server._finding_hash(
            "app.py", "High-Entropy String", HIGH_ENTROPY
        )
        # Default bar: the hash is generated.
        assert server.generate_baseline(str(tmp_path)) == digest + "\n"
        # Raised bar: nothing to acknowledge.
        assert server.generate_baseline(
            str(tmp_path), entropy_threshold=4.5
        ) == ""
        # Invalid value is an error, like scan_secrets.
        assert server.generate_baseline(
            str(tmp_path), entropy_threshold=9
        ).startswith("Error: entropy_threshold must be a number")
