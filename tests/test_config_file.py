"""Unit tests for GuardX's `.guardx.toml` config file support.

A `.guardx.toml` at the scan root (or an explicit `config=` path)
holds repo-level `[scan_secrets]` defaults — `exclude` patterns, an
`entropy_threshold`, and a `baseline` path — so CI runs stop repeating
the same flags. Explicit `exclude=` / `baseline=` arguments always win
over the config; a malformed config is an error.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic. Scans run against `tmp_path`
fixtures — no real target is ever touched.
"""

from __future__ import annotations

import importlib.util
import json
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


FAKE_KEY = "AKIA" + "A" * 16  # format-valid, not a real credential
# 20 chars, Shannon entropy 4.322: caught at the default 4.0 threshold,
# missed when the config raises it to 4.5.
HIGH_ENTROPY = "aB3xK9mQ2vZ8pL5wR7tY"
# 20 chars, Shannon entropy 3.322: missed at the default 4.0 threshold,
# caught when the config lowers it to 3.0.
LOW_ENTROPY = "aabbccddeeffgghhiijj"


class TestConfigFile:
    def test_config_exclude_string_skips_file(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "fixtures/data.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nexclude = "fixtures/*"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 1" in report
        assert "fixtures/data.py" not in report
        assert "Config: .guardx.toml" in report

    def test_config_exclude_list_skips_files(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "a.min.js", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "vendor/b.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nexclude = ["*.min.js", "vendor/*"]\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 1" in report
        assert "a.min.js" not in report
        assert "vendor/b.py" not in report

    def test_explicit_exclude_overrides_config(self, tmp_path):
        _write(tmp_path, "keep.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, "drop.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nexclude = "keep.py"\n')
        # The explicit flag replaces the config list entirely: keep.py is
        # scanned again, drop.py is skipped.
        report = server.scan_secrets(str(tmp_path), exclude="drop.py")
        assert "Findings: 1" in report
        assert "keep.py" in report
        assert "drop.py" not in report

    def test_config_baseline_suppresses(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        digest = server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
        _write(tmp_path, "reviewed.txt", digest + "\n")
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nbaseline = "reviewed.txt"\n')
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 0 (HIGH: 0, MED: 0, LOW: 0)" in report
        assert "Suppressed: 1 acknowledged" in report

    def test_explicit_baseline_overrides_config(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        digest = server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
        _write(tmp_path, "reviewed.txt", digest + "\n")
        _write(tmp_path, "empty.txt", "")
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nbaseline = "reviewed.txt"\n')
        # The explicit (empty) baseline wins: the finding is reported.
        report = server.scan_secrets(str(tmp_path), baseline=str(tmp_path / "empty.txt"))
        assert "Findings: 1" in report
        assert "Suppressed" not in report

    def test_config_baseline_path_missing_is_error(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nbaseline = "no-such-file.txt"\n')
        report = server.scan_secrets(str(tmp_path))
        assert report.startswith("Error: baseline does not exist:")

    def test_config_entropy_threshold_raises_bar(self, tmp_path):
        _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        # Default threshold (4.0) catches the 4.322-entropy string.
        assert "High-Entropy String" in server.scan_secrets(str(tmp_path))
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\nentropy_threshold = 4.5\n")
        assert "High-Entropy String" not in server.scan_secrets(str(tmp_path))

    def test_config_entropy_threshold_lowers_bar(self, tmp_path):
        _write(tmp_path, "app.py", f'misc = "{LOW_ENTROPY}"\n')
        # Default threshold (4.0) misses the 3.322-entropy string.
        assert "High-Entropy String" not in server.scan_secrets(str(tmp_path))
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\nentropy_threshold = 3.0\n")
        assert "High-Entropy String" in server.scan_secrets(str(tmp_path))

    def test_config_entropy_threshold_invalid_is_error(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        for bad in ("9", "-1", '"high"', "true"):
            _write(tmp_path, ".guardx.toml",
                   f"[scan_secrets]\nentropy_threshold = {bad}\n")
            report = server.scan_secrets(str(tmp_path))
            assert report.startswith("Error: invalid config .guardx.toml:"), bad

    def test_malformed_config_is_error(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        _write(tmp_path, ".guardx.toml", "[scan_secrets]\nthis is not toml\n")
        report = server.scan_secrets(str(tmp_path))
        assert report.startswith("Error: invalid config .guardx.toml:")

    def test_explicit_config_path_missing_is_error(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        report = server.scan_secrets(str(tmp_path),
                                     config=str(tmp_path / "nope.toml"))
        assert report.startswith("Error: config does not exist:")

    def test_explicit_config_path_loads(self, tmp_path):
        # Config lives outside the scanned tree; its baseline path is
        # resolved relative to the config file, not the scan root.
        cfg_dir = tmp_path / "cfg"
        cfg_dir.mkdir()
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        digest = server._finding_hash("app.py", "AWS Access Key ID", FAKE_KEY)
        (cfg_dir / "reviewed.txt").write_text(digest + "\n")
        (cfg_dir / "guardx.toml").write_text(
            '[scan_secrets]\nbaseline = "reviewed.txt"\n')
        report = server.scan_secrets(str(tmp_path),
                                     config=str(cfg_dir / "guardx.toml"))
        assert "Findings: 0" in report
        assert "Suppressed: 1 acknowledged" in report

    def test_config_file_itself_not_scanned(self, tmp_path):
        # A secret-shaped value inside the config (an unknown key) must
        # not be reported: the config file is skipped like the baseline.
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\n"
               "exclude = \"vendor/*\"\n"
               f"note = \"ghp_{'b' * 36}\"\n")
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 0" in report
        assert "GitHub Token" not in report

    def test_unknown_keys_and_sections_ignored(self, tmp_path):
        _write(tmp_path, "app.py", f'KEY = "{FAKE_KEY}"\n')
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\n"
               "exclude = \"vendor/*\"\n"
               "future_option = true\n"
               "[other_tool]\n"
               "whatever = 42\n")
        report = server.scan_secrets(str(tmp_path))
        assert "Findings: 1" in report

    def test_json_carries_config(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        _write(tmp_path, ".guardx.toml",
               '[scan_secrets]\nexclude = "vendor/*"\n'
               "entropy_threshold = 4.5\n")
        report = json.loads(server.scan_secrets(str(tmp_path),
                                                json_output=True))
        assert report["config"]["path"].endswith(".guardx.toml")
        assert report["config"]["exclude"] == ["vendor/*"]
        assert report["config"]["entropy_threshold"] == 4.5
        assert report["config"]["baseline"] is None

    def test_no_config_means_no_config_key(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        report = json.loads(server.scan_secrets(str(tmp_path),
                                                json_output=True))
        assert "config" not in report

    def test_single_file_scan_discovers_config_next_to_it(self, tmp_path):
        fp = _write(tmp_path, "app.py", f'misc = "{HIGH_ENTROPY}"\n')
        _write(tmp_path, ".guardx.toml",
               "[scan_secrets]\nentropy_threshold = 4.5\n")
        report = server.scan_secrets(fp)
        assert "High-Entropy String" not in report
        assert "Config: .guardx.toml" in report
