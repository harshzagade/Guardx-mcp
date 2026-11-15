"""Unit tests for the skipped-large-files count in `scan_secrets`.

Files over `MAX_FILE_BYTES` (1 MB) are skipped unread; the report header
now says how many were skipped, and JSON output carries the count as
`skipped_large_files`, so a huge vendored file is never mistaken for
scanned. `mcp` and `httpx` are stubbed exactly like the other suites —
no packages are installed to run these tests.
"""

from __future__ import annotations

import importlib.util
import json
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
    "guardx_server_skipped_large",
    str(Path(__file__).resolve().parent.parent / "server.py"),
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _token() -> str:
    # Built by concatenation so no literal secret-shaped string lands
    # in this file (GitHub push protection rejects those even in tests).
    return "ghp_" + "A" * 36


def _big_content(extra_bytes: int) -> bytes:
    """A file with a real secret on line 1, padded past the size limit."""
    line = f'TOKEN = "{_token()}"\n'.encode()
    pad = b"#" + b"x" * max(0, server.MAX_FILE_BYTES + extra_bytes - len(line) - 1)
    return line + pad + b"\n"


class TestSkippedLargeFiles:
    def test_oversized_file_skipped_and_counted(self, tmp_path):
        (tmp_path / "small.py").write_text("print('clean')\n")
        (tmp_path / "big.py").write_bytes(_big_content(100))
        report = server.scan_secrets(str(tmp_path))
        assert "Files scanned: 1" in report
        assert "Skipped (over 1 MB): 1" in report
        # The secret inside the skipped file is never reported.
        assert "No hardcoded secrets detected." in report
        assert _token() not in report

    def test_multiple_oversized_files_counted(self, tmp_path):
        (tmp_path / "a.py").write_bytes(_big_content(10))
        (tmp_path / "b.py").write_bytes(_big_content(20))
        report = server.scan_secrets(str(tmp_path))
        assert "Files scanned: 0" in report
        assert "Skipped (over 1 MB): 2" in report

    def test_no_large_files_carries_no_skipped_line(self, tmp_path):
        (tmp_path / "a.py").write_text("print('clean')\n")
        report = server.scan_secrets(str(tmp_path))
        assert "Skipped" not in report
        parsed = json.loads(server.scan_secrets(str(tmp_path), json_output=True))
        assert parsed["skipped_large_files"] == 0
        assert parsed["files_scanned"] == 1

    def test_json_carries_skipped_count(self, tmp_path):
        (tmp_path / "small.py").write_text("print('clean')\n")
        (tmp_path / "big.py").write_bytes(_big_content(100))
        parsed = json.loads(server.scan_secrets(str(tmp_path), json_output=True))
        assert parsed["skipped_large_files"] == 1
        assert parsed["files_scanned"] == 1
        assert parsed["findings_count"] == 0

    def test_file_exactly_at_limit_is_scanned(self, tmp_path):
        # getsize == MAX_FILE_BYTES is not "over" the limit: the file is
        # read, and the secret on line 1 is found.
        line = f'TOKEN = "{_token()}"\n'.encode()
        fp = tmp_path / "edge.py"
        fp.write_bytes(line + b"x" * (server.MAX_FILE_BYTES - len(line)))
        assert fp.stat().st_size == server.MAX_FILE_BYTES
        report = server.scan_secrets(str(tmp_path))
        assert "Files scanned: 1" in report
        assert "Skipped" not in report
        assert "GitHub Token" in report

    def test_single_oversized_file_scan(self, tmp_path):
        fp = tmp_path / "big.py"
        fp.write_bytes(_big_content(100))
        report = server.scan_secrets(str(fp))
        assert "Files scanned: 0" in report
        assert "Skipped (over 1 MB): 1" in report
        assert "No hardcoded secrets detected." in report
