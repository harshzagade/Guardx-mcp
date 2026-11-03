"""Unit tests for GuardX's `audit_this_codebase_prompt` template.

The template is registered as an MCP prompt only when the installed
SDK supports `mcp.prompt()`; the test stub's `FastMCP` deliberately
has no `prompt()` method, so these tests also prove the fallback: the
plain function stays importable and returns the same text without a
running server.
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
                return fn
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


def test_prompt_chains_both_tools_in_order():
    out = guardx.audit_this_codebase_prompt("./my-project", "requirements.txt")
    assert "scan_secrets" in out
    assert "audit_dependencies" in out
    assert out.index("scan_secrets") < out.index("audit_dependencies")
    assert "./my-project" in out
    assert "requirements.txt" in out


def test_prompt_defaults_to_cwd_and_generic_manifest():
    out = guardx.audit_this_codebase_prompt()
    assert "Audit this codebase for security issues: ." in out
    assert "requirements.txt" in out  # named as one possible manifest


def test_prompt_orders_secrets_before_dependencies():
    out = guardx.audit_this_codebase_prompt()
    assert "Secrets to rotate" in out
    assert "Dependencies to upgrade" in out
    assert out.index("Secrets to rotate") < out.index("Dependencies to upgrade")
    assert "HIGH findings first" in out


def test_prompt_forbids_pasting_real_secrets_and_edits():
    out = guardx.audit_this_codebase_prompt()
    assert "only masked previews" in out
    assert "never paste a real secret" in out
    assert "read-only" in out


def test_prompt_reports_tool_failures_instead_of_claiming_clean():
    out = guardx.audit_this_codebase_prompt()
    assert "say so plainly instead of claiming that area is clean" in out
