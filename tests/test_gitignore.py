"""Unit tests for `scan_secrets` honouring `.gitignore`.

Same `mcp`/`httpx` stub strategy as the other suites: no third-party
installs, scans run against `tmp_path` fixtures — no real target touched.
Secrets below are deliberately fake (formats the patterns recognise, but
not real credentials).
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
    "guardx_server_gitignore", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)

SECRET_LINE = 'api_key = "some-app-secret-thing"\n'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk(tmp_path: Path, rel: str, content: str = SECRET_LINE) -> None:
    fp = tmp_path / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)


def _root(tmp_path: Path, gitignore: str) -> str:
    """Lay out a fixture: .gitignore + one ignored + one kept secret file."""
    _mk(tmp_path, ".gitignore", gitignore)
    return str(tmp_path)


# ---------------------------------------------------------------------------
# .gitignore parsing
# ---------------------------------------------------------------------------

class TestGitignorePatterns:
    def test_blank_lines_and_comments_are_not_patterns(self, tmp_path):
        _mk(tmp_path, ".gitignore", "# *.log\n\n   \n# trailing comment\n")
        # A commented-out pattern must not take effect: the fixture dir has
        # no .log files, so only the .gitignore itself is scanned.
        assert server._load_gitignore(str(tmp_path)) == []
        assert server._gitignore_ignored([], "a.log", False) is False

    def test_missing_gitignore_means_nothing_ignored(self, tmp_path):
        assert server._load_gitignore(str(tmp_path)) == []
        assert server._gitignore_ignored([], "anything.py", False) is False

    def test_basename_pattern_matches_at_any_depth(self, tmp_path):
        root = _root(tmp_path, "*.log\n")
        _mk(tmp_path, "debug.log")
        _mk(tmp_path, "deep/nested/debug.log")
        report = server.scan_secrets(root)
        assert "debug.log" not in report
        assert "Files scanned: 1" in report  # only .gitignore itself was read

    def test_dir_only_pattern_prunes_the_whole_tree(self, tmp_path):
        root = _root(tmp_path, "build/\n")
        _mk(tmp_path, "build/output.py")
        _mk(tmp_path, "build/sub/bundle.py")
        report = server.scan_secrets(root)
        assert "Findings: 0" in report
        assert "No hardcoded secrets detected. [OK]" in report

    def test_basename_dir_pattern_matches_nested_dirs(self, tmp_path):
        root = _root(tmp_path, "dist/\n")
        _mk(tmp_path, "sub/dist/secret.py")
        _mk(tmp_path, "src/app.py")  # kept: still reported
        report = server.scan_secrets(root)
        assert "sub/dist/secret.py" not in report
        assert "src/app.py" in report
        assert "Findings: 1" in report

    def test_anchored_pattern_only_matches_at_root(self, tmp_path):
        root = _root(tmp_path, "/secrets/\n")
        _mk(tmp_path, "secrets/s1.py")        # ignored (root-level dir)
        _mk(tmp_path, "nested/secrets/s2.py")  # kept (not root-level)
        report = server.scan_secrets(root)
        assert "nested/secrets/s2.py" in report
        assert "secrets/s1.py" not in report
        assert "Findings: 1" in report

    def test_bare_trailing_slash_pattern_matches_at_any_depth(self, tmp_path):
        # Unlike /secrets/, a bare `secrets/` follows git semantics and
        # matches a dir named `secrets` at any depth.
        root = _root(tmp_path, "secrets/\n")
        _mk(tmp_path, "secrets/s1.py")
        _mk(tmp_path, "nested/secrets/s2.py")
        report = server.scan_secrets(root)
        assert "secrets/s1.py" not in report
        assert "nested/secrets/s2.py" not in report
        assert "Findings: 0" in report

    def test_negation_re_includes_a_file(self, tmp_path):
        root = _root(tmp_path, "*.log\n!keep.log\n")
        _mk(tmp_path, "skip.log")
        _mk(tmp_path, "keep.log")
        report = server.scan_secrets(root)
        assert "skip.log" not in report
        assert "keep.log" in report
        assert "Findings: 1" in report

    def test_last_matching_pattern_wins(self, tmp_path):
        # `!keep.log` first, then `*.log` re-ignores it again.
        root = _root(tmp_path, "!keep.log\n*.log\n")
        _mk(tmp_path, "keep.log")
        report = server.scan_secrets(root)
        assert "keep.log" not in report
        assert "Findings: 0" in report

    def test_double_star_spans_segments(self, tmp_path):
        root = _root(tmp_path, "**/cache/\n")
        _mk(tmp_path, "a/b/cache/x.py")
        _mk(tmp_path, "a/y.py")  # kept
        report = server.scan_secrets(root)
        assert "a/b/cache/x.py" not in report
        assert "a/y.py" in report
        assert "Findings: 1" in report

    def test_hardcoded_ignore_dirs_still_apply(self, tmp_path):
        # node_modules is pruned even with an empty .gitignore.
        root = _root(tmp_path, "")
        _mk(tmp_path, "node_modules/dep/index.py")
        _mk(tmp_path, "src/app.py")
        report = server.scan_secrets(root)
        assert "node_modules/dep/index.py" not in report
        assert "src/app.py" in report

    def test_single_file_scan_honours_gitignore(self, tmp_path):
        _mk(tmp_path, ".gitignore", "secret.py\n")
        _mk(tmp_path, "secret.py")
        fp = tmp_path / "secret.py"
        report = server.scan_secrets(str(fp))
        assert "Files scanned: 0" in report
        assert "Findings: 0" in report

    def test_gitignore_pattern_itself_is_not_a_secret_source(self, tmp_path):
        # The .gitignore file is scanned like any other file, but its
        # contents are inert text — no findings, and the patterns still work.
        root = _root(tmp_path, "*.pem\n")
        _mk(tmp_path, "cert.pem")
        report = server.scan_secrets(root)
        assert "Findings: 0" in report


# ---------------------------------------------------------------------------
# --exclude flag
# ---------------------------------------------------------------------------

class TestExcludeFlag:
    def test_bare_pattern_matches_any_segment(self, tmp_path):
        root = str(tmp_path)
        _mk(tmp_path, "bundle.min.js")
        _mk(tmp_path, "nested/bundle.min.js")
        _mk(tmp_path, "app.py")
        report = server.scan_secrets(root, exclude="*.min.js")
        assert "bundle.min.js" not in report
        assert "app.py" in report
        assert "Findings: 1" in report

    def test_slash_pattern_is_path_anchored(self, tmp_path):
        root = str(tmp_path)
        _mk(tmp_path, "fixtures/bad.py")
        _mk(tmp_path, "src/fixtures/bad.py")
        report = server.scan_secrets(root, exclude="fixtures/*")
        assert "src/fixtures/bad.py" in report
        assert report.count("bad.py") == 1  # only the nested one reported
        assert "Findings: 1" in report

    def test_comma_separated_list_all_apply(self, tmp_path):
        root = str(tmp_path)
        _mk(tmp_path, "a.log")
        _mk(tmp_path, "tmp/x.py")
        _mk(tmp_path, "app.py")
        report = server.scan_secrets(root, exclude="*.log, tmp")
        assert "a.log" not in report
        assert "tmp/x.py" not in report
        assert "Findings: 1" in report

    def test_excluded_dir_is_pruned_not_just_filtered(self, tmp_path):
        root = str(tmp_path)
        _mk(tmp_path, "vendored/dep/secret.py")
        report = server.scan_secrets(root, exclude="vendored")
        assert "vendored" not in report
        assert "Files scanned: 0" in report
        assert "Findings: 0" in report

    def test_empty_exclude_changes_nothing(self, tmp_path):
        root = str(tmp_path)
        _mk(tmp_path, "app.py")
        report = server.scan_secrets(root, exclude="")
        assert "app.py" in report
        assert "Findings: 1" in report

    def test_single_file_scan_honours_exclude(self, tmp_path):
        fp = tmp_path / "secret.py"
        _mk(tmp_path, "secret.py")
        report = server.scan_secrets(str(fp), exclude="secret.py")
        assert "Files scanned: 0" in report
        assert "Findings: 0" in report

    def test_exclude_stacks_with_gitignore(self, tmp_path):
        # .gitignore drops the .log; --exclude drops fixtures/ — both held.
        root = _root(tmp_path, "*.log\n")
        _mk(tmp_path, "debug.log")
        _mk(tmp_path, "fixtures/bad.py")
        _mk(tmp_path, "app.py")
        report = server.scan_secrets(root, exclude="fixtures/*")
        assert "debug.log" not in report
        assert "fixtures/bad.py" not in report
        assert "app.py" in report
        assert "Findings: 1" in report
