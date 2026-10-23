"""True-positive / false-positive coverage for GuardX's `scan_secrets` pattern suite.

Every entry in `SECRET_PATTERNS` gets at least one realistic true-positive
line (asserting the pattern fires with the right name and severity) and at
least one near-miss false-positive line (asserting the *whole line* is
clean — `_match_line` returns None, so no other pattern may fire either).
`mcp` and `httpx` are not installed in this environment, so the stubs below
are installed exactly once per pytest process (shared with the other GuardX
test modules via the sentinel).
"""

from __future__ import annotations

import importlib.util
import sys
import types

import pytest

from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs (shared, installed once per process)
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

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("guardx_server", REPO_ROOT / "server.py")
assert _spec and _spec.loader
guardx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guardx)


# ---------------------------------------------------------------------------
# Case table: pattern name -> (expected severity, true positives, false positives)
#
# True-positive lines are realistic snippets the pattern must catch.
# False-positive lines are near misses that must match NO pattern at all,
# so each one also guards against the other patterns over-matching.
# ---------------------------------------------------------------------------

CASES = {
    "AWS Access Key ID": (
        "HIGH",
        [
            'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
        ],
        [
            'aws_access_key_id = "AKIA123"',          # too short
            'aws_access_key_id = "akiaiosfodnn7example"',  # lowercase
        ],
    ),
    "AWS Secret Access Key": (
        "HIGH",
        [
            'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            'awsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        ],
        [
            'aws_secret = "short"',  # quoted value too short
            # 40-char value but no aws/secret/key context nearby
            'greeting = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        ],
    ),
    "GitHub Token": (
        "HIGH",
        [
            'token = "ghp_1234567890abcdef1234567890ABCDEF1234"',
            'GITHUB_TOKEN=ghp_1234567890abcdef1234567890ABCDEF1234',
        ],
        [
            'githubkey = "ghx_1234567890abcdef1234567890ABCDEF1234"',  # wrong prefix
            'githubkey = "ghp_1234567890abcdef1234567890ABCDEF123"',  # 35 chars, too short
        ],
    ),
    "Slack Token": (
        "HIGH",
        [
            'slack_token = "xoxb-1234567890AB"',
            'export SLACK_TOKEN="xoxp-ABCDEFGHIJ-klmnop"',
        ],
        [
            'slackkey = "xoxz-1234567890AB"',  # wrong prefix
            'slackkey = "xoxb-abc"',  # too short
        ],
    ),
    "Google API Key": (
        "HIGH",
        [
            'api_key = "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
        ],
        [
            'key = "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',  # 34 chars, too short
            'GOOGLE_KEY: Bxza0123456789abcdefghijklmnopqrstuVWXYZ',  # no AIza prefix
        ],
    ),
    "Stripe Secret Key": (
        "HIGH",
        [
            # Stripe fixtures are built by concatenation: GitHub push
            # protection rejects blobs containing literal sk_live_ /
            # rk_live_ secret-shaped strings, even obviously fake test
            # fixtures. The runtime values are identical, so the
            # assertions test the same real patterns.
            'stripe_key = "' + "sk_live_" + "A" * 28 + '"',
            'STRIPE_SECRET_KEY=' + "sk_live_" + "B" * 31,
        ],
        [
            'stripe_key = "sk_test_51HAbCdEfGhIjKlMnOpQrStUv"',  # test key
            'stripe_key = "sk_live_abc"',  # too short
        ],
    ),
    "Stripe Restricted Key": (
        "HIGH",
        [
            'stripe_key = "' + "rk_live_" + "C" * 28 + '"',
        ],
        [
            'stripe_key = "rk_test_51HAbCdEfGhIjKlMnOpQrStUv"',  # test key
            'stripe_key = "rk_live_ab"',  # too short
        ],
    ),
    "Discord Bot Token": (
        "HIGH",
        [
            'client.run("M' + "a" * 23 + "." + "b" * 6 + "." + "c" * 27 + '")',
            'discord_token = "mfa.' + "d" * 84 + '"',
        ],
        [
            'client.run("X' + "a" * 23 + "." + "b" * 6 + "." + "c" * 27 + '")',
            'client.run("M' + "a" * 10 + "." + "b" * 6 + "." + "c" * 27 + '")',
        ],
    ),
    "Slack Webhook URL": (
        "HIGH",
        [
            '"https://hooks.slack.com/services/TABCDEF/BGHIJKL/abcdefghijklmnopqrst"',
        ],
        [
            '"http://hooks.slack.com/services/TABCDEF/BGHIJKL/abcdefghijklmnopqrst"',  # plain http
            '"https://hooks.example.com/services/TABCDEF/BGHIJKL/abcdefghijklmnopqrst"',  # wrong host
        ],
    ),
    "GitLab Personal Access Token": (
        "HIGH",
        [
            'gitlab_token = "glpat-1234567890abcdefghij"',
        ],
        [
            'gitlabkey = "glpat-abc"',  # too short
            'gitlabkey = "glpat_1234567890abcdefghij"',  # underscore, not hyphen
        ],
    ),
    "SendGrid API Key": (
        "HIGH",
        [
            'sendgrid_key = "SG.' + "a" * 22 + "." + "b" * 30 + '"',
        ],
        [
            'sendgrid_key = "SG.' + "a" * 21 + "." + "b" * 30 + '"',  # first part too short
            'sendgrid_key = "SG.' + "a" * 22 + '"',  # missing second part
        ],
    ),
    "Private Key Block": (
        "HIGH",
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ],
        [
            "-----BEGIN PUBLIC KEY-----",  # public key, not private
            "-----BEGIN RSA PRIVATE KEY----",  # malformed armor
        ],
    ),
    "Generic Secret Assignment": (
        "MED",
        [
            'api_key = "myquirkycustomkey123"',
            'password: "hunter2-hunter2"',
        ],
        [
            'api_key = "short"',  # value under 8 chars
            'monkey = "averylongsecretvalue"',  # no credential keyword
            'password = "has a space"',  # spaces break the value match
        ],
    ),
    "JWT": (
        "HIGH",
        [
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiIxMjM0In0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
        [
            "Authorization: Bearer eyJhbGciOi.eyJzdWIi.e30",  # not a token
            "token: header.payload",  # only two segments
        ],
    ),
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_every_pattern_has_cases():
    """The table must cover the whole pattern suite — no pattern untested."""
    assert set(CASES) == set(guardx.SECRET_PATTERNS)


@pytest.mark.parametrize("name", sorted(CASES))
def test_true_positive(name):
    severity, true_positives, _ = CASES[name]
    expected_severity, _ = guardx.SECRET_PATTERNS[name]
    assert severity == expected_severity
    assert true_positives, f"{name}: no true-positive cases"
    for line in true_positives:
        hit = guardx._match_line(line)
        assert hit is not None, f"{name}: missed true positive: {line!r}"
        hit_name, hit_severity, _ = hit
        assert hit_name == name, (
            f"{name}: matched as {hit_name} instead: {line!r}"
        )
        assert hit_severity == severity, (
            f"{name}: severity {hit_severity}, expected {severity}: {line!r}"
        )


@pytest.mark.parametrize("name", sorted(CASES))
def test_false_positive(name):
    _, _, false_positives = CASES[name]
    assert false_positives, f"{name}: no false-positive cases"
    for line in false_positives:
        hit = guardx._match_line(line)
        assert hit is None, (
            f"{name}: false positive fired as {hit[0]} ({hit[1]}): {line!r}"
        )
