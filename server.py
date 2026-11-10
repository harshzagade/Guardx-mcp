"""
GuardX - Code Security Auditor MCP Server
=========================================

A keyless, *defensive* (blue-team) security toolkit exposed over the
Model Context Protocol (MCP). It inspects **local codebases** rather than
live websites, so it complements offensive recon tooling instead of
duplicating it.

Tools:
  1. scan_secrets(path)          - find hardcoded secrets/credentials in code
  2. audit_dependencies(path)    - check dependencies against the OSV vuln DB
  3. check_pwned_password(pw)    - check a password against Have I Been Pwned
                                   (k-anonymity: only a hash prefix is sent)
  4. check_pwned_passwords(pws)  - batch version of (3): one summary line
                                   per password, one range request per
                                   distinct hash prefix
Prompt:
  audit_this_codebase_prompt     - "audit this codebase" template chaining
                                   scan_secrets + audit_dependencies into a
                                   remediation summary

No API keys are required and all tools are read-only / privacy-preserving.
Use only on code and credentials you own or are authorized to assess.
"""

from __future__ import annotations

import fnmatch
import math
import os
import re
import json
import asyncio
import hashlib
import random
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import unquote
from collections import Counter
from datetime import datetime
from functools import cmp_to_key

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("guardx")

USER_AGENT = "guardx-mcp/1.0"
HTTP_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# Tool 1: secret scanning
# ---------------------------------------------------------------------------

# name -> (severity, compiled regex). Patterns favour low false-positives.
# Severities: HIGH = a live credential or private-key material — rotate
# immediately. MED = credential-like heuristic with real false-positive
# risk (generic assignments). LOW = weak or context-poor signal.
SECRET_PATTERNS = {
    "AWS Access Key ID": (
        "HIGH",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    "AWS Secret Access Key": (
        "HIGH",
        re.compile(
            r"(?i)aws.{0,20}?(secret|key).{0,5}['\"][0-9a-zA-Z/+]{40}['\"]"
        ),
    ),
    "GitHub Token": (
        "HIGH",
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ),
    "Slack Token": (
        "HIGH",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ),
    "Google API Key": (
        "HIGH",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    "Stripe Secret Key": (
        "HIGH",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ),
    "Stripe Restricted Key": (
        "HIGH",
        re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"),
    ),
    "Discord Bot Token": (
        "HIGH",
        re.compile(
            r"\b(?:mfa\.[\w\-]{84}|[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27})\b"
        ),
    ),
    "Slack Webhook URL": (
        "HIGH",
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"
        ),
    ),
    "GitLab Personal Access Token": (
        "HIGH",
        re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    ),
    "SendGrid API Key": (
        "HIGH",
        re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{30,}\b"),
    ),
    "Credential in URL": (
        "HIGH",
        re.compile(
            r"(?i)\b(?:https?|ftp|ssh|postgres(?:ql)?|mysql|mongodb(?:\+srv)?"
            r"|redis|amqp)://[^\s/'\":@]+:[^\s/'\"@]+@[^\s/'\"@]+"
        ),
    ),
    "Private Key Block": (
        "HIGH",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    "Generic Secret Assignment": (
        "MED",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*"
            r"['\"][^'\"\s]{8,}['\"]"
        ),
    ),
    "JWT": (
        "HIGH",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
}

IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".idea", ".vscode", "vendor", ".mypy_cache",
}
# Extensions we skip (binaries / non-source).
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".mp4",
    ".mp3", ".class", ".jar", ".pyc", ".lock",
}
MAX_FILE_BYTES = 1_000_000  # skip files larger than ~1 MB

# Long (e.g. minified) lines are scanned in overlapping windows instead of
# being skipped outright. The 500-char overlap guarantees a secret sitting
# on a window boundary is still caught.
LONG_LINE_WINDOW = 2000
LONG_LINE_STEP = 1500


def _load_gitignore(scan_root: str) -> list[str]:
    """Return the raw (comment/blank-stripped) patterns from a `.gitignore`
    sitting at the scan root, or [] when there is no readable one."""
    patterns = []
    gi = os.path.join(scan_root, ".gitignore")
    try:
        with open(gi, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    patterns.append(stripped)
    except OSError:
        pass
    return patterns


def _seg_match(pat_segs: list[str], path_segs: list[str]) -> bool:
    """Match pattern segments against path segments; a `**` pattern segment
    consumes zero or more path segments. Within a segment, `*`, `?` and
    `[...]` follow fnmatch semantics (`*` never crosses a `/`, since each
    segment is matched individually)."""
    def rec(pi: int, si: int) -> bool:
        if pi == len(pat_segs):
            return si == len(path_segs)
        if pat_segs[pi] == "**":
            return any(rec(pi + 1, k) for k in range(si, len(path_segs) + 1))
        if si == len(path_segs):
            return False
        return fnmatch.fnmatchcase(path_segs[si], pat_segs[pi]) and rec(pi + 1, si + 1)
    return rec(0, 0)


def _gitignore_ignored(patterns: list[str], rel_path: str, is_dir: bool) -> bool:
    """True when `rel_path` (posix-style, relative to the scan root) is
    ignored by `patterns` following the practical subset of gitignore rules:
    basename patterns match at any depth (dir matches cascade to their
    contents), patterns containing `/` (beyond a trailing one) or a leading
    `/` are anchored to the scan root, a trailing `/` restricts to
    directories, `!` negates, and the last matching pattern wins. Directory
    pruning happens in `os.walk`, so a matched dir's children are never
    visited."""
    rel = rel_path.replace(os.sep, "/")
    rel_segs = rel.split("/")
    ignored = False
    for raw in patterns:
        neg = raw.startswith("!")
        pat = raw[1:] if neg else raw
        dir_only = pat.endswith("/")
        body = pat.rstrip("/")
        anchored = body.startswith("/")
        body = body.lstrip("/")
        if not body:
            continue
        anchored = anchored or "/" in body
        if anchored:
            match = _seg_match(body.split("/"), rel_segs)
        else:
            match = any(fnmatch.fnmatchcase(seg, body) for seg in rel_segs)
        if match and not (dir_only and not is_dir):
            # A dir-only pattern ignores only directories; when a matched
            # dir is pruned in os.walk its contents vanish with it.
            ignored = not neg
    return ignored


def _parse_exclude(exclude: str | None) -> list[str]:
    """Split a comma-separated `--exclude` string into clean patterns."""
    if not exclude:
        return []
    return [p.strip() for p in exclude.split(",") if p.strip()]


def _excluded(patterns: list[str], rel_path: str) -> bool:
    """True when `rel_path` (posix-style, relative to the scan root) matches
    any user-supplied exclude pattern. Patterns with `/` are matched against
    the full relative path (segment-wise, `*` never crosses `/`, `**` may);
    bare patterns match any path segment. Directory matches cascade because
    matched dirs are pruned from `os.walk`."""
    rel = rel_path.replace(os.sep, "/")
    rel_segs = rel.split("/")
    for pat in patterns:
        if "/" in pat:
            if _seg_match(pat.split("/"), rel_segs):
                return True
        elif any(fnmatch.fnmatchcase(seg, pat) for seg in rel_segs):
            return True
    return False


def _line_windows(line: str):
    """Yield the scan window(s) for a line: the whole line, or overlapping
    chunks when it exceeds LONG_LINE_WINDOW."""
    if len(line) <= LONG_LINE_WINDOW:
        yield line
        return
    for start in range(0, len(line), LONG_LINE_STEP):
        yield line[start:start + LONG_LINE_WINDOW]
        if start + LONG_LINE_WINDOW >= len(line):
            break


def _match_line(line: str):
    """Return (name, severity, secret) for the first secret-pattern hit in
    `line`, or None when the line is clean. Long lines are scanned in
    overlapping windows; at most one finding per line is returned."""
    for window in _line_windows(line):
        for name, (severity, pattern) in SECRET_PATTERNS.items():
            m = pattern.search(window)
            if m:
                return name, severity, m.group(0)
    return None


# Entropy fallback: catches custom token formats no known pattern covers.
# A 20-char string can carry at most log2(20) ~= 4.32 bits/char, so the
# 4.0 threshold with a 20-char floor only fires on genuinely mixed
# alphabets; plain English (3.6-3.8) and pure hex hashes (3.4-3.7) stay
# below it. Quoted strings only, and the charset excludes `:` and `/`
# so URLs are not split into flaggable fragments.
ENTROPY_MIN_LENGTH = 20
ENTROPY_THRESHOLD = 4.0
_QUOTED_TOKEN_RE = re.compile(r"""["']([A-Za-z0-9_+\-=.]{20,})["']""")


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of `text` in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_hit(line: str):
    """Return ("High-Entropy String", "LOW", candidate) for the first
    quoted string in `line` that is long and high-entropy, or None.

    Deliberately separate from `_match_line`: the pattern suite's
    false-positive cases assert `_match_line` returns None, and entropy
    is a LOW heuristic, not a pattern — `scan_secrets` only consults
    this after the patterns miss, so a known pattern always wins and
    the one-finding-per-line rule is preserved."""
    for m in _QUOTED_TOKEN_RE.finditer(line):
        candidate = m.group(1)
        if len(candidate) >= ENTROPY_MIN_LENGTH and (
            _shannon_entropy(candidate) >= ENTROPY_THRESHOLD
        ):
            return "High-Entropy String", "LOW", candidate
    return None


# Config-file credential heuristic: in config files, a credential-named
# key with a real-looking value is worth a MED finding even when no
# known pattern matches — most often because the value is unquoted
# (`.env`, YAML, INI) or the assignment uses `:` (YAML/JSON), both of
# which the generic assignment pattern misses. Only the key's last
# `-`/`_`/`/`-split token needs to be credential-like, so
# `password_length` or `secret_santa` stay clean, and placeholder
# values (changeme, ${VAR} references, masked ***) are skipped.
_CONFIG_EXTS = {".ini", ".cfg", ".conf", ".yaml", ".yml", ".json",
                ".toml", ".properties"}
_CONFIG_CRED_TOKENS = {"password", "passwd", "pwd", "secret", "token",
                        "apikey", "api_key", "accesskey", "privatekey",
                        "auth", "credential"}
_CONFIG_PLACEHOLDERS = {"changeme", "change-me", "example", "placeholder",
                         "your-password", "your-secret", "your_api_key",
                         "password", "secret", "token", "xxx", "none",
                         "null", "true", "false"}
_CONFIG_ASSIGN_RE = re.compile(
    r"""^\s*(?:export\s+)?["']?([A-Za-z0-9_.\-]+)["']?\s*[:=]\s*"""
    r"""["']?([^"'\s,;]+)["']?,?\s*$"""
)


def _is_config_file(filename: str) -> bool:
    base = os.path.basename(filename)
    if base == ".env" or base.startswith(".env."):
        return True
    return os.path.splitext(base)[1].lower() in _CONFIG_EXTS


def _config_credential_hit(line: str, filename: str):
    """Return ("Config Credential", "MED", value) for a credential-named
    key with a non-placeholder value in a config file, or None.

    Deliberately separate from `_match_line`: it only runs on config
    files and only after the patterns miss, so code files are
    unaffected and a known pattern always wins.
    """
    if not _is_config_file(filename):
        return None
    stripped = line.strip()
    if not stripped or stripped[0] in "#;/" or stripped.startswith("//"):
        return None
    m = _CONFIG_ASSIGN_RE.match(stripped)
    if not m:
        return None
    key, value = m.group(1).lower(), m.group(2)
    tokens = re.split(r"[_.\-]", key)
    if tokens[-1] not in _CONFIG_CRED_TOKENS:
        return None
    lowered = value.lower()
    if (len(value) < 4 or lowered in _CONFIG_PLACEHOLDERS
            or lowered.startswith("${") or lowered.startswith("<")
            or set(value) <= set("*x")):
        return None
    return "Config Credential", "MED", value


# IaC credential heuristic: in infrastructure-as-code files, a hardcoded
# credential inside a resource block that actually provisions a credential
# store (a database, a cache with auth, a SQL server) is a HIGH finding —
# the value is a live credential for a deployed service, not a generic
# assignment. Block-awareness matters: the same `password = ...` line in
# an unrelated resource (or outside any sensitive block) is left to the
# generic/config heuristics instead of being promoted. Terraform
# (`.tf`) blocks are tracked by brace depth, so the context ends when
# the resource block closes; CloudFormation/ARM templates (`.json`,
# `.yaml`) carry no braces to count, so their context lasts until the
# next `Type:` declaration. `.tfvars` files have no resource blocks at
# all, so every credential-named assignment in one is treated as IaC
# (a tfvars file is, by definition, values for a deployment).
_IAC_EXTS = {".tf", ".tfvars", ".json", ".yaml", ".yml"}
_IAC_TF_RESOURCE_RE = re.compile(
    r"""^\s*resource\s+"([^"]+)"\s+"[^"]+"\s*\{"""
)
_IAC_TYPE_RE = re.compile(
    r"""^\s*"(?i:type)"?\s*[:=]\s*"?"""
    r"""(AWS::[A-Za-z0-9:]+|Microsoft\.[A-Za-z0-9/._\-]+)"?,?\s*$"""
    r"""|^\s*(?i:type)\s*[:=]\s*"?"""
    r"""(AWS::[A-Za-z0-9:]+|Microsoft\.[A-Za-z0-9/._\-]+)"?,?\s*$"""
)
_IAC_TF_SENSITIVE_PREFIXES = (
    "aws_db_", "aws_rds_", "aws_redshift_", "aws_elasticache_",
    "azurerm_sql_", "azurerm_mysql_", "azurerm_postgresql_",
    "azurerm_mariadb_",
)
_IAC_CFN_SENSITIVE_TYPES = {
    "AWS::RDS::DBInstance", "AWS::RDS::DBCluster",
    "AWS::Redshift::Cluster", "AWS::DocDB::DBCluster",
    "AWS::ElastiCache::ReplicationGroup", "AWS::ElastiCache::CacheCluster",
}
_IAC_ARM_SENSITIVE_TYPES = {
    "Microsoft.DBforMySQL/servers", "Microsoft.DBforPostgreSQL/servers",
    "Microsoft.DBforMariaDB/servers", "Microsoft.Sql/servers",
    "Microsoft.DocumentDB/databaseAccounts",
}
_IAC_ASSIGN_RE = re.compile(
    r"""^\s*"?([A-Za-z0-9_.\-]+)"?\s*[:=]\s*"""
    r"""["']?([^"'\s,;]+)["']?,?\s*$"""
)
_IAC_REFERENCE_PREFIXES = ("var.", "local.", "data.", "module.",
                           "random_password.", "aws_", "azurerm_")


def _is_iac_file(filename: str) -> bool:
    return os.path.splitext(os.path.basename(filename))[1].lower() in _IAC_EXTS


def _iac_resource_type(line: str):
    """Resource type declared on `line`, or None.

    Terraform: `resource "aws_db_instance" "main" {`. CloudFormation /
    ARM: a `Type:` / `"Type":` line naming an `AWS::...` or
    `Microsoft....` resource type."""
    m = _IAC_TF_RESOURCE_RE.match(line)
    if m:
        return m.group(1)
    m = _IAC_TYPE_RE.match(line.strip())
    if m:
        return m.group(1) or m.group(2)
    return None


def _iac_resource_sensitive(resource_type: str | None) -> bool:
    """True when `resource_type` provisions a credential store."""
    if resource_type is None:
        return False
    if resource_type == "tfvars":
        return True
    if resource_type.startswith(_IAC_TF_SENSITIVE_PREFIXES):
        return True
    return (resource_type in _IAC_CFN_SENSITIVE_TYPES
            or resource_type in _IAC_ARM_SENSITIVE_TYPES)


def _iac_key_is_credential(key: str) -> bool:
    """True when the key's last name token is credential-like.

    Splits on `_`/`.`/`-` and on camelCase boundaries, so
    `master_password`, `MasterUserPassword`, and
    `administratorLoginPassword` all end in `password` while
    `password_length` and `secret_santa` stay clean."""
    parts = re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+",
                       key.replace("_", " ").replace(".", " ").replace("-", " "))
    if not parts:
        return False
    return parts[-1].lower() in _CONFIG_CRED_TOKENS


def _iac_credential_hit(line: str, filename: str, resource_type: str | None):
    """Return ("IaC Credential", "HIGH", value) for a hardcoded
    credential assignment inside a sensitive IaC resource block, or
    None.

    Runs only on IaC files and only inside a sensitive block, so a
    password in an unrelated resource is not promoted. Placeholder
    values (`changeme`, `${var...}` interpolations, `var.`/`local.`
    references, masked `***`) stay clean, exactly like the config
    heuristic. Known patterns still win on lines that are not
    credential assignments (a bare AWS key in a .tf file is reported
    under its pattern name, not here)."""
    if not _is_iac_file(filename):
        return None
    if not _iac_resource_sensitive(resource_type):
        return None
    stripped = line.strip()
    if not stripped or stripped[0] in "#;/":
        return None
    m = _IAC_ASSIGN_RE.match(stripped)
    if not m:
        return None
    key, value = m.group(1), m.group(2)
    if not _iac_key_is_credential(key):
        return None
    lowered = value.lower()
    if (len(value) < 4 or lowered in _CONFIG_PLACEHOLDERS
            or lowered.startswith("${") or lowered.startswith("<")
            or value.startswith(_IAC_REFERENCE_PREFIXES)
            or set(value) <= set("*x")):
        return None
    return "IaC Credential", "HIGH", value


def _mask(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return secret[:2] + "****"
    return f"{secret[:4]}...{secret[-2:]} (len {len(secret)})"


BASELINE_FILENAME = ".guardx-baseline"


def _finding_hash(rel_path: str, finding_type: str, secret: str) -> str:
    """Stable identity for one finding, for baseline suppression.

    The line number is deliberately excluded, so a finding stays
    suppressed when surrounding lines are added or removed. The raw
    secret never goes into the baseline file — only its SHA-256, so a
    committed baseline does not leak the secret it acknowledges.
    """
    payload = f"{rel_path}\0{finding_type}\0{secret}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_baseline(baseline_path: str) -> set:
    """Return the set of finding hashes in a baseline file.

    One SHA-256 hex digest per line; blank lines, `#` comments, and
    malformed lines are ignored so a hand-edited baseline cannot break
    a scan.
    """
    try:
        with open(baseline_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return set()
    hashes = set()
    for raw in lines:
        token = raw.strip().lower()
        if not token or token.startswith("#"):
            continue
        if re.fullmatch(r"[0-9a-f]{64}", token):
            hashes.add(token)
    return hashes


def _per_file_counts(findings) -> dict:
    """Return {file: finding count} for a findings list, sorted by count
    descending (most-affected file first) with filename as tie-break, so
    triage starts where the findings cluster."""
    counts = Counter(f["file"] for f in findings)
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _report_json(path, scanned, findings, unique, sev_counts, suppressed=0,
                 since=None, history=None):
    """Build the machine-readable `scan_secrets` report dict.

    Finding previews are masked with the same `_mask()` used by the text
    report, so the JSON is safe to store in CI logs. History-scan
    findings carry their commit short-SHA, and a history run adds a
    `history` object with the commit count and truncation flag.
    """
    report = {
        "tool": "scan_secrets",
        "path": path,
        "files_scanned": scanned,
        "findings_count": len(findings),
        "unique_secrets": unique,
        "severity_counts": dict(sev_counts),
        "per_file_counts": _per_file_counts(findings),
        "suppressed_count": suppressed,
        "findings": [
            {
                "file": f["file"],
                "line": f["line"],
                "type": f["type"],
                "severity": f["severity"],
                "match": _mask(f["secret"]),
                **({"commit": f["commit"]} if "commit" in f else {}),
            }
            for f in findings
        ],
    }
    if since is not None:
        report["since"] = since
    if history is not None:
        report["history"] = history
    return report


def _parse_since_timestamp(value: str) -> float | None:
    """Parse a `since` value as a timestamp, or return None.

    Accepts ISO dates/datetimes (``2026-10-01``, ``2026-10-01T09:30:00``,
    trailing ``Z`` included) and plain epoch seconds. A naive datetime is
    read in local time, matching how file mtimes are reported.
    """
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return None
    return parsed.timestamp()


def _git_repo_root(start: str) -> str | None:
    """Return the git repository root containing `start`, or None."""
    try:
        proc = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _git_changed_files(repo_root: str, since: str) -> set[str] | None:
    """Return repo-relative paths changed since a git ref, or None.

    ``git diff --name-only <ref>`` compares the ref against the worktree,
    so staged and unstaged edits both count; untracked files (new files
    are exactly what an incremental scan must not miss) are added via
    ``git ls-files --others``. Returns None when the ref does not
    resolve, so the caller can fall back to timestamp parsing.
    """
    try:
        diff = subprocess.run(
            ["git", "-C", repo_root, "diff", "--name-only", since],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if diff.returncode != 0:
        return None
    changed = {line.strip() for line in diff.stdout.splitlines() if line.strip()}
    try:
        others = subprocess.run(
            ["git", "-C", repo_root, "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, timeout=30,
        )
        if others.returncode == 0:
            changed.update(line.strip() for line in others.stdout.splitlines() if line.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return changed


def _resolve_since(scan_root: str, since: str):
    """Resolve a `since` value to ("git", changed_paths) or ("mtime", ts).

    A value that resolves as a git ref in the scan path's repository wins;
    otherwise a parseable date/timestamp selects files by mtime. Returns
    (None, None, error_message) when the value is neither.
    """
    repo_root = _git_repo_root(scan_root)
    if repo_root is not None:
        changed = _git_changed_files(repo_root, since)
        if changed is not None:
            return "git", (repo_root, changed), None
    ts = _parse_since_timestamp(since)
    if ts is not None:
        return "mtime", ts, None
    return None, None, (
        f"since must be a git ref resolvable in this repository or a "
        f"date/timestamp, got: {since}"
    )


MAX_HISTORY_COMMITS = 500  # history scans stop here; the header says so


def _scan_history(repo_root: str, pathspec: str, max_commits: int, on_diff_line):
    """Stream `git log -p` for `pathspec` and call
    `on_diff_line(commit, file, new_lineno, content, is_added)` for
    every added (`+`) and context (` `) line, newest commit first.

    Commit boundaries come from `--format=COMMIT %H`, file boundaries
    from `diff --git` headers, and new-file line numbers from hunk
    headers, so a huge history never lands in memory whole. Returns
    (commits_scanned, files_seen, truncated, error): `files_seen` is
    the set of repo-relative files with diffs, `truncated` is True
    when the log was cut at `max_commits`, and `error` names the
    failure when git is unavailable or the log command fails. Stops
    early when the callback returns False (e.g. the caller hit
    `max_findings`). C-quoted paths (spaces, non-ASCII names) are
    unquoted only at the outer level, so an exotic filename may
    misparse — the finding still names the file git printed.
    """
    try:
        proc = subprocess.Popen(
            ["git", "-C", repo_root, "log", "-p",
             "--format=COMMIT %H", "--no-ext-diff", "--", pathspec],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace",
        )
    except OSError as exc:
        return 0, set(), False, f"git log failed: {exc}"
    commits = 0
    truncated = False
    files_seen: set[str] = set()
    commit = None
    cur_file = None
    new_lineno = 0
    in_hunk = False
    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line.startswith("COMMIT "):
                if commits >= max_commits:
                    truncated = True
                    break
                parts = line.split(None, 1)
                commit = parts[1].strip()[:7] if len(parts) > 1 else "?"
                commits += 1
                cur_file = None
                in_hunk = False
                continue
            if commit is None:
                continue
            if line.startswith("diff --git "):
                m = re.match(r"^diff --git a/(.*) b/(.*)$", line)
                if m is not None:
                    cur_file = m.group(2)
                    if cur_file.startswith('"') and cur_file.endswith('"'):
                        cur_file = cur_file[1:-1]
                    files_seen.add(cur_file)
                else:
                    cur_file = None
                in_hunk = False
                continue
            if cur_file is None:
                continue
            if line.startswith("@@ "):
                m = re.search(r"\+(\d+)(?:,\d+)? @@", line)
                new_lineno = int(m.group(1)) if m else 1
                in_hunk = True
                continue
            if not in_hunk:
                continue
            if line.startswith("Binary files "):
                in_hunk = False
                continue
            if line.startswith("+++ ") or line.startswith("--- "):
                continue
            if line.startswith("+"):
                if on_diff_line(commit, cur_file, new_lineno, line[1:], True) is False:
                    break
                new_lineno += 1
            elif line.startswith(" "):
                on_diff_line(commit, cur_file, new_lineno, line[1:], False)
                new_lineno += 1
            # "-" lines (removals) never advance the new-file line number.
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
    if proc.returncode not in (0, None) and commits == 0:
        err = ""
        try:
            err = (proc.stderr.read() or "").strip()
        except OSError:
            pass
        return 0, set(), False, f"git log failed: {err or proc.returncode}"
    return commits, files_seen, truncated, None


@mcp.tool()
def scan_secrets(
    path: str,
    max_findings: int = 200,
    exclude: str | None = None,
    json_output: bool = False,
    baseline: str | None = None,
    since: str | None = None,
    history: bool = False,
) -> str:
    """Scan a file or directory for hardcoded secrets and credentials.

    Args:
        path: File or directory to scan.
        max_findings: Stop after this many findings (default 200).
        exclude: Optional comma-separated glob patterns for noisy paths
            (e.g. `"*.min.js,fixtures/*"`); matching files and directories
            are skipped on top of `.gitignore` and the built-in ignore dirs.
        json_output: Return the report as machine-readable JSON instead of
            human-readable text (for CI pipelines). The JSON object carries
            the path, files scanned, finding count, unique-secrets count,
            per-severity counts, per-file finding counts, and a findings array of
            {file, line, type, severity, match} — previews are masked
            exactly like the text report. Errors are returned as
            {"error": ...} objects instead of plain "Error: ..." strings.
        baseline: Optional path to a baseline file. When omitted, a
            `.guardx-baseline` file at the scan root (or next to a
            single scanned file) is auto-discovered and applied. Each
            line holds the SHA-256 hash of one acknowledged finding
            (see `_finding_hash`); matching findings are suppressed
            from the report and counted as "Suppressed" (and as
            `suppressed_count` in JSON output) so CI runs stay green
            on reviewed false positives without hiding new findings.
            An explicitly given baseline path that does not exist is
            an error; a missing auto-discovered file simply means no
            suppression.
        since: Optional incremental-scan selector. A git ref (e.g.
            `"HEAD~1"`, `"main"`, a commit SHA) scans only files
            changed since that ref in the scan path's repository —
            staged/unstaged edits plus untracked files — so CI runs on
            large repos stay fast. A date/timestamp (e.g.
            `"2026-10-01"`, an ISO datetime, or epoch seconds) scans
            only files modified after that time. Anything else is an
            error. Unchanged files are not counted as scanned.
        history: Scan the git history instead of the working tree:
            added lines in `git log -p` for the path, so a secret that
            was committed and later removed is still found (it stays
            in history until the history itself is rewritten). Each
            finding names its commit short-SHA; the header reports
            how many commits were scanned (capped at 500, newest
            first — the header says so when the cap cuts the log).
            `.gitignore` is deliberately NOT applied here — a file
            committed and later ignored is exactly what this mode is
            for — but `exclude` patterns still skip files, and the
            baseline still suppresses acknowledged findings. Rejects
            `since=` (the two modes select different inputs).

    Returns:
        A report of likely secrets with file, line number, type, and a
        masked preview. Values are masked so the report is safe to share.
        The header carries per-severity counts plus a "Unique secrets"
        count — the number of distinct secret values across the whole
        scan, so a key committed in twelve files shows as one unique
        secret rather than twelve independent findings. When findings
        exist, the header also lists per-file finding counts
        ("Per-file findings"), most-affected file first, so triage can
        start where the findings cluster without counting the detail
        section by hand; the same map appears as `per_file_counts` in
        JSON output. Lines no known pattern matches are also checked
        for long high-entropy quoted strings (at least 20 characters,
        Shannon entropy at least 4.0 bits/char), reported as LOW
        "High-Entropy String" findings — a catch for custom token
        formats; plain English and pure hex hashes stay below the
        threshold. When scanning a directory, a `.gitignore` at the
        scan root is honoured (basename/dir/negation patterns); ignored
        paths are not counted as scanned. In infrastructure-as-code
        files (Terraform `.tf`, `.tfvars`, CloudFormation/ARM
        `.json`/`.yaml`), a credential assignment inside a sensitive
        resource block (e.g. `aws_db_instance`, `AWS::RDS::DBInstance`,
        `Microsoft.Sql/servers`) is reported as a HIGH "IaC Credential"
        finding; the same assignment outside a sensitive block is left
        to the generic/config heuristics, and placeholder values and
        `var.`/`local.` references stay clean.
    """
    if not os.path.exists(path):
        if json_output:
            return json.dumps({"tool": "scan_secrets", "path": path,
                               "error": f"path does not exist: {path}"})
        return f"Error: path does not exist: {path}"

    if history and since is not None:
        error = "history and since cannot be combined: history scans the git log, since selects working-tree files"
        if json_output:
            return json.dumps({"tool": "scan_secrets", "path": path,
                               "error": error})
        return f"Error: {error}"

    exclude_patterns = _parse_exclude(exclude)

    files = []
    if history:
        # No working-tree file collection: the history branch streams
        # `git log -p` instead. scan_root still anchors relative paths.
        scan_root = (
            os.path.dirname(os.path.abspath(path))
            if os.path.isfile(path)
            else os.path.abspath(path)
        )
    elif os.path.isfile(path):
        # A single file still honours a .gitignore at its own directory.
        scan_root = os.path.dirname(os.path.abspath(path))
        patterns = _load_gitignore(scan_root)
        base = os.path.basename(path)
        if not _gitignore_ignored(patterns, base, False) and not _excluded(
            exclude_patterns, base
        ):
            files = [path]
    else:
        scan_root = os.path.abspath(path)
        patterns = _load_gitignore(scan_root)
        for root, dirs, names in os.walk(path):
            dirs[:] = [
                d
                for d in dirs
                if d not in IGNORE_DIRS
                and not _gitignore_ignored(
                    patterns,
                    os.path.relpath(os.path.join(root, d), scan_root),
                    True,
                )
                and not _excluded(
                    exclude_patterns,
                    os.path.relpath(os.path.join(root, d), scan_root),
                )
            ]
            for n in names:
                if os.path.splitext(n)[1].lower() in SKIP_EXTS:
                    continue
                rel = os.path.relpath(os.path.join(root, n), scan_root)
                if rel == BASELINE_FILENAME:
                    continue
                if _gitignore_ignored(patterns, rel, False):
                    continue
                if _excluded(exclude_patterns, rel):
                    continue
                files.append(os.path.join(root, n))

    if since is not None:
        mode, value, since_error = _resolve_since(scan_root, since)
        if since_error is not None:
            if json_output:
                return json.dumps({"tool": "scan_secrets", "path": path,
                                   "error": since_error})
            return f"Error: {since_error}"
        if mode == "git":
            repo_root, changed = value
            files = [
                fp for fp in files
                if os.path.relpath(fp, repo_root) in changed
            ]
        else:
            kept = []
            for fp in files:
                try:
                    if os.path.getmtime(fp) > value:
                        kept.append(fp)
                except OSError:
                    continue
            files = kept

    if baseline is not None:
        if not os.path.isfile(baseline):
            if json_output:
                return json.dumps({"tool": "scan_secrets", "path": path,
                                   "error": f"baseline does not exist: {baseline}"})
            return f"Error: baseline does not exist: {baseline}"
        baseline_hashes = _load_baseline(baseline)
    else:
        auto = os.path.join(scan_root, BASELINE_FILENAME)
        baseline_hashes = _load_baseline(auto) if os.path.isfile(auto) else set()

    findings = []
    sev_counts = {"HIGH": 0, "MED": 0, "LOW": 0}
    suppressed = 0
    scanned = 0
    history_info = None

    def _record(hit, fp, lineno, commit=None):
        """Append one matched line as a finding (baseline-suppressed
        findings only bump the counter). Shared by the working-tree
        loop and the history branch so both apply the same
        suppression, severity counts, and finding shape; history
        findings additionally carry their commit short-SHA."""
        nonlocal suppressed
        name, severity, secret = hit
        rel = os.path.relpath(fp, scan_root)
        if _finding_hash(rel, name, secret) in baseline_hashes:
            suppressed += 1
            return
        sev_counts[severity] += 1
        finding = {
            "file": fp,
            "line": lineno,
            "type": name,
            "severity": severity,
            "secret": secret,
        }
        if commit is not None:
            finding["commit"] = commit
        findings.append(finding)

    if history:
        repo_root = _git_repo_root(scan_root)
        if repo_root is None:
            error = "history scan needs a git repository"
            if json_output:
                return json.dumps({"tool": "scan_secrets", "path": path,
                                   "error": error})
            return f"Error: {error}"
        pathspec = os.path.relpath(os.path.abspath(path), repo_root)
        # IaC block context for the current diff: reset whenever the
        # commit or the file changes, since one commit's hunk window
        # says nothing about the next commit's block context.
        hist_state = {"commit": None, "file": None, "resource": None, "depth": 0}

        def _on_diff_line(commit, rel_file, lineno, content, is_added):
            if _excluded(exclude_patterns, rel_file):
                return True
            if os.path.splitext(rel_file)[1].lower() in SKIP_EXTS:
                return True
            if hist_state["commit"] != commit or hist_state["file"] != rel_file:
                hist_state["commit"] = commit
                hist_state["file"] = rel_file
                hist_state["resource"] = (
                    "tfvars"
                    if os.path.splitext(rel_file)[1].lower() == ".tfvars"
                    else None
                )
                hist_state["depth"] = 0
            fp = os.path.join(repo_root, rel_file)
            if _is_iac_file(fp):
                declared = _iac_resource_type(content)
                if declared is not None:
                    hist_state["resource"] = declared
                    hist_state["depth"] = content.count("{") - content.count("}")
                elif hist_state["resource"] is not None and hist_state["depth"] > 0:
                    hist_state["depth"] += content.count("{") - content.count("}")
                    if hist_state["depth"] <= 0:
                        hist_state["resource"] = None
                        hist_state["depth"] = 0
            if not is_added:
                return True
            iac_hit = _iac_credential_hit(content, fp, hist_state["resource"])
            hit = (iac_hit or _match_line(content)
                   or _config_credential_hit(content, fp)
                   or _entropy_hit(content))
            if hit:
                _record(hit, fp, lineno, commit)
            return len(findings) < max_findings

        commits_scanned, files_seen, truncated, history_error = _scan_history(
            repo_root, pathspec, MAX_HISTORY_COMMITS, _on_diff_line
        )
        if history_error is not None:
            if json_output:
                return json.dumps({"tool": "scan_secrets", "path": path,
                                   "error": history_error})
            return f"Error: {history_error}"
        scanned = len(files_seen)
        history_info = {
            "commits_scanned": commits_scanned,
            "truncated": truncated,
        }
    else:
        for fp in files:
            try:
                if os.path.getsize(fp) > MAX_FILE_BYTES:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except (OSError, UnicodeError):
                continue
            scanned += 1

            # IaC block context for this file: the resource type currently
            # open (Terraform: brace-tracked; CFN/ARM: until the next Type;
            # .tfvars: the whole file, since it holds deployment values).
            iac_resource = None
            iac_depth = 0
            if os.path.splitext(fp)[1].lower() == ".tfvars":
                iac_resource = "tfvars"
            for lineno, line in enumerate(lines, start=1):
                if _is_iac_file(fp):
                    declared = _iac_resource_type(line)
                    if declared is not None:
                        iac_resource = declared
                        iac_depth = line.count("{") - line.count("}")
                    elif iac_resource is not None and iac_depth > 0:
                        iac_depth += line.count("{") - line.count("}")
                        if iac_depth <= 0:
                            iac_resource = None
                            iac_depth = 0
                iac_hit = _iac_credential_hit(line, fp, iac_resource)
                hit = (iac_hit or _match_line(line)
                       or _config_credential_hit(line, fp)
                       or _entropy_hit(line))
                if hit:
                    _record(hit, fp, lineno)
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break

    # Repo-wide dedup: one committed key checked into many files is still
    # one secret. Compare raw values (never the masked previews) so a
    # value is counted once even when it shows up in several places.
    unique = len({f["secret"] for f in findings})

    sev_summary = ", ".join(f"{s}: {sev_counts[s]}" for s in ("HIGH", "MED", "LOW"))
    header = (
        f"Secret scan of {path}"
        + (" (git history)" if history else "")
        + f"\nFiles scanned: {scanned}\n"
        f"Findings: {len(findings)} ({sev_summary})\n"
        f"Unique secrets: {unique}"
    )
    if history_info is not None:
        history_line = (
            f"\nGit history: {history_info['commits_scanned']} commit(s) scanned"
        )
        if history_info["truncated"]:
            history_line += (
                f" (limited to the {MAX_HISTORY_COMMITS} most recent)"
            )
        header += history_line
    if since is not None:
        header += f"\nIncremental scan: only files changed since {since}"
    if suppressed:
        header += (
            f"\nSuppressed: {suppressed} acknowledged finding(s) "
            f"via {BASELINE_FILENAME}"
        )
    if findings:
        per_file = _per_file_counts(findings)
        header += "\nPer-file findings:\n" + "\n".join(
            f"  {fp}: {n}" for fp, n in per_file.items()
        )
    if not findings:
        if json_output:
            return json.dumps(_report_json(path, scanned, findings,
                                           unique, sev_counts, suppressed,
                                           since, history_info))
        return header + "\n\nNo hardcoded secrets detected. [OK]"
    if json_output:
        return json.dumps(_report_json(path, scanned, findings,
                                       unique, sev_counts, suppressed,
                                       since, history_info), indent=2)

    def _render_finding(f):
        loc = f"{f['file']}:{f['line']}"
        if "commit" in f:
            loc += f" (commit {f['commit']})"
        return (
            f"  [{f['severity']}] {f['type']}\n"
            f"      {loc}\n"
            f"      match: {_mask(f['secret'])}"
        )

    rendered = "\n\n".join(_render_finding(f) for f in findings)
    note = (
        "\n\nNote: these are heuristic matches and may include false positives. "
        "Rotate any real secret that is committed to source control."
    )
    if history:
        note += (
            " History findings stay in git until the history itself is "
            "rewritten — removing the file from HEAD is not enough."
        )
    return header + "\n\n" + rendered + note


# ---------------------------------------------------------------------------
# Tool 2: dependency vulnerability audit via OSV.dev (keyless)
# ---------------------------------------------------------------------------

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
MAX_DEPS = 100
OSV_MAX_ATTEMPTS = 4  # initial try + up to 3 retries on HTTP 429
OSV_MAX_RETRY_WAIT = 60.0  # never wait longer than this per retry


def _parse_requirements(text: str):
    """Yield (name, version) for pinned (==) requirements lines."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            yield m.group(1), m.group(2)


def _parse_package_json(text: str):
    """Yield (name, version) for npm deps, stripping range prefixes."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            cleaned = re.sub(r"^[\^~>=<\s]+", "", str(ver)).strip()
            if re.match(r"^\d+\.\d+", cleaned):
                yield name, cleaned


def _retry_after_seconds(value: str | None) -> float | None:
    """Parse a `Retry-After` header value into seconds (delta-seconds form
    only); return None when absent, non-numeric, or negative. The HTTP-date
    form is deliberately not parsed — a date is useless without trusting the
    server clock."""
    if value is None:
        return None
    try:
        seconds = int(str(value).strip())
    except ValueError:
        return None
    return float(seconds) if seconds >= 0 else None


def _parse_go_mod(text: str):
    """Yield (module, version) for `require` entries in a go.mod file.

    Handles both the block form::

        require (
            example.com/mod v1.2.3
            example.com/other v0.4.0 // indirect
        )

    and the single-line form (`require example.com/mod v1.2.3`).
    Versions keep their leading `v` — OSV's Go ecosystem normalises it.
    Only pinned module versions are reported; other directives
    (`module`, `go`, `replace`, `retract`, `exclude`, ...) are ignored.
    """
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0][0].isalnum():
                yield parts[0], parts[1]
            continue
        if line.startswith("require"):
            rest = line[len("require"):].strip()
            if rest.startswith("("):
                in_block = True
                continue
            parts = rest.split()
            if len(parts) >= 2 and parts[0][0].isalnum():
                yield parts[0], parts[1]


def _parse_pom_xml(text: str):
    """Yield (group:artifact, version) for `<dependency>` entries in a
    Maven `pom.xml`.

    OSV's Maven ecosystem names a package `groupId:artifactId`, so that
    is the name yielded here. Only the project's own `<dependencies>`
    block is read — `<dependencyManagement>` entries are version-only
    declarations, not dependencies, and are skipped. A version written
    as a property reference (`${spring.version}`) is resolved from the
    POM's `<properties>` block when possible; references that cannot be
    resolved (including inherited parent versions, which live outside
    this file) are skipped rather than queried with a placeholder.
    Dependencies without a version are skipped the same way. Malformed
    XML yields nothing, so a broken POM never breaks the audit.
    Namespace-agnostic: Maven POMs declare the
    `http://maven.apache.org/POM/4.0.0` namespace, and namespace-free
    POMs must parse the same way.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def children(elem, name: str):
        return [c for c in elem if local(c.tag) == name]

    def text_of(elem, name: str):
        found = children(elem, name)
        if not found or found[0].text is None:
            return None
        return found[0].text.strip()

    properties = {}
    for props in children(root, "properties"):
        for prop in props:
            if prop.text is not None:
                properties[local(prop.tag)] = prop.text.strip()

    def resolve(value: str) -> str | None:
        def repl(match):
            name = match.group(1)
            return properties.get(name, match.group(0))

        resolved = re.sub(r"\$\{([^}]+)\}", repl, value)
        return None if "${" in resolved else resolved

    for deps_block in children(root, "dependencies"):
        for dep in children(deps_block, "dependency"):
            group = text_of(dep, "groupId")
            artifact = text_of(dep, "artifactId")
            version = text_of(dep, "version")
            if not group or not artifact or not version:
                continue
            version = resolve(version)
            if version is None:
                continue
            yield f"{group}:{artifact}", version


# Package-URL type -> OSV ecosystem, for CycloneDX SBOM components.
_PURL_ECOSYSTEMS = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
}

# Filenames that mark a JSON file as a CycloneDX SBOM even when it
# omits the `bomFormat` field.
_SBOM_FILENAMES = ("sbom.json", "cyclonedx.json", "bom.json")


def _parse_purl(purl: str):
    """(name, version, ecosystem) for a package URL, or None when the
    purl is malformed, has no version, or names an ecosystem GuardX
    does not query.

    `pkg:maven/org.apache.commons/commons-lang3@3.12.0` becomes
    `org.apache.commons:commons-lang3` (the OSV Maven package name),
    `pkg:npm/%40angular/core@16.0.0` becomes `@angular/core` (scoped
    npm names are URL-decoded), and
    `pkg:golang/github.com/gin-gonic/gin@v1.9.1` keeps its `v` prefix —
    OSV's Go ecosystem normalises it. Qualifiers (`?...`) and subpaths
    (`#...`) never affect a package's identity and are stripped.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = re.split(r"[?#]", purl[4:], maxsplit=1)[0]
    ptype, slash, path = rest.partition("/")
    if not slash:
        return None
    ecosystem = _PURL_ECOSYSTEMS.get(ptype.lower())
    if ecosystem is None:
        return None
    if "@" not in path:
        return None
    path, _, version = path.rpartition("@")
    version = unquote(version)
    if not version:
        return None
    segments = [unquote(s) for s in path.split("/") if s]
    if not segments:
        return None
    name = segments[-1]
    namespace = "/".join(segments[:-1])
    if not name:
        return None
    ptype = ptype.lower()
    if ptype == "maven":
        name = f"{namespace}:{name}" if namespace else name
    elif ptype in ("golang", "npm"):
        name = f"{namespace}/{name}" if namespace else name
    return name, version, ecosystem


def _is_cyclonedx(data, name_lower: str) -> bool:
    """True when parsed JSON is a CycloneDX SBOM: a `bomFormat`
    of "CycloneDX" says so outright, and a file named like an SBOM
    (`sbom.json`, `cyclonedx.json`, `bom.json`, `*.cdx.json`) with a
    `components` list counts too, for exporters that omit the field.
    Anything else — a package.json with an incidental `components`
    key, for example — is not an SBOM."""
    if not isinstance(data, dict):
        return False
    if str(data.get("bomFormat", "")).lower() == "cyclonedx":
        return True
    if name_lower in _SBOM_FILENAMES or name_lower.endswith(".cdx.json"):
        return isinstance(data.get("components"), list)
    return False


def _parse_cyclonedx_sbom(data):
    """Yield (name, version, ecosystem) for the components of a parsed
    CycloneDX SBOM.

    Each component is identified by its package URL (`purl`), which
    carries both the ecosystem and the canonical package name — so one
    SBOM can mix Maven, npm, PyPI, Go, and crates.io components and
    each is queried against its own ecosystem. Components without a
    purl (or with an unsupported purl type, or no version) are skipped
    rather than guessed at: without a purl there is no reliable way to
    tell which ecosystem a bare name belongs to. The SBOM's own root
    component (`metadata.component`) is the audited project itself,
    not a dependency, and is not yielded."""
    components = data.get("components") if isinstance(data, dict) else None
    if not isinstance(components, list):
        return
    for comp in components:
        if not isinstance(comp, dict):
            continue
        parsed = _parse_purl(comp.get("purl"))
        if parsed is not None:
            yield parsed


def _parse_package_lock(text: str):
    """Yield (name, version) pairs from a `package-lock.json`.

    Handles the v2/v3 `packages` map (keys are `node_modules/...`
    paths; scoped names keep their `@scope/` prefix, nested copies
    resolve to the last `node_modules` segment) and the legacy v1
    `dependencies` tree (recursed, since nested deps carry their own
    versions). Exact (name, version) duplicates — v2 files carry both
    maps — are yielded once.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    seen = set()

    def emit(name, version):
        if name and version:
            pair = (str(name), str(version))
            if pair not in seen:
                seen.add(pair)
                yield pair

    for key, info in (data.get("packages") or {}).items():
        if not key or not isinstance(info, dict):
            continue
        version = info.get("version")
        if not version:
            continue
        parts = str(key).split("/")
        idxs = [i for i, p in enumerate(parts) if p == "node_modules"]
        name_parts = parts[idxs[-1] + 1:] if idxs else parts
        if name_parts:
            yield from emit("/".join(name_parts), version)

    def walk_deps(deps):
        if not isinstance(deps, dict):
            return
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            yield from emit(name, info.get("version"))
            yield from walk_deps(info.get("dependencies"))

    yield from walk_deps(data.get("dependencies"))


def _parse_toml_lock(text: str):
    """Yield (name, version) pairs from `poetry.lock` / `Cargo.lock`.

    Both formats are TOML with one `[[package]]` block per dependency;
    each block's `name`/`version` lines are read and everything else
    (sources, checksums, dependency lists, `[package.dependencies]`
    sub-tables) is ignored. No TOML library is needed — and none is
    assumed, since the stdlib only gained `tomllib` in Python 3.11
    while GuardX supports 3.10.
    """
    current = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[["):
            if isinstance(current, dict) and current.get("name") and current.get("version"):
                yield current["name"], current["version"]
            current = {} if line == "[[package]]" else None
            continue
        if not isinstance(current, dict):
            continue
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            current["name"] = m.group(1)
            continue
        m = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if m:
            current["version"] = m.group(1)
    if isinstance(current, dict) and current.get("name") and current.get("version"):
        yield current["name"], current["version"]


async def _osv_query(client: httpx.AsyncClient, name: str, version: str, ecosystem: str):
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    attempt = 0
    while True:
        try:
            resp = await client.post(OSV_QUERY, json=payload)
        except httpx.RequestError:
            return name, version, None
        if resp.status_code != 200:
            attempt += 1
            if resp.status_code != 429 or attempt >= OSV_MAX_ATTEMPTS:
                return name, version, None
            # Honor Retry-After when present, else exponential backoff
            # (1s, 2s, 4s), clamped so one bad header can't stall the scan.
            retry_after = _retry_after_seconds(resp.headers.get("retry-after"))
            wait = retry_after if retry_after is not None else 2.0 ** (attempt - 1)
            await asyncio.sleep(min(wait, OSV_MAX_RETRY_WAIT))
            continue
        vulns = resp.json().get("vulns", [])
        return name, version, vulns


async def _osv_querybatch(client: httpx.AsyncClient, deps: list, ecosystem: str):
    """[(name, version, vulns | None)] for every dep in `deps`, from a
    single `POST /v1/querybatch` call.

    The response's `results` array is in query order, so result `i`
    belongs to dep `i`; an entry without a `vulns` key means no known
    vulnerabilities. Retry behaviour mirrors `_osv_query`: HTTP 429 is
    retried up to OSV_MAX_ATTEMPTS times honouring `Retry-After` (else
    exponential 1s/2s/4s, clamped), other non-200 statuses and network
    failures fail the whole batch (every dep reported as a lookup
    failure, counted in the header) rather than silently claiming the
    batch clean. A response shorter than the query list is treated the
    same way for the missing tail — a truncated batch must not read as
    "no vulnerabilities". `_osv_query` stays for single-package callers
    and its backoff tests; `audit_dependencies` uses this batch call."""
    queries = [
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        for name, version in deps
    ]
    attempt = 0
    while True:
        try:
            resp = await client.post(OSV_QUERYBATCH, json={"queries": queries})
        except httpx.RequestError:
            return [(name, version, None) for name, version in deps]
        if resp.status_code != 200:
            attempt += 1
            if resp.status_code != 429 or attempt >= OSV_MAX_ATTEMPTS:
                return [(name, version, None) for name, version in deps]
            retry_after = _retry_after_seconds(resp.headers.get("retry-after"))
            wait = retry_after if retry_after is not None else 2.0 ** (attempt - 1)
            await asyncio.sleep(min(wait, OSV_MAX_RETRY_WAIT))
            continue
        results = resp.json().get("results", [])
        out = []
        for i, (name, version) in enumerate(deps):
            if i >= len(results) or not isinstance(results[i], dict):
                out.append((name, version, None))
            else:
                out.append((name, version, results[i].get("vulns", [])))
        return out


# CVSS severity bands (OSV `severity` entries carry a numeric score).
_SEVERITY_RANKS = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_MIN_SEVERITY_ALIASES = {"MED": "MEDIUM"}


def _vuln_cvss_score(vuln: dict) -> float | None:
    """Best (highest) numeric CVSS score on an OSV vuln, or None when the
    vuln carries no parseable score."""
    best = None
    for entry in vuln.get("severity", []) or []:
        try:
            score = float(entry.get("score"))
        except (TypeError, ValueError):
            continue
        if best is None or score > best:
            best = score
    return best


def _vuln_severity(vuln: dict) -> tuple[str, float | None]:
    """(label, score) for an OSV vuln, using standard CVSS bands:
    >= 9.0 CRITICAL, >= 7.0 HIGH, >= 4.0 MEDIUM, > 0 LOW, else UNKNOWN."""
    score = _vuln_cvss_score(vuln)
    if score is None:
        return "UNKNOWN", None
    if score >= 9.0:
        return "CRITICAL", score
    if score >= 7.0:
        return "HIGH", score
    if score >= 4.0:
        return "MEDIUM", score
    if score > 0:
        return "LOW", score
    return "UNKNOWN", score


def _version_tokens(version: str) -> list:
    """Sortable tokens for a version string: numeric runs become (0, int)
    and text runs (1, str), so 1.10.0 sorts after 1.9.0. A leading "v"
    is stripped; separators (`.`, `-`, `+`, `_`) just split the runs."""
    tokens = []
    for part in re.split(r"[.\-+_]", str(version).strip().lstrip("vV")):
        if not part:
            continue
        for tok in re.findall(r"\d+|[^\d]+", part):
            tokens.append((0, int(tok)) if tok.isdigit() else (1, tok))
    return tokens


def _version_cmp(a: str, b: str) -> int:
    """-1/0/1 version comparison, best-effort for the version strings OSV
    carries: numeric runs compare numerically, a trailing pre-release
    tag sorts below the bare release ("1.2.3rc1" < "1.2.3"), and a
    shorter prefix sorts below its extension ("1.2" < "1.2.3"). Only
    used to decide whether a queried version sits below an OSV `fixed`
    version — never for security decisions."""
    ta, tb = _version_tokens(a), _version_tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if x[0] == 0 and y[0] == 0:
            return -1 if x[1] < y[1] else 1
        if x[0] == 0:
            return -1
        if y[0] == 0:
            return 1
        return -1 if x[1] < y[1] else 1
    if len(ta) == len(tb):
        return 0
    # One is a prefix of the other: a trailing pre-release tag sorts
    # below the bare release; otherwise the shorter one is earlier.
    longer = ta if len(ta) > len(tb) else tb
    extra_is_prerelease = longer[min(len(ta), len(tb))][0] == 1
    if extra_is_prerelease:
        return 1 if len(ta) < len(tb) else -1
    return -1 if len(ta) < len(tb) else 1


def _vuln_fixed_versions(vuln: dict, version: str, ecosystem: str | None = None):
    """(fixed_versions, has_unfixed_range) for one OSV vuln at `version`.

    Walks each `affected` entry's `ranges` events in order: an
    `introduced` event at or below the queried version opens the
    affected window, a `fixed` event at or below it closes it, and a
    `last_affected`/`limit` event bounds it. For every range still open
    at the queried version, the first `fixed` event above it is the
    version that closes the hole; ranges with no such event are
    reported via `has_unfixed_range` (e.g. only a `last_affected` is
    known, or no fix has been released yet). An entry with no
    `introduced` event is treated as affected from the start, per the
    OSV schema. Entries without `ranges` (a bare `versions` list) carry
    no fix information and are skipped, as are entries for a different
    ecosystem than the one queried (when the entry names one). The
    returned versions are deduplicated and sorted ascending, so the
    caller can suggest the highest one as the single upgrade target
    that closes every affected range.
    """
    fixed: list[str] = []
    unfixed = False
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package") or {}
        entry_eco = pkg.get("ecosystem")
        if ecosystem is not None and entry_eco is not None and entry_eco != ecosystem:
            continue
        for rng in affected.get("ranges", []) or []:
            events = rng.get("events", []) or []
            introduced_seen = any("introduced" in e for e in events)
            # No introduced event: affected from the start.
            affected_now = not introduced_seen
            fix_after = None
            for ev in events:
                if "introduced" in ev:
                    affected_now = _version_cmp(ev["introduced"], version) <= 0
                elif "fixed" in ev:
                    if _version_cmp(ev["fixed"], version) <= 0:
                        affected_now = False
                    elif affected_now and fix_after is None:
                        fix_after = ev["fixed"]
                elif "last_affected" in ev:
                    affected_now = _version_cmp(ev["last_affected"], version) >= 0
                elif "limit" in ev:
                    if _version_cmp(ev["limit"], version) <= 0:
                        affected_now = False
            if affected_now:
                if fix_after is not None:
                    fixed.append(fix_after)
                else:
                    unfixed = True
    fixed = sorted(set(fixed), key=cmp_to_key(_version_cmp))
    return fixed, unfixed


def _parse_min_severity(value: str | None) -> int | None:
    """Rank for a `min_severity` filter value, or None when the value is
    invalid. A None input means "no filter" and is handled by the caller,
    not here. Accepts any case; "MED" is an alias for "MEDIUM"."""
    if value is None:
        return None
    label = _MIN_SEVERITY_ALIASES.get(value.strip().upper(), value.strip().upper())
    return _SEVERITY_RANKS.get(label)


def _dedupe_deps(deps: list) -> tuple[list, int]:
    """(unique_deps, cache_hits) for one audit run: exact (name, version)
    duplicates are dropped in first-seen order, so the same package@version
    is queried against OSV once per run even when several manifest entries
    reference it (e.g. a pin repeated in requirements.txt, or the same
    package in both `dependencies` and `devDependencies`). The cache is
    per-run only — OSV data changes, so nothing is persisted across runs."""
    seen = set()
    unique = []
    for dep in deps:
        if dep not in seen:
            seen.add(dep)
            unique.append(dep)
    return unique, len(deps) - len(unique)


@mcp.tool()
async def audit_dependencies(path: str, min_severity: str | None = None) -> str:
    """Audit a dependency manifest against the OSV vulnerability database.

    Supports Python (requirements.txt), npm (package.json), Go
    modules (go.mod), and Maven (pom.xml). Only pinned/exact versions
    are checked. Lockfiles
    resolve transitive dependencies too: `package-lock.json` (npm),
    `poetry.lock` (PyPI), and `Cargo.lock` (crates.io) — so a
    vulnerability in a dependency-of-a-dependency is caught even when
    the direct manifest never names it. A CycloneDX SBOM (a JSON file
    with `bomFormat: CycloneDX`, or named `sbom.json`, `cyclonedx.json`,
    `bom.json`, or `*.cdx.json`) is audited too: each component is
    identified by its package URL, so one SBOM can mix Maven, npm,
    PyPI, Go, and crates.io components and each is queried against its
    own ecosystem. The same package@version is queried against OSV
    only once per run: duplicate manifest entries are served from a
    per-run cache and counted in the header. All distinct dependencies
    are queried in one `POST /v1/querybatch` call per ecosystem instead
    of one query per package, so a large manifest costs one round trip
    per ecosystem (with the same 429 retry behaviour as a single
    query; a failed batch counts every dep as a lookup failure).

    Args:
        path: Path to a requirements.txt, package.json, go.mod, pom.xml,
            lockfile (package-lock.json, poetry.lock, Cargo.lock), or
            CycloneDX SBOM (.json).
        min_severity: Optional severity floor ("LOW", "MEDIUM"/"MED",
            "HIGH", "CRITICAL", any case). Vulnerabilities below the
            floor are hidden from the report and counted in the header,
            so noisy dependency trees can be triaged by severity.
            Each reported vulnerability is tagged with its CVSS band
            and score (e.g. `[HIGH 7.5]`); vulnerabilities with no
            CVSS score are tagged `[UNKNOWN]` and are hidden by any
            filter, since they cannot be shown to meet the floor.
            Each finding also carries fixed-version guidance from the
            OSV `affected` ranges: "upgrade to >= X" names the lowest
            version that closes every affected range for the queried
            version, or "no fixed version released" when an affected
            range has no fix yet; vulnerabilities without range data
            carry no guidance.

    Returns:
        A report of known vulnerabilities (OSV/CVE ids and summaries).
    """
    if not os.path.isfile(path):
        return f"Error: file not found: {path}"

    min_rank = None
    min_label = None
    if min_severity is not None:
        min_rank = _parse_min_severity(min_severity)
        if min_rank is None:
            return (
                f"Error: unknown min_severity: {min_severity!r}. "
                "Use LOW, MEDIUM (or MED), HIGH, or CRITICAL."
            )
        min_label = _MIN_SEVERITY_ALIASES.get(
            min_severity.strip().upper(), min_severity.strip().upper()
        )

    name_lower = os.path.basename(path).lower()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()

    # Every input normalises to (name, version, ecosystem) triples, so
    # a multi-ecosystem SBOM flows through the same query/report path
    # as a single-ecosystem manifest.
    triples: list[tuple[str, str, str]] = []
    if name_lower == "package-lock.json":
        triples = [(n, v, "npm") for n, v in _parse_package_lock(text)]
    elif name_lower == "poetry.lock":
        triples = [(n, v, "PyPI") for n, v in _parse_toml_lock(text)]
    elif name_lower == "cargo.lock":
        triples = [(n, v, "crates.io") for n, v in _parse_toml_lock(text)]
    elif name_lower.endswith("package.json"):
        triples = [(n, v, "npm") for n, v in _parse_package_json(text)]
    elif name_lower == "go.mod":
        triples = [(n, v, "Go") for n, v in _parse_go_mod(text)]
    elif name_lower == "pom.xml":
        triples = [(n, v, "Maven") for n, v in _parse_pom_xml(text)]
    elif "requirements" in name_lower or name_lower.endswith(".txt"):
        triples = [(n, v, "PyPI") for n, v in _parse_requirements(text)]
    elif name_lower.endswith(".json"):
        try:
            sbom_data = json.loads(text)
        except json.JSONDecodeError:
            sbom_data = None
        if sbom_data is not None and _is_cyclonedx(sbom_data, name_lower):
            triples = list(_parse_cyclonedx_sbom(sbom_data))
        else:
            return (
                f"Unsupported manifest: {name_lower}. "
                "Provide a requirements.txt, package.json, go.mod, pom.xml, "
                "package-lock.json, poetry.lock, Cargo.lock, or a "
                "CycloneDX SBOM (.json)."
            )
    else:
        return (
            f"Unsupported manifest: {name_lower}. "
            "Provide a requirements.txt, package.json, go.mod, pom.xml, "
            "package-lock.json, poetry.lock, Cargo.lock, or a "
            "CycloneDX SBOM (.json)."
        )

    if not triples:
        return (
            f"No pinned dependencies found in {path}. "
            '(Only exact versions are checked: "pkg==1.2.3" for pip, '
            '"1.2.3" for npm, a go.mod require line, or a pom.xml '
            "dependency with a groupId, artifactId, and version; lockfiles "
            "contribute every package entry they contain; SBOM components "
            "need a package URL with a supported ecosystem and a version.)"
        )

    triples = triples[:MAX_DEPS]
    unique_triples, cache_hits = _dedupe_deps(triples)

    # Group by ecosystem (first-seen order) — one querybatch call per
    # ecosystem, since a batch carries a single ecosystem per query.
    groups: dict[str, list] = {}
    for name, version, eco in unique_triples:
        groups.setdefault(eco, []).append((name, version))

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}
    ) as client:
        # One querybatch call per ecosystem, not one query per package
        # — large manifests cost one round trip per ecosystem.
        results = []
        for eco, eco_deps in groups.items():
            for name, version, vulns in await _osv_querybatch(
                client, eco_deps, eco
            ):
                results.append((name, version, vulns, eco))

    vuln_blocks = []
    errors = 0
    vuln_pkgs = 0
    filtered_out = 0
    for name, version, vulns, eco in results:
        if vulns is None:
            errors += 1
            continue
        if not vulns:
            continue
        kept = []
        for v in vulns:
            label, score = _vuln_severity(v)
            if min_rank is not None and _SEVERITY_RANKS[label] < min_rank:
                filtered_out += 1
                continue
            kept.append((v, label, score))
        if not kept:
            continue
        vuln_pkgs += 1
        ids = []
        for v, label, score in kept[:10]:
            vid = v.get("id", "?")
            aliases = ", ".join(v.get("aliases", [])[:3])
            summary = v.get("summary", "").strip()
            tag = f" [{label} {score:g}]" if score is not None else f" [{label}]"
            vuln_label = f"{vid}" + (f" ({aliases})" if aliases else "") + tag
            fixed, unfixed = _vuln_fixed_versions(v, version, eco)
            if fixed:
                # The highest fixed version closes every affected range.
                guidance = f" — upgrade to >= {fixed[-1]}"
            elif unfixed:
                guidance = " — no fixed version released"
            else:
                guidance = ""
            ids.append(
                f"      - {vuln_label}"
                + (f": {summary}" if summary else "")
                + guidance
            )
        vuln_blocks.append(
            f"  [!] {name}=={version}  -> {len(kept)} known vuln(s)\n" + "\n".join(ids)
        )

    ecosystems = list(groups)
    eco_label = "Ecosystem" if len(ecosystems) == 1 else "Ecosystems"
    header = (
        f"Dependency audit of {path}\n"
        f"{eco_label}: {', '.join(ecosystems)}\n"
        f"Dependencies checked: {len(unique_triples)}\n"
        f"Vulnerable packages: {vuln_pkgs}"
    )
    if min_label is not None:
        header += f"\nMinimum severity: {min_label}"
    if filtered_out:
        header += f"\nVulnerabilities hidden by filter: {filtered_out}"
    if cache_hits:
        header += f"\nOSV cache hits: {cache_hits}"
    if errors:
        header += f"\nLookups failed (network): {errors}"
    if not vuln_blocks:
        return header + "\n\nNo known vulnerabilities found. [OK]"
    return header + "\n\n" + "\n\n".join(vuln_blocks)


# ---------------------------------------------------------------------------
# Tool 3: Have I Been Pwned password check (k-anonymity, keyless)
# ---------------------------------------------------------------------------

HIBP_RANGE = "https://api.pwnedpasswords.com/range/"
HIBP_MAX_ATTEMPTS = 3  # initial request + 2 retries on transient network failures


async def _hibp_suffix_counts(client, prefix: str):
    """(suffix -> breach count, error) for one HIBP range-prefix lookup.

    Shared by the single and batch password checks so both get the same
    retry behaviour: transient network failures (`httpx.RequestError`)
    are retried twice with full-jitter backoff (up to 1s, then up to
    2s); HTTP error statuses are not retried. Malformed response lines
    are ignored, matching the single-check parser. Returns (None,
    error_string) on failure.
    """
    resp = None
    for attempt in range(HIBP_MAX_ATTEMPTS):
        try:
            resp = await client.get(HIBP_RANGE + prefix)
            break
        except httpx.RequestError as exc:
            if attempt == HIBP_MAX_ATTEMPTS - 1:
                return None, (
                    f"Error: could not reach HIBP "
                    f"({exc.__class__.__name__}: {exc})."
                )
            # Transient network failure: full-jitter backoff before retrying.
            await asyncio.sleep(random.uniform(0, 2 ** attempt))

    # The loop either breaks with a response or returns the error above.
    if resp.status_code != 200:
        return None, f"HIBP returned HTTP {resp.status_code}."

    counts = {}
    for line in resp.text.splitlines():
        h, _, c = line.partition(":")
        try:
            counts[h.strip().upper()] = int(c.strip())
        except ValueError:
            continue
    return counts, None


@mcp.tool()
async def check_pwned_password(password: str) -> str:
    """Check whether a password appears in known data breaches.

    Uses the Have I Been Pwned range API with k-anonymity: only the first
    5 characters of the password's SHA-1 hash are ever sent over the
    network, so the password itself is never transmitted.

    Args:
        password: The password to check.

    Returns:
        Whether the password was found in breaches and how many times.
        Transient network failures (`httpx.RequestError`) are retried
        twice with full-jitter backoff (up to 1s, then up to 2s) before
        reporting an error; HTTP error statuses are not retried.
    """
    if not password:
        return "Error: empty password."

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    ) as client:
        counts, error = await _hibp_suffix_counts(client, prefix)
    if error is not None:
        return error
    count = counts.get(suffix, 0)

    if count == 0:
        return (
            "Good news: this password was NOT found in any known breach. [OK]\n"
            "(Only the SHA-1 prefix was sent; the password never left this machine.)"
        )
    return (
        f"WARNING: this password has appeared in known breaches {count:,} times. [!]\n"
        "Do not use it. Choose a unique, strong password and enable MFA.\n"
        "(Only the SHA-1 prefix was sent; the password never left this machine.)"
    )


@mcp.tool()
async def check_pwned_passwords(passwords: list[str]) -> str:
    """Check a list of passwords against known breaches, in one call.

    Same k-anonymity model as `check_pwned_password`: only the first 5
    characters of each password's SHA-1 hash are sent, and the match is
    found locally. Passwords sharing a hash prefix are looked up once —
    one range request per distinct prefix, in first-seen order — so a
    batch with duplicate or prefix-colliding entries costs fewer
    requests than one call per password. Each password still gets its
    own summary line, and per-prefix lookup failures (network or HTTP
    error) are reported on that prefix's lines instead of failing the
    whole batch.

    Args:
        passwords: The passwords to check.

    Returns:
        A header line with breached/clean/error counts, then exactly
        one summary line per password, in input order, numbered
        ("Password 1: ...") — passwords themselves never appear in the
        output, only their position in the list.
    """
    if not passwords:
        return "Error: no passwords given."

    # Group by hash prefix (first-seen order) so one range request
    # serves every password sharing a prefix; empty entries get an
    # error line without any network call.
    groups: dict[str, list[tuple[int, str]]] = {}
    lines: dict[int, str] = {}
    for idx, password in enumerate(passwords, start=1):
        if not password:
            lines[idx] = f"Password {idx}: Error: empty password."
            continue
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        groups.setdefault(sha1[:5], []).append((idx, sha1[5:]))

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    ) as client:
        for prefix, members in groups.items():
            counts, error = await _hibp_suffix_counts(client, prefix)
            for idx, suffix in members:
                if error is not None:
                    lines[idx] = f"Password {idx}: {error}"
                elif counts.get(suffix, 0) > 0:
                    lines[idx] = (
                        f"Password {idx}: WARNING — appeared in known "
                        f"breaches {counts[suffix]:,} times. Do not use it. [!]"
                    )
                else:
                    lines[idx] = (
                        f"Password {idx}: NOT found in any known breach. [OK]"
                    )

    breached = sum("WARNING" in line for line in lines.values())
    clean = sum("[OK]" in line for line in lines.values())
    errors = len(lines) - breached - clean
    header = (
        f"Password breach check: {len(passwords)} checked "
        f"({breached} breached, {clean} clean, {errors} errors)"
    )
    body = "\n".join(lines[idx] for idx in range(1, len(passwords) + 1))
    return header + "\n" + body + (
        "\n(Only SHA-1 prefixes were sent; the passwords never left "
        "this machine.)"
    )


# ---------------------------------------------------------------------------
# Prompt: one-shot codebase audit
# ---------------------------------------------------------------------------

def audit_this_codebase_prompt(path: str = ".", manifest: str | None = None) -> str:
    """Prompt template chaining GuardX's tools into a one-shot audit.

    Registered as an MCP prompt when the installed SDK supports
    `mcp.prompt()` (FastMCP 1.x does); on SDKs without prompt support
    the plain function is still importable and returns the same text,
    so the template is testable without a running server. The prompt
    tells the client to run `scan_secrets` first, then
    `audit_dependencies` on the project's manifest, then write a
    remediation summary — secrets first (HIGH before MED/LOW),
    vulnerabilities second — using only masked previews, never
    pasting a real secret or password into its answer.
    """
    manifest_text = manifest or (
        "the project's dependency manifest "
        "(requirements.txt, package.json, go.mod, or a lockfile)"
    )
    return (
        f"Audit this codebase for security issues: {path}\n\n"
        "Work through these steps in order, using only the GuardX tools:\n\n"
        "1. Run `scan_secrets` on the codebase path above. Note every "
        "finding's file, line, type, and severity, and the report's "
        "per-severity counts and unique-secrets count.\n"
        "2. Run `audit_dependencies` on " + manifest_text + ". Note "
        "every vulnerable package, its CVE/GHSA ids, and the CVSS band "
        "and score of each vulnerability.\n"
        "3. Write a remediation summary, in this order:\n"
        "   a. Secrets to rotate immediately (HIGH findings first, then "
        "MED, then LOW) — one line per finding: file, line, type.\n"
        "   b. Dependencies to upgrade — one line per package: name, "
        "pinned version, and its highest-severity vulnerability.\n"
        "   c. Anything that looks like a false positive, and why.\n\n"
        "Rules: quote only masked previews from the tool output — never "
        "paste a real secret, token, or password into your answer. Do "
        "not change any file; this audit is read-only. If a tool "
        "reports a network or lookup failure, say so plainly instead "
        "of claiming that area is clean."
    )


try:
    audit_this_codebase_prompt = mcp.prompt()(audit_this_codebase_prompt)  # type: ignore[attr-defined]
except AttributeError:
    pass


if __name__ == "__main__":
    mcp.run()
