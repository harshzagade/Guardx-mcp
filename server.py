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
from collections import Counter
from datetime import datetime

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


def _report_json(path, scanned, findings, unique, sev_counts, suppressed=0, since=None):
    """Build the machine-readable `scan_secrets` report dict.

    Finding previews are masked with the same `_mask()` used by the text
    report, so the JSON is safe to store in CI logs.
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
            }
            for f in findings
        ],
    }
    if since is not None:
        report["since"] = since
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


@mcp.tool()
def scan_secrets(
    path: str,
    max_findings: int = 200,
    exclude: str | None = None,
    json_output: bool = False,
    baseline: str | None = None,
    since: str | None = None,
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
        paths are not counted as scanned.
    """
    if not os.path.exists(path):
        if json_output:
            return json.dumps({"tool": "scan_secrets", "path": path,
                               "error": f"path does not exist: {path}"})
        return f"Error: path does not exist: {path}"

    exclude_patterns = _parse_exclude(exclude)

    files = []
    if os.path.isfile(path):
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
    for fp in files:
        try:
            if os.path.getsize(fp) > MAX_FILE_BYTES:
                continue
            with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except (OSError, UnicodeError):
            continue
        scanned += 1

        for lineno, line in enumerate(lines, start=1):
            hit = (_match_line(line) or _config_credential_hit(line, fp)
                   or _entropy_hit(line))
            if hit:
                name, severity, secret = hit
                rel = os.path.relpath(fp, scan_root)
                if _finding_hash(rel, name, secret) in baseline_hashes:
                    suppressed += 1
                    continue
                sev_counts[severity] += 1
                findings.append(
                    {
                        "file": fp,
                        "line": lineno,
                        "type": name,
                        "severity": severity,
                        "secret": secret,
                    }
                )
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
        f"Secret scan of {path}\n"
        f"Files scanned: {scanned}\n"
        f"Findings: {len(findings)} ({sev_summary})\n"
        f"Unique secrets: {unique}"
    )
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
                                           unique, sev_counts, suppressed, since))
        return header + "\n\nNo hardcoded secrets detected. [OK]"
    if json_output:
        return json.dumps(_report_json(path, scanned, findings,
                                       unique, sev_counts, suppressed, since), indent=2)
    rendered = "\n\n".join(
        f"  [{f['severity']}] {f['type']}\n"
        f"      {f['file']}:{f['line']}\n"
        f"      match: {_mask(f['secret'])}"
        for f in findings
    )
    note = (
        "\n\nNote: these are heuristic matches and may include false positives. "
        "Rotate any real secret that is committed to source control."
    )
    return header + "\n\n" + rendered + note


# ---------------------------------------------------------------------------
# Tool 2: dependency vulnerability audit via OSV.dev (keyless)
# ---------------------------------------------------------------------------

OSV_QUERY = "https://api.osv.dev/v1/query"
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

    Supports Python (requirements.txt), npm (package.json), and Go
    modules (go.mod). Only pinned/exact versions are checked. Lockfiles
    resolve transitive dependencies too: `package-lock.json` (npm),
    `poetry.lock` (PyPI), and `Cargo.lock` (crates.io) — so a
    vulnerability in a dependency-of-a-dependency is caught even when
    the direct manifest never names it. The same package@version is
    queried against OSV only once per run: duplicate manifest entries
    are served from a per-run cache and counted in the header.

    Args:
        path: Path to a requirements.txt, package.json, go.mod, or
            lockfile (package-lock.json, poetry.lock, Cargo.lock).
        min_severity: Optional severity floor ("LOW", "MEDIUM"/"MED",
            "HIGH", "CRITICAL", any case). Vulnerabilities below the
            floor are hidden from the report and counted in the header,
            so noisy dependency trees can be triaged by severity.
            Each reported vulnerability is tagged with its CVSS band
            and score (e.g. `[HIGH 7.5]`); vulnerabilities with no
            CVSS score are tagged `[UNKNOWN]` and are hidden by any
            filter, since they cannot be shown to meet the floor.

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

    if name_lower == "package-lock.json":
        ecosystem = "npm"
        deps = list(_parse_package_lock(text))
    elif name_lower == "poetry.lock":
        ecosystem = "PyPI"
        deps = list(_parse_toml_lock(text))
    elif name_lower == "cargo.lock":
        ecosystem = "crates.io"
        deps = list(_parse_toml_lock(text))
    elif name_lower.endswith("package.json"):
        ecosystem = "npm"
        deps = list(_parse_package_json(text))
    elif name_lower == "go.mod":
        ecosystem = "Go"
        deps = list(_parse_go_mod(text))
    elif "requirements" in name_lower or name_lower.endswith(".txt"):
        ecosystem = "PyPI"
        deps = list(_parse_requirements(text))
    else:
        return (
            f"Unsupported manifest: {name_lower}. "
            "Provide a requirements.txt, package.json, go.mod, "
            "package-lock.json, poetry.lock, or Cargo.lock."
        )

    if not deps:
        return (
            f"No pinned dependencies found in {path}. "
            '(Only exact versions are checked: "pkg==1.2.3" for pip, '
            '"1.2.3" for npm, or a go.mod require line; lockfiles '
            "contribute every package entry they contain.)"
        )

    deps = deps[:MAX_DEPS]
    unique_deps, cache_hits = _dedupe_deps(deps)

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}
    ) as client:
        results = await asyncio.gather(
            *[_osv_query(client, n, v, ecosystem) for n, v in unique_deps]
        )

    vuln_blocks = []
    errors = 0
    vuln_pkgs = 0
    filtered_out = 0
    for name, version, vulns in results:
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
            ids.append(f"      - {vuln_label}" + (f": {summary}" if summary else ""))
        vuln_blocks.append(
            f"  [!] {name}=={version}  -> {len(kept)} known vuln(s)\n" + "\n".join(ids)
        )

    header = (
        f"Dependency audit of {path}\n"
        f"Ecosystem: {ecosystem}\n"
        f"Dependencies checked: {len(unique_deps)}\n"
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

    resp = None
    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    ) as client:
        for attempt in range(HIBP_MAX_ATTEMPTS):
            try:
                resp = await client.get(HIBP_RANGE + prefix)
                break
            except httpx.RequestError as exc:
                if attempt == HIBP_MAX_ATTEMPTS - 1:
                    return (
                        f"Error: could not reach HIBP "
                        f"({exc.__class__.__name__}: {exc})."
                    )
                # Transient network failure: full-jitter backoff before retrying.
                await asyncio.sleep(random.uniform(0, 2 ** attempt))

    # The loop either breaks with a response or returns the error above.
    if resp.status_code != 200:
        return f"HIBP returned HTTP {resp.status_code}."

    count = 0
    for line in resp.text.splitlines():
        h, _, c = line.partition(":")
        if h.strip().upper() == suffix:
            count = int(c.strip())
            break

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


if __name__ == "__main__":
    mcp.run()
