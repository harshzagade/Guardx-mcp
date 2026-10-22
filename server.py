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
import os
import re
import json
import asyncio
import hashlib

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


def _mask(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return secret[:2] + "****"
    return f"{secret[:4]}...{secret[-2:]} (len {len(secret)})"


def _report_json(path, scanned, findings, unique, sev_counts):
    """Build the machine-readable `scan_secrets` report dict.

    Finding previews are masked with the same `_mask()` used by the text
    report, so the JSON is safe to store in CI logs.
    """
    return {
        "tool": "scan_secrets",
        "path": path,
        "files_scanned": scanned,
        "findings_count": len(findings),
        "unique_secrets": unique,
        "severity_counts": dict(sev_counts),
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


@mcp.tool()
def scan_secrets(
    path: str,
    max_findings: int = 200,
    exclude: str | None = None,
    json_output: bool = False,
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
            per-severity counts, and a findings array of
            {file, line, type, severity, match} — previews are masked
            exactly like the text report. Errors are returned as
            {"error": ...} objects instead of plain "Error: ..." strings.

    Returns:
        A report of likely secrets with file, line number, type, and a
        masked preview. Values are masked so the report is safe to share.
        The header carries per-severity counts plus a "Unique secrets"
        count — the number of distinct secret values across the whole
        scan, so a key committed in twelve files shows as one unique
        secret rather than twelve independent findings. When scanning a
        directory, a `.gitignore` at the scan root is honoured
        (basename/dir/negation patterns); ignored paths are not counted
        as scanned.
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
                if _gitignore_ignored(patterns, rel, False):
                    continue
                if _excluded(exclude_patterns, rel):
                    continue
                files.append(os.path.join(root, n))

    findings = []
    sev_counts = {"HIGH": 0, "MED": 0, "LOW": 0}
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
            hit = _match_line(line)
            if hit:
                name, severity, secret = hit
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
    if not findings:
        if json_output:
            return json.dumps(_report_json(path, scanned, findings,
                                           unique, sev_counts))
        return header + "\n\nNo hardcoded secrets detected. [OK]"
    if json_output:
        return json.dumps(_report_json(path, scanned, findings,
                                       unique, sev_counts), indent=2)
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


@mcp.tool()
async def audit_dependencies(path: str) -> str:
    """Audit a dependency manifest against the OSV vulnerability database.

    Supports Python (requirements.txt), npm (package.json), and Go
    modules (go.mod). Only pinned/exact versions are checked.

    Args:
        path: Path to a requirements.txt, package.json, or go.mod file.

    Returns:
        A report of known vulnerabilities (OSV/CVE ids and summaries).
    """
    if not os.path.isfile(path):
        return f"Error: file not found: {path}"

    name_lower = os.path.basename(path).lower()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()

    if name_lower.endswith("package.json"):
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
            "Provide a requirements.txt, package.json, or go.mod."
        )

    if not deps:
        return (
            f"No pinned dependencies found in {path}. "
            '(Only exact versions are checked: "pkg==1.2.3" for pip, '
            '"1.2.3" for npm, or a go.mod require line.)'
        )

    deps = deps[:MAX_DEPS]

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}
    ) as client:
        results = await asyncio.gather(
            *[_osv_query(client, n, v, ecosystem) for n, v in deps]
        )

    vuln_blocks = []
    errors = 0
    vuln_pkgs = 0
    for name, version, vulns in results:
        if vulns is None:
            errors += 1
            continue
        if not vulns:
            continue
        vuln_pkgs += 1
        ids = []
        for v in vulns[:10]:
            vid = v.get("id", "?")
            aliases = ", ".join(v.get("aliases", [])[:3])
            summary = v.get("summary", "").strip()
            label = f"{vid}" + (f" ({aliases})" if aliases else "")
            ids.append(f"      - {label}" + (f": {summary}" if summary else ""))
        vuln_blocks.append(
            f"  [!] {name}=={version}  -> {len(vulns)} known vuln(s)\n" + "\n".join(ids)
        )

    header = (
        f"Dependency audit of {path}\n"
        f"Ecosystem: {ecosystem}\n"
        f"Dependencies checked: {len(deps)}\n"
        f"Vulnerable packages: {vuln_pkgs}"
    )
    if errors:
        header += f"\nLookups failed (network): {errors}"
    if not vuln_blocks:
        return header + "\n\nNo known vulnerabilities found. [OK]"
    return header + "\n\n" + "\n\n".join(vuln_blocks)


# ---------------------------------------------------------------------------
# Tool 3: Have I Been Pwned password check (k-anonymity, keyless)
# ---------------------------------------------------------------------------

HIBP_RANGE = "https://api.pwnedpasswords.com/range/"


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
    """
    if not password:
        return "Error: empty password."

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
        ) as client:
            resp = await client.get(HIBP_RANGE + prefix)
    except httpx.RequestError as exc:
        return f"Error: could not reach HIBP ({exc.__class__.__name__}: {exc})."

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
