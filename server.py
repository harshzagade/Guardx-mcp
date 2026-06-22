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

import os
import re
import json
import hashlib

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("guardx")

USER_AGENT = "guardx-mcp/1.0"
HTTP_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# Tool 1: secret scanning
# ---------------------------------------------------------------------------

# name -> compiled regex. Patterns favour low false-positives.
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(
        r"(?i)aws.{0,20}?(secret|key).{0,5}['\"][0-9a-zA-Z/+]{40}['\"]"
    ),
    "GitHub Token": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Stripe Secret Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    "Private Key Block": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
    "Generic Secret Assignment": re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*"
        r"['\"][^'\"\s]{8,}['\"]"
    ),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
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


def _mask(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return secret[:2] + "****"
    return f"{secret[:4]}...{secret[-2:]} (len {len(secret)})"


@mcp.tool()
def scan_secrets(path: str, max_findings: int = 200) -> str:
    """Scan a file or directory for hardcoded secrets and credentials.

    Args:
        path: File or directory to scan.
        max_findings: Stop after this many findings (default 200).

    Returns:
        A report of likely secrets with file, line number, type, and a
        masked preview. Values are masked so the report is safe to share.
    """
    if not os.path.exists(path):
        return f"Error: path does not exist: {path}"

    files = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for n in names:
                if os.path.splitext(n)[1].lower() in SKIP_EXTS:
                    continue
                files.append(os.path.join(root, n))

    findings = []
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
            if len(line) > 2000:  # avoid pathological minified lines
                continue
            for name, pattern in SECRET_PATTERNS.items():
                m = pattern.search(line)
                if m:
                    findings.append(
                        f"  [!] {name}\n"
                        f"      {fp}:{lineno}\n"
                        f"      match: {_mask(m.group(0))}"
                    )
                    break  # one finding per line is enough
            if len(findings) >= max_findings:
                break
        if len(findings) >= max_findings:
            break

    header = f"Secret scan of {path}\nFiles scanned: {scanned}\nFindings: {len(findings)}"
    if not findings:
        return header + "\n\nNo hardcoded secrets detected. [OK]"
    note = (
        "\n\nNote: these are heuristic matches and may include false positives. "
        "Rotate any real secret that is committed to source control."
    )
    return header + "\n\n" + "\n\n".join(findings) + note


# ---------------------------------------------------------------------------
# Tool 2: dependency vulnerability audit via OSV.dev (keyless)
# ---------------------------------------------------------------------------

OSV_QUERY = "https://api.osv.dev/v1/query"
MAX_DEPS = 100


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


async def _osv_query(client: httpx.AsyncClient, name: str, version: str, ecosystem: str):
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    try:
        resp = await client.post(OSV_QUERY, json=payload)
    except httpx.RequestError:
        return name, version, None
    if resp.status_code != 200:
        return name, version, None
    vulns = resp.json().get("vulns", [])
    return name, version, vulns


@mcp.tool()
async def audit_dependencies(path: str) -> str:
    """Audit a dependency manifest against the OSV vulnerability database.

    Supports Python (requirements.txt) and npm (package.json). Only
    pinned/exact versions are checked.

    Args:
        path: Path to a requirements.txt or package.json file.

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
    elif "requirements" in name_lower or name_lower.endswith(".txt"):
        ecosystem = "PyPI"
        deps = list(_parse_requirements(text))
    else:
        return (
            f"Unsupported manifest: {name_lower}. "
            "Provide a requirements.txt or package.json."
        )

    if not deps:
        return (
            f"No pinned dependencies found in {path}. "
            "(Only exact versions like 'pkg==1.2.3' or npm \"1.2.3\" are checked.)"
        )

    deps = deps[:MAX_DEPS]

    import asyncio
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
