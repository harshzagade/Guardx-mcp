# Changelog

All notable changes to GuardX are recorded here. Entries are based on the
actual git history — no invented features.

## [Unreleased]

### Added
- `scan_secrets`: long lines are now scanned with a sliding window instead
  of being skipped — minified bundles are chunked into overlapping
  2000-char windows (1500-char stride), so secrets buried past the old
  2000-char cutoff, including ones straddling a window boundary, are
  caught; still at most one finding per line.
- `scan_secrets`: severity-graded findings — every pattern is now marked
  HIGH (live credentials, private key blocks), MED (generic secret
  assignments), or LOW; each finding carries its `[SEV]` tag and the
  report header prints per-severity counts
  (`Findings: N (HIGH: x, MED: y, LOW: z)`).
- `tests/test_scan_secrets.py`: 7 unit tests for the severity grading
  (HIGH/MED tags, header counts, clean-report zeros, masking intact).
  Stub installation is now idempotent across test modules via a
  process-wide sentinel so `tests/` run green together; each module loads
  `server.py` under its own name to avoid clobbering `sys.modules`.
- `tests/test_pwned_password.py`: 10 unit tests for `check_pwned_password`
  (breached/clean verdicts, count formatting, prefix-only transmission,
  case-insensitive suffix match, network/HTTP error paths, `Add-Padding`
  and User-Agent headers, malformed-line tolerance). Runs with stdlib-only
  pytest via `mcp`/`httpx` stubs — no third-party installs needed.

### Fixed
- `requirements.txt`: pinned `mcp` to `>=1.2.0,<2` — the unpinned
  `mcp>=1.2.0` pulled mcp 2.x on fresh installs, whose stub
  `fastmcp.py` raises and breaks `server.py`. The pin matches the
  README's Troubleshooting guidance (verified: a fresh venv now
  resolves to mcp 1.30.0 and `server.py` imports cleanly).

### Added
- `scan_secrets`: 5 new detection patterns — Stripe Restricted Key
  (`rk_live_`), Discord Bot Token (classic `M…`/`N…` and `mfa.` forms),
  Slack Incoming Webhook URL, GitLab Personal Access Token (`glpat-`),
  and SendGrid API Key (`SG.…`).

### Docs
- README: added a **Sample output** section with real output captured from
  all three tools (`scan_secrets`, `audit_dependencies` against
  `requests==2.28.0` / `urllib3==1.26.0` via OSV.dev, and
  `check_pwned_password` against Have I Been Pwned).
- README: added a **Data sources** section documenting the CVE source
  (OSV.dev, queried live per run — no local DB to refresh) and the HIBP
  k-anonymity model.
- README: added a **Troubleshooting** section (pin `mcp<2` — the 2.x SDK
  renamed `FastMCP`; internet required for the audit and password tools).
- README: fixed the local folder name in the clone instructions
  (`cd Guardx-mcp`, matching what `git clone` actually creates).
- Added this CHANGELOG.

### Docs
- README **Data sources**: documented refresh cadence for both data sources
  (OSV ingestion freshness caveat; HIBP corpus is refreshed by HIBP as new
  breaches are added — counts reflect the corpus at query time) and the
  `Add-Padding: true` privacy detail in the k-anonymity section.

## 2026-06-22 — docs: MCP client setup

- Setup guides for five clients: Claude Code (CLI), Claude Desktop (app),
  Gemini CLI, OpenAI Codex (CLI + IDE), Cursor / VS Code.
- Clone URL documented as `harshzagade/Guardx-mcp`.

## 2026-06-22 — rebrand: GuardX (guardx-mcp)

- Project renamed to GuardX; framed as the blue-team companion to red-team
  tooling (inspects your own code, never probes live targets).

## 2026-06-22 — docs: professional README pass

- Badges (Python 3.10+, MCP-compatible, MIT, no API keys, defensive only).
- Real terminal screenshots for all three tools under `assets/`.
- Defensive-use-only disclaimer and tool reference table.

## 2026-06-22 — Initial commit

- `scan_secrets(path, max_findings=200)`: recursive scan for 9 secret
  patterns (AWS key ID / secret, GitHub and Slack tokens, Google API key,
  Stripe secret key, private key blocks, generic secret assignments, JWTs).
  Findings are masked; binaries, common ignore dirs, and files over 1 MB
  are skipped.
- `audit_dependencies(path)`: audits `requirements.txt` (PyPI) and
  `package.json` (npm) against the OSV.dev vulnerability database.
  Only pinned versions are checked.
- `check_pwned_password(password)`: checks against Have I Been Pwned via
  k-anonymity — only the first 5 characters of the SHA-1 hash are sent.
- Keyless: no API keys or accounts needed; MIT license.
