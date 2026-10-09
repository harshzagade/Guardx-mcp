# Changelog

All notable changes to GuardX are recorded here. Entries are based on the
actual git history — no invented features.

## [Unreleased]

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
