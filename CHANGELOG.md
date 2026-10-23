# Changelog

All notable changes to GuardX are recorded here. Entries are based on the
actual git history — no invented features.

## [Unreleased]

### Added
- `tests/test_pattern_suite.py`: true-positive / false-positive coverage for
  the entire `scan_secrets` pattern suite — every one of the 14 patterns in
  `SECRET_PATTERNS` now has realistic true-positive lines (asserting the
  pattern fires with the right name and severity) and near-miss
  false-positive lines (asserting the whole line is clean, so each case
  also guards the other patterns against over-matching). A meta-test
  asserts the case table covers all 14 patterns, so a future pattern added
  without cases fails the suite.
- `scan_secrets`: repo-wide secret dedup — the report header now carries a
  "Unique secrets" count (distinct secret values across the whole scan),
  so a key committed in many files is reported once per location but
  counts as one unique secret. Deduplication compares raw values, not
  masked previews, and per-file findings are unchanged. The clean-scan
  header reports `Unique secrets: 0`.
- `tests/test_scan_secrets.py`: 5 unit tests (same secret in two files /
  twice in one file counts once, different secrets each count, masked
  previews are not the dedup key, clean scan reports zero).
- `scan_secrets`: `json_output` parameter — returns the report as
  machine-readable JSON instead of text (for CI pipelines): the path,
  files scanned, finding count, unique-secrets count, per-severity
  counts, and a findings array of {file, line, type, severity, match}
  with masked previews; path errors become {"error": ...} objects.
- `tests/test_scan_secrets.py`: 6 unit tests (valid JSON shape, masked
  previews never leak raw values, dedup count in JSON, clean-scan JSON,
  error-as-JSON, default output still text).
- `audit_dependencies`: OSV rate-limit backoff — HTTP 429 responses from
  OSV.dev are now retried (up to 3 retries per package) instead of being
  reported as lookup failures. A `Retry-After` response header is honored
  (delta-seconds form, clamped to 60s; the HTTP-date form falls back to
  the exponential 1s/2s/4s backoff), so a rate-limited burst no longer
  blanks the whole report.
- `tests/test_osv_backoff.py`: 10 unit tests (Retry-After honored, backoff
  fallback, 60s clamp, malformed header, give-up after max attempts,
  non-429 failure fast-path, network-error path, end-to-end audit retry).
- `audit_dependencies`: Go module support — `go.mod` manifests are now
  audited against OSV's Go ecosystem. Both block-form and single-line
  `require` directives are parsed (versions keep their `v` prefix, which
  OSV normalises); other directives (`replace`, `retract`, `exclude`,
  ...) are ignored. README feature list, tool reference, and
  contributing notes updated.
- `tests/test_go_mod.py`: 9 unit tests (block/single-line parsing,
  `// indirect` comment stripping, directive exclusion, empty files,
  `v`-prefix retention, Go-ecosystem query payloads, end-to-end vuln
  report, unsupported-manifest message).
- `scan_secrets`: honours a `.gitignore` at the scan root — basename
  patterns match at any depth, patterns with an interior/leading `/` are
  root-anchored, trailing `/` restricts to directories, `!` negates, and
  the last matching pattern wins; matched directories are pruned from the
  walk so their contents are never read. Applies to directory scans and to
  single-file scans (via the file's own directory).
- `tests/test_gitignore.py`: 13 unit tests (blank/comment lines ignored,
  basename wildcards at any depth, dir pruning, nested-dir matching,
  root-anchored vs bare trailing-slash patterns, `!` negation, last-match
  wins, `**` spanning, hard-coded dirs still applied, single-file honoring).
- `scan_secrets`: `exclude` parameter — comma-separated glob patterns for
  noisy paths (e.g. `"*.min.js,fixtures/*"`); bare patterns match any path
  segment, patterns with `/` are path-anchored, matched directories are
  pruned from the walk. Stacks on top of `.gitignore` and the built-in
  ignore dirs.
- `tests/test_gitignore.py`: 7 unit tests for `--exclude` semantics (bare
  pattern at any depth, path-anchored `fixtures/*`, comma-separated list,
  dir pruning, empty string no-op, single-file exclusion, stacking with
  `.gitignore`). Full suite: 43 green.
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
