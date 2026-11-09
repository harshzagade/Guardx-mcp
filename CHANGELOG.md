# Changelog

All notable changes to GuardX are recorded here. Entries are based on the
actual git history — no invented features.

## [Unreleased]

### Added
- `audit_dependencies`: CycloneDX SBOM input — a JSON file with
  `bomFormat: CycloneDX`, or named `sbom.json`, `cyclonedx.json`,
  `bom.json`, or `*.cdx.json`, is audited from its `components`:
  each component is identified by its package URL (`pkg:maven/...`,
  `pkg:npm/...`, `pkg:pypi/...`, `pkg:golang/...`, `pkg:cargo/...`),
  so one SBOM can mix ecosystems and each component is queried
  against its own (one querybatch call per ecosystem; the header
  lists them all as `Ecosystems:`). Components without a purl, with
  an unsupported purl type, or without a version are skipped rather
  than guessed at, and the SBOM's own root component
  (`metadata.component`) is not audited. All inputs now normalise to
  (name, version, ecosystem) triples, so the multi-ecosystem path
  shares the single-ecosystem query/report code.
- `tests/test_cyclonedx_sbom.py`: 13 unit tests (mixed-ecosystem
  parsing, scoped npm names, Go `v` prefix, purl qualifiers/subpath,
  root-component exclusion, bad-purl rejection, SBOM detection by
  `bomFormat` and by filename, per-ecosystem querybatch calls, vuln
  reporting with fixed-version guidance, empty-SBOM message,
  non-SBOM JSON and malformed JSON rejection).
- `audit_dependencies`: Maven support — a `pom.xml` is parsed for its
  `<dependencies>` (groupId:artifactId:version, the OSV Maven package
  name) and queried against the Maven ecosystem. Versions written as
  `${property}` references are resolved from the POM's `<properties>`
  block when possible; unresolvable references, unversioned entries,
  and `<dependencyManagement>` declarations are skipped rather than
  queried with a placeholder, and malformed XML yields no dependencies.
- `tests/test_maven_pom.py`: 11 unit tests (namespaced and
  namespace-free POMs, property resolution, dependencyManagement /
  unversioned / unresolvable skipping, malformed XML, Maven-ecosystem
  querybatch payload, vuln reporting, empty-POM message, unsupported
  manifest message naming `pom.xml`).
- `audit_dependencies`: fixed-version guidance — each reported
  vulnerability now reads "upgrade to >= X" (the lowest version that
  closes every OSV `affected` range for the queried version) or "no
  fixed version released" when an affected range has no fix yet
  (`last_affected` with no `fixed` event, or a reintroduced range).
  Ranges are walked event by event (`introduced` opens the window,
  `fixed` closes it, `last_affected`/`limit` bound it; a range with
  no `introduced` event counts as affected from the start), and
  entries for other ecosystems or without `ranges` are skipped, so
  the guidance never names a fix for a version the query already
  passed. A small best-effort version comparator (numeric runs sort
  numerically, a trailing pre-release tag sorts below the bare
  release) decides whether the queried version sits below a fix.
- `tests/test_fixed_versions.py`: 17 unit tests (version comparison:
  numeric runs, `v` prefix, pre-release, prefix ordering;
  fixed-version extraction: single/multiple/mixed ranges,
  already-fixed, before-introduced, fixed-gap, reintroduced,
  `last_affected`-only, no-`affected`, no-`ranges`, other-ecosystem;
  report lines for guided, unfixed, and range-less findings).
- `scan_secrets`: git-history scan (`history=True`) — streams
  `git log -p` for the path and scans added lines, so a secret
  committed and later removed is still found (it stays in history
  until the history is rewritten). Each finding names its commit
  short-SHA; the header reports commits scanned, capped at the 500
  most recent (the header says so when the cap cuts the log); JSON
  output carries a `history` object plus a `commit` per finding.
  The diff stream is parsed line by line (commit/file/hunk
  boundaries, new-file line numbers from hunk headers), so a huge
  history never lands in memory whole; removed lines are never
  scanned, binary extensions are skipped, and IaC block context is
  tracked per commit. `.gitignore` is deliberately not applied in
  history mode — a committed-then-ignored file is exactly what it is
  for — while `exclude` patterns and the baseline still apply, and
  `history` rejects `since=`.
- `tests/test_history_scan.py`: 10 unit tests (secret removed from
  HEAD still found with the right commit, attribution across
  commits, clean repo, non-repo error, `history`+`since` conflict,
  JSON shape, 500-commit truncation, `exclude`, single-file path,
  secrets across files and commits).
- `scan_secrets`: IaC credential scan — in Terraform (`.tf`,
  `.tfvars`), CloudFormation, and ARM files, a hardcoded credential
  assignment inside a sensitive resource block (`aws_db_instance` /
  `aws_rds_*` / `azurerm_sql_*` / `AWS::RDS::DBInstance` /
  `Microsoft.Sql/servers`, and similar database/SQL types) is a HIGH
  "IaC Credential" finding. Terraform blocks are tracked by brace
  depth so the context ends when the block closes; CloudFormation/ARM
  context lasts until the next `Type:` declaration; `.tfvars` files
  are treated as deployment values throughout. The same assignment
  outside a sensitive block is left to the generic/config heuristics,
  and placeholder values, `${var...}` interpolations, and
  `var.`/`local.` references stay clean.
- `tests/test_iac_credentials.py`: 12 unit tests (Terraform sensitive
  vs non-sensitive blocks, block-close context end, reference and
  placeholder skipping, Azure key forms, non-credential keys, tfvars
  without a block, code-file exclusion, CloudFormation RDS vs S3,
  ARM SQL server, JSON masking).
- `audit_dependencies`: OSV querybatch — all distinct dependencies are
  now queried in a single `POST /v1/querybatch` call instead of one
  query per package, with results aligned to queries by position
  (entries without a `vulns` key mean no known vulnerabilities). The
  batch keeps the single-query 429 retry behaviour (honouring
  `Retry-After`, else exponential backoff, clamped); a non-429 failure,
  network error, or truncated response counts every affected dep as a
  lookup failure instead of claiming it clean. `_osv_query` is kept
  for single-package callers. Existing OSV test fakes were updated to
  the batch contract (one batch post per audit, queries inspected
  instead of per-package payloads).
- `tests/test_osv_querybatch.py`: 6 unit tests (single batch call and
  payload shape, position alignment incl. vuln-less entries, 429
  retry with `Retry-After`, non-429 and network failures counted as
  lookup failures, truncated-results tail counted as a failure).
- `check_pwned_passwords`: batch breached-password check — one call
  audits a list of passwords with the same k-anonymity model as the
  single check (only SHA-1 hash prefixes sent, matching done
  locally). Passwords sharing a hash prefix are looked up once, so a
  batch costs one range request per distinct prefix; each password
  gets one numbered summary line (passwords never appear in the
  output) and the header carries breached/clean/error counts, while a
  per-prefix network or HTTP failure is reported on that prefix's
  lines instead of failing the whole batch. The single check now
  shares the same `_hibp_suffix_counts` lookup helper, with no change
  to its output or retry behaviour.
- `tests/test_batch_passwords.py`: 6 unit tests (empty list, one line
  per password in input order, shared-prefix queried once, empty
  entry without a request, per-prefix failure isolation, non-200
  status per line).
- `audit_this_codebase_prompt`: MCP prompt template chaining
  `scan_secrets` + `audit_dependencies` into a one-shot audit with a
  remediation summary (secrets to rotate first, HIGH before MED/LOW,
  then dependencies to upgrade, then suspected false positives). It
  registers via `mcp.prompt()` when the SDK supports prompts and
  otherwise stays a plain importable function returning the same
  text, so it is testable without a running server; the template
  forbids pasting real secrets and requires tool failures to be
  reported instead of claimed clean.
- `tests/test_audit_prompt.py`: 5 unit tests (tool chaining order,
  defaults, secrets-before-dependencies ordering, masked-preview and
  read-only rules, failure-reporting rule).
- `audit_dependencies`: `min_severity` filter — an optional severity
  floor (`LOW`, `MEDIUM`/`MED`, `HIGH`, `CRITICAL`, any case) hides
  vulnerabilities below the floor from the report and counts them in
  the header, so noisy dependency trees can be triaged by severity.
  Each reported vulnerability is tagged with its CVSS band and score
  (e.g. `[HIGH 7.5]`, from the highest score when a vuln carries
  several); unscored vulnerabilities are tagged `[UNKNOWN]` and are
  hidden by any filter, since they cannot be shown to meet the floor.
  A package whose vulnerabilities are all filtered out is not counted
  as vulnerable, and an unknown filter value is an error naming the
  valid values.
- `tests/test_min_severity.py`: 8 unit tests (CVSS band boundaries,
  highest-score selection, filter hiding + hidden count, fully
  filtered package reporting clean, no-filter behaviour keeping
  unscored vulnerabilities, `MED` alias + case-insensitivity, invalid
  value error).
- `audit_dependencies`: per-run OSV response cache — the same
  package@version is queried only once per run, even when several
  manifest entries reference it (a repeated pin, or the same package
  in both `dependencies` and `devDependencies`). Duplicate entries are
  dropped in first-seen order before querying, so the report lists
  each package once; `Dependencies checked` counts distinct packages
  and the header gains an `OSV cache hits` line when duplicates were
  served from the cache. The cache lives for one run only — OSV data
  changes, so nothing is persisted across runs.
- `tests/test_osv_cache.py`: 5 unit tests (dedupe order + hit count,
  no-duplicate behaviour, duplicate pin queried once and reported
  once, same name with different versions still queried separately,
  no cache line without duplicates).
- `audit_dependencies`: lockfile support — `package-lock.json` (npm),
  `poetry.lock` (PyPI), and `Cargo.lock` (crates.io) now resolve
  transitive dependencies instead of direct manifests only, so a
  vulnerability in a dependency-of-a-dependency is caught. The npm
  parser handles the v2/v3 `packages` map (scoped and nested
  `node_modules` paths, root entry skipped, exact duplicates
  deduped) and the legacy v1 `dependencies` tree; the TOML parser
  reads `[[package]]` name/version lines without a TOML library
  (stdlib `tomllib` only exists from Python 3.11, GuardX supports
  3.10), ignoring sources, checksums, dependency lists, and
  `[package.dependencies]` sub-tables. The unsupported-manifest
  error now lists the lockfile names.
- `tests/test_lockfiles.py`: 12 unit tests (packages-map parsing,
  scoped/nested names, root/versionless skipping, dedupe, v1 tree,
  bad-JSON tolerance, poetry/Cargo TOML parsing, npm/PyPI/crates.io
  audit wiring, empty-lock message, unsupported-manifest message).
- `scan_secrets`: incremental scan mode via `since=` — a git ref
  (e.g. `HEAD~1`, a branch, a commit SHA) scans only files changed
  since that ref in the scan path's repository (staged/unstaged edits
  plus untracked files), and a date/timestamp (ISO date/datetime or
  epoch seconds) scans only files modified after that time, so CI runs
  on large repos stay fast. Unchanged files are not counted as
  scanned; the report header notes the incremental selector and JSON
  output carries it as `since`. A value that is neither a resolvable
  ref nor a parseable date is an error.
- `tests/test_incremental_scan.py`: 8 unit tests (modified-file-only
  scan since HEAD, clean-tree no-op, untracked new file included,
  JSON `since` field, timestamp mode, date fallback inside a git
  repo, invalid-`since` error in text and JSON, timestamp parser
  variants).
- `scan_secrets`: `.guardx-baseline` allowlist — a baseline file at the
  scan root (or an explicit `baseline=` path) suppresses acknowledged
  findings by SHA-256 hash (relative path + finding type + secret
  value; line numbers excluded so suppression survives edits, and the
  raw secret never lands in the baseline file). Suppressed findings
  are counted in the report header and as `suppressed_count` in JSON
  output, so CI runs stay green on reviewed false positives while new
  findings still surface. A missing explicit baseline path is an
  error; a missing auto-discovered file means no suppression. The
  baseline file itself is never scanned.
- `tests/test_baseline.py`: 9 unit tests (suppression + count, unlisted
  findings still reported, line-shift stability, JSON
  `suppressed_count`, explicit path + missing-path error, comment /
  blank / malformed line tolerance, no-baseline behaviour, single-file
  scans, baseline file excluded from the scan).
- `scan_secrets`: config-file credential heuristic — in `.env`, `.ini`,
  YAML, JSON, TOML, and `.properties` files, a credential-named key
  (last `-`/`_` split token `password`/`secret`/`token`/…) with a
  non-placeholder value is a MED "Config Credential" finding, catching
  unquoted values and `:` assignments the generic pattern misses.
  Runs only after the known patterns miss, only in config files, and
  skips placeholders (`changeme`, `${VAR}` references, masked values)
  and non-credential names (`password_length`, `secret_santa`).
- `tests/test_config_credentials.py`: 9 unit tests (.env / YAML / JSON /
  INI positives, code-file exclusion, placeholder and reference
  skipping, non-credential names clean, known-pattern precedence,
  JSON masking).
- `scan_secrets`: entropy-based LOW findings — lines no known pattern
  matches are checked for long high-entropy quoted strings (at least
  20 characters, Shannon entropy at least 4.0 bits/char), reported as
  "High-Entropy String" findings for custom token formats. Kept
  separate from `_match_line` so the pattern suite's false-positive
  cases stay valid; a known pattern always wins and the
  one-finding-per-line rule is preserved. Plain English and pure hex
  hashes stay below the threshold by design.
- `tests/test_entropy.py`: 9 unit tests (custom token is LOW and
  masked, helper/pattern separation, known-pattern precedence,
  low-entropy / hex-hash / short / repeated strings stay clean, one
  finding per line, JSON finding masked).
- `scan_secrets`: per-file finding counts in the report header — when
  findings exist, the header lists each affected file with its count
  ("Per-file findings"), most-affected file first, so triage starts
  where the findings cluster; the same map is exposed as
  `per_file_counts` in `json_output` mode. Clean scans carry no
  per-file block.
- `tests/test_scan_secrets.py`: 5 unit tests (header lists per-file
  counts, most-affected file first, clean scan has no block, JSON
  `per_file_counts` agrees with the text header, single-file scan).
- `tests/test_pattern_suite.py`: true-positive / false-positive coverage for
  the entire `scan_secrets` pattern suite — every one of the 14 patterns in
  `SECRET_PATTERNS` now has realistic true-positive lines (asserting the
  pattern fires with the right name and severity) and near-miss
  false-positive lines (asserting the whole line is clean, so each case
  also guards the other patterns against over-matching). A meta-test
  asserts the case table covers all 14 patterns, so a future pattern added
  without cases fails the suite.
- `check_pwned_password`: retry transient network failures — an
  `httpx.RequestError` now retries twice (initial attempt + 2 retries) with
  full-jitter backoff (`random.uniform(0, 1)` then `random.uniform(0, 2)`
  seconds) before reporting the error. HTTP error statuses are not
  retried. Docstring documents the retry behavior.
- `tests/test_pwned_password.py`: 3 new unit tests (flaky-then-success,
  give-up after two retries, jittered growing backoff); the network-failure
  test now also asserts the 3-attempt count and zeroes the backoff so the
  suite stays fast.
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
