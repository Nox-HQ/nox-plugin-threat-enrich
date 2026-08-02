# Changelog

All notable changes to this project will be documented in this file.

## 0.3.0 - 2026-08-02

- **Breaking: the plugin enriches the scan's findings instead of manufacturing
  its own.** It used to run a regex sweep over the source tree and emit
  `ENRICH-001`–`ENRICH-004` findings. That was self-defeating: a plugin whose
  entire purpose is to *enrich findings* was re-detecting vulnerabilities in
  order to have something of its own to attach metadata to — duplicating the
  core scanner at far worse precision, and leaving core's real findings
  un-enriched, which is the one job it existed to do.

  It is now a **post-scan** tool (`requires_scan_context: true`). nox hands it
  the completed scan's findings, it reads each finding's CWE, and it attaches
  the OWASP category, MITRE ATT&CK technique and remediation guidance for that
  weakness.

  **Migration.** The tool is renamed `scan` → `enrich`, and it takes no
  `workspace_root`. It emits **enrichments keyed by finding fingerprint, never
  findings** — so installing it no longer changes how many findings a scan
  reports. Anything consuming `ENRICH-00x` findings should read the enrichment
  attached to the core finding instead: `metadata.owasp_top10`,
  `metadata.attack_technique`, `metadata.remediation`, `metadata.cwe`.

- The CWE→OWASP/ATT&CK table is keyed on CWE rather than on the plugin's own
  pattern matches, and was rewritten to cover the CWEs nox core actually emits
  — 60+ entries, up from the 10 the regex rules could produce. A CWE with no
  entry is passed over in silence: a guessed OWASP category is worse than none,
  because it routes the finding to the wrong owner and looks authoritative
  doing it.

- Fixed a mis-categorisation carried over from the old table: XSS (`CWE-79`) was
  filed under `A07:2021-Identification and Authentication Failures`. In the
  OWASP 2021 Top 10 it belongs to `A03:2021-Injection`.

### Removed

- The `scan` tool, the `ENRICH-001`–`ENRICH-004` regex rule families, the
  workspace walker, and the comment/placeholder guards they needed. The guards
  existed to stop the regex sweep firing on prose; with no sweep there is
  nothing to guard.

## 0.2.3 - 2026-08-02

- fix: stop flagging prose and documentation placeholders. The rules matched
  their patterns anywhere in a file, so comments, README prose and placeholder
  literals were reported as findings. Enrichment now requires the match to sit
  in code.
- chore(deps): nox SDK and the CI action pin both move to v1.26.0, so the
  plugin builds against the same nox that scans it.

## 0.2.2 - 2026-07-20

- chore(deps): nox SDK v1.13.0 (loopback bind + gRPC token auth), grpc 1.82.1.

## 0.2.1 - 2026-07-05

- fix(ENRICH-001): SQL-injection patterns no longer fire on safe code. The go
  pattern requires a DB method (`Query`/`Exec`/...) with concatenation instead
  of a bare `query +` (matched GraphQL/URL query builders); the py pattern
  requires a `%` format operator after a quote, not a `%s` placeholder in a
  parameterized `execute("... %s", (x,))` call.
- fix(ENRICH-002): drop `role == "admin"` (a correct authorization CHECK, not a
  weakness) and `= false` default-init variants from Broken Access Control.
- fix(ENRICH-003): require a NON-EMPTY string literal, excluding empty-string
  guards (`password == ""`, `credentials = ""`).
- fix(ENRICH-004): the py deserialization rule was INVERTED — it matched the
  SAFE `yaml.load(..., Loader=...)` form and missed the unsafe one. Now plain
  `yaml.load(`/`yaml.unsafe_load(` is flagged and the safe-Loader form
  suppressed via mitigations. Removed `JSON.parse(req.body)`: JSON is a safe
  format, not insecure deserialization.
- feat: per-rule mitigation patterns to suppress known-safe variants.
- test: add `testdata/clean/` negative fixtures (all 4 languages) and
  `TestCleanCodeNoFindings` asserting safe code produces zero findings.

## 0.2.0

- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

