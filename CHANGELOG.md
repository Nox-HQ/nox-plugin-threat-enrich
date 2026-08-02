# Changelog

All notable changes to this project will be documented in this file.

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

