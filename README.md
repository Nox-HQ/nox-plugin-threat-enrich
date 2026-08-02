# nox-plugin-threat-enrich

**Attaches CWE, OWASP Top 10 and MITRE ATT&CK context to the findings a nox scan produced.**

## Overview

`nox-plugin-threat-enrich` runs *after* a nox scan. It reads each finding's CWE and attaches the threat-intelligence context for that weakness: where it sits in the OWASP Top 10, which MITRE ATT&CK technique an attacker exercising it would be using, and what to do about it.

Findings tell you what is wrong. Enrichment tells you what *kind* of wrong it is — which is what compliance mapping, risk scoring and routing all need. A `CWE-89` finding is `A03:2021-Injection` for the auditor and "use parameterized queries" for the engineer, and neither is something the detector itself should have to say.

The plugin emits **enrichments keyed by finding fingerprint, never findings of its own**. Installing it does not change how many findings a scan reports.

All mappings are static and offline — no threat-intelligence feed is queried, and the same CWE always yields the same context.

> **Changed in 0.3.0.** Earlier versions ran their own regex sweep over the source tree and emitted `ENRICH-001`–`ENRICH-004` findings. That was self-defeating: a plugin whose purpose is to *enrich findings* was re-detecting vulnerabilities in order to have something of its own to attach metadata to — duplicating the core scanner at far worse precision, and leaving core's real findings un-enriched. The `scan` tool is gone; the tool is now `enrich`. See [CHANGELOG.md](CHANGELOG.md) for the migration.

## Use Cases

### Unified vulnerability taxonomy for compliance reporting

Auditors ask for OWASP and CWE coverage, not rule IDs. Enrichment maps every finding onto both taxonomies so a report can be generated from scan output directly.

### Threat-informed development

ATT&CK technique IDs connect a code-level finding to the attacker behaviour it enables, which is the vocabulary detection and response teams already use.

### Automated security metrics dashboards

Consistent OWASP categories make trending possible across repositories and languages — "A03 findings across the estate" rather than per-scanner rule counts.

### Multi-framework risk assessment

One finding carries CWE, OWASP Top 10, OWASP Agentic Security (where applicable) and ATT&CK simultaneously, so different consumers can each read the framework they care about.

## What it attaches

One enrichment per finding whose CWE the plugin recognises:

| Field | Value |
|---|---|
| `kind` | `threat-intel` |
| `finding_fingerprint` | the fingerprint of the finding being enriched |
| `title` | `CWE-89: SQL Injection` |
| `body` | markdown: weakness, taxonomy mappings, remediation |
| `metadata.cwe` | `CWE-89` |
| `metadata.weakness` | `SQL Injection` |
| `metadata.owasp_top10` | `A03:2021-Injection` (omitted when unmapped) |
| `metadata.owasp_asi` | OWASP Agentic Security category, for AI/agent weaknesses |
| `metadata.attack_technique` | `T1059` (omitted when unmapped) |
| `metadata.remediation` | actionable fix guidance |

The CWE is read from `metadata["cwe"]`, which nox core sets. Where an analyzer does not set it, the plugin falls back to a `CWE-nnn` identifier in the rule ID or message rather than skipping the finding.

**Findings with no CWE, or with a CWE the table does not cover, are passed over in silence.** A guessed OWASP category is worse than none: it routes the finding to the wrong owner and looks authoritative doing it.

## Coverage

The table covers 60+ CWEs, chosen to cover what nox core actually emits — including its highest-volume families (`CWE-798`, `CWE-693`, `CWE-78`, `CWE-22`, `CWE-89`, `CWE-918`, `CWE-284`, `CWE-95`, `CWE-79`). A test asserts those stay covered, since a regression there would silently switch enrichment off for a large share of real findings.

## Configuration

None required. The plugin receives findings from nox's post-scan phase; it does not read the source tree and takes no scan path.

## Installation

### Via nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-threat-enrich
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-threat-enrich.git
cd nox-plugin-threat-enrich
make build
```

## Development

```bash
make build   # build the plugin binary
make test    # run tests with race detection
make lint    # run the linter
make clean   # clean build artifacts

docker build -t nox-plugin-threat-enrich .
```

## Architecture

The plugin speaks the nox Plugin SDK over stdio and declares a single tool, `enrich`, with `requires_scan_context: true`.

1. **Post-scan invocation.** nox completes its scan, then hands the plugin a `ScanContext` carrying the findings it produced. The plugin never walks the workspace.

2. **CWE resolution.** Each finding's CWE is read from `metadata["cwe"]`, falling back to a `CWE-nnn` identifier in the rule ID or message.

3. **Static taxonomy mapping.** The CWE is looked up in a static table carrying the OWASP category, ATT&CK technique and remediation guidance. No network access, no feeds, fully deterministic.

4. **Enrichment output.** Context is emitted as enrichments linked to findings by fingerprint. Nothing is added to the finding set, so the scan's finding count is independent of whether enrichment ran.

## Contributing

Contributions welcome — open an issue or a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-threat-enrich).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
