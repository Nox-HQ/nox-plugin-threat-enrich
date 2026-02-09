# nox-plugin-threat-enrich

**Threat intelligence enrichment with CWE, OWASP Top 10, and MITRE ATT&CK metadata.**

## Overview

`nox-plugin-threat-enrich` is a Nox security scanner plugin that enriches security findings with threat intelligence context. It detects vulnerability patterns in source code and annotates each finding with the relevant CWE identifier, OWASP Top 10 2021 category, MITRE ATT&CK technique ID, and actionable remediation guidance -- all in a single scan pass.

Security findings without context are noise. A raw "SQL injection detected" finding tells a developer something is wrong but leaves the compliance team, the threat intelligence analyst, and the incident responder without the information they need. This plugin bridges that gap by mapping every detected pattern to the taxonomies that security teams actually use: CWE for vulnerability classification, OWASP Top 10 for web application risk categorization, and MITRE ATT&CK for adversary technique mapping.

The plugin scans Go, Python, JavaScript, and TypeScript source files across four enrichment categories. It operates in passive read-only mode, produces deterministic results, and requires no external threat intelligence feeds or API calls.

## Use Cases

### Unified Vulnerability Taxonomy for Compliance Reporting

Your security team needs to report findings using CWE identifiers for NIST compliance, OWASP categories for PCI DSS, and ATT&CK techniques for threat-informed defense. The plugin produces findings enriched with all three taxonomies simultaneously, eliminating manual cross-referencing and accelerating compliance reporting.

### Threat-Informed Development

Your development team wants to understand not just what vulnerabilities exist, but how adversaries exploit them. Each finding includes the MITRE ATT&CK technique ID (e.g., T1059 for command injection, T1110 for credential access), connecting code-level patterns to real-world attack campaigns and helping developers understand the threat landscape.

### Automated Security Metrics Dashboards

Your CISO needs a dashboard that shows vulnerability distribution by OWASP Top 10 category and CWE class. The plugin produces structured findings with consistent metadata fields that feed directly into SIEM tools, security dashboards, and GRC platforms without manual enrichment.

### Multi-Framework Risk Assessment

Your organization operates under multiple compliance frameworks that reference different vulnerability taxonomies. The plugin maps each finding to CWE, OWASP, and ATT&CK simultaneously, so a single scan satisfies the reporting requirements of NIST 800-53, OWASP ASVS, PCI DSS, and MITRE-based threat models.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-threat-enrich
   ```

2. **Create test files with enrichable patterns**

   ```bash
   mkdir -p demo-enrich && cd demo-enrich

   cat > app.py <<'EOF'
   import hashlib
   import subprocess
   from flask import Flask, request

   app = Flask(__name__)

   @app.route("/search")
   def search():
       term = request.args["q"]
       cursor = app.db.cursor()
       cursor.execute("SELECT * FROM items WHERE name = '%s'" % term)
       return cursor.fetchall()

   @app.route("/hash")
   def hash_password():
       pwd = request.form["password"]
       return hashlib.md5(pwd.encode()).hexdigest()

   @app.route("/run")
   def execute():
       cmd = request.args["cmd"]
       subprocess.call(cmd, shell=True)

   api_key = "sk-prod-a1b2c3d4e5f6g7h8i9j0"
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/threat-enrich demo-enrich/
   ```

4. **Review findings**

   ```
   nox/threat-enrich scan completed: 4 findings

   ENRICH-001 [HIGH] CWE-categorizable vulnerability: SQL Injection:
       cursor.execute("SELECT * FROM items WHERE name = '%s'" % term)
     Location: demo-enrich/app.py:11
     CWE: CWE-89
     OWASP: A03:2021-Injection
     Remediation: Use parameterized queries or prepared statements instead of string concatenation

   ENRICH-002 [MEDIUM] OWASP A02:2021 Cryptographic Failures pattern:
       return hashlib.md5(pwd.encode()).hexdigest()
     Location: demo-enrich/app.py:17
     CWE: CWE-327
     OWASP: A02:2021-Cryptographic Failures
     Remediation: Use strong, modern cryptographic algorithms (AES-256, SHA-256+); avoid MD5, SHA1, DES, RC4

   ENRICH-001 [HIGH] CWE-categorizable vulnerability: Command Injection:
       subprocess.call(cmd, shell=True)
     Location: demo-enrich/app.py:21
     CWE: CWE-78
     OWASP: A03:2021-Injection
     ATT&CK: T1059
     Remediation: Avoid shell execution with user input; use safe command APIs with argument arrays

   ENRICH-004 [LOW] Common vulnerability pattern: Hardcoded Secret:
       api_key = "sk-prod-a1b2c3d4e5f6g7h8i9j0"
     Location: demo-enrich/app.py:23
     CWE: CWE-798
     OWASP: A07:2021-Identification and Authentication Failures
     ATT&CK: T1552
     Remediation: Use environment variables or a secrets manager; never embed secrets in source code
   ```

## Rules

| Rule ID    | Description | Severity | Confidence | CWE | OWASP Top 10 | ATT&CK |
|------------|-------------|----------|------------|-----|-------------|--------|
| ENRICH-001 | CWE-categorizable vulnerability: SQL Injection | High | High | CWE-89 | A03:2021-Injection | -- |
| ENRICH-001 | CWE-categorizable vulnerability: Cross-Site Scripting | High | High | CWE-79 | A07:2021-XSS | -- |
| ENRICH-001 | CWE-categorizable vulnerability: Command Injection | High | High | CWE-78 | A03:2021-Injection | T1059 |
| ENRICH-002 | OWASP A01:2021 Broken Access Control pattern | Medium | Medium | CWE-284 | A01:2021-Broken Access Control | -- |
| ENRICH-002 | OWASP A02:2021 Cryptographic Failures pattern | Medium | Medium | CWE-327 | A02:2021-Cryptographic Failures | -- |
| ENRICH-003 | ATT&CK Credential Access technique (T1110) | Medium | High | CWE-522 | A07:2021 | T1110 |
| ENRICH-003 | ATT&CK Discovery technique: File and Directory Discovery (T1083) | Medium | High | CWE-200 | -- | T1083 |
| ENRICH-003 | ATT&CK Execution technique: Command and Scripting Interpreter (T1059) | Medium | High | CWE-78 | A03:2021-Injection | T1059 |
| ENRICH-004 | Common vulnerability: Insecure Deserialization | Low | Medium | CWE-502 | A08:2021 | -- |
| ENRICH-004 | Common vulnerability: Hardcoded Secret | Low | Medium | CWE-798 | A07:2021 | T1552 |

## Supported Languages / File Types

| Language | Extensions |
|----------|-----------|
| Go | `.go` |
| Python | `.py` |
| JavaScript | `.js` |
| TypeScript | `.ts` |

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/threat-enrich --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

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
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-threat-enrich .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, filtering for supported source file extensions (`.go`, `.py`, `.js`, `.ts`).

2. **Pattern Matching with Enrichment**: Each source file is scanned line by line. When a pattern matches, the finding is emitted with the full enrichment metadata from the rule definition:
   - `cwe` -- CWE identifier (e.g., CWE-89)
   - `owasp_top10` -- OWASP Top 10 2021 category (e.g., A03:2021-Injection)
   - `mitre_attack` -- MITRE ATT&CK technique ID (e.g., T1059)
   - `remediation` -- Actionable fix guidance

3. **Multi-Taxonomy Rules**: Each rule carries all applicable taxonomy mappings. A command injection pattern maps simultaneously to CWE-78, OWASP A03:2021-Injection, and ATT&CK T1059. This is not a separate enrichment step -- the mappings are baked into the rule definitions.

4. **Deterministic Output**: All analysis uses pre-compiled regex patterns with static enrichment metadata. No external threat intelligence feeds are queried.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-threat-enrich).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
