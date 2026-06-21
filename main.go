package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// enrichRule defines a threat enrichment rule with compiled regex patterns,
// keyed by file extension, and associated threat intelligence metadata.
type enrichRule struct {
	ID          string
	Description string
	Severity    pluginv1.Severity
	ConfLevel   pluginv1.Confidence
	Patterns    map[string]*regexp.Regexp // extension -> compiled regex
	// Mitigations suppress a match on the same line when present — used to
	// encode known-safe variants RE2 cannot express via negative lookahead
	// (e.g. yaml.load with an explicit safe Loader=).
	Mitigations map[string]*regexp.Regexp
	// Enrichment metadata
	CWE         string // CWE ID for ENRICH-001
	OWASPTop10  string // OWASP Top 10 category for ENRICH-002
	ATTACKTech  string // MITRE ATT&CK technique for ENRICH-003
	Remediation string // Remediation guidance for ENRICH-004
}

// Compiled regex patterns and enrichment metadata for each rule.
var rules = []enrichRule{
	// ENRICH-001: CWE-categorizable patterns — SQL Injection (CWE-89)
	{
		ID:          "ENRICH-001",
		Description: "CWE-categorizable vulnerability: SQL Injection",
		Severity:    sdk.SeverityHigh,
		ConfLevel:   sdk.ConfidenceHigh,
		CWE:         "CWE-89",
		OWASPTop10:  "A03:2021-Injection",
		ATTACKTech:  "",
		Remediation: "Use parameterized queries or prepared statements instead of string concatenation",
		// SQL injection: string-built SQL passed to a DB call. The go pattern
		// requires a DB method (Query/Exec/...) with concatenation rather than
		// a bare `query +`, which matched any variable named "query" (GraphQL
		// strings, URL query builders). The py pattern requires the `%` format
		// operator after a quote (`"..." % x`) — not a `%s` placeholder inside
		// a parameterized `execute("... %s", (x,))` call, which is SAFE.
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(fmt\.Sprintf\(.*(?:SELECT|INSERT|UPDATE|DELETE)|(?:Query|QueryRow|QueryContext|Exec|ExecContext)\(.*\+)`),
			".py": regexp.MustCompile(`(?i)(execute\([^)]*["']\s*%|execute\(\s*f["']|execute\(.*\.format|f["'].*(?:SELECT|INSERT|UPDATE|DELETE))`),
			".js": regexp.MustCompile(`(?i)(query\(.*\+|query\(` + "`" + `.*\$\{)`),
			".ts": regexp.MustCompile(`(?i)(query\(.*\+|query\(` + "`" + `.*\$\{)`),
		},
	},
	// ENRICH-001: CWE-categorizable patterns — XSS (CWE-79)
	{
		ID:          "ENRICH-001",
		Description: "CWE-categorizable vulnerability: Cross-Site Scripting",
		Severity:    sdk.SeverityHigh,
		ConfLevel:   sdk.ConfidenceHigh,
		CWE:         "CWE-79",
		OWASPTop10:  "A07:2021-XSS",
		ATTACKTech:  "",
		Remediation: "Sanitize and encode all user-supplied output; avoid innerHTML and document.write",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(template\.HTML\()`),
			".js": regexp.MustCompile(`(?i)(\.innerHTML\s*=|document\.write\()`),
			".ts": regexp.MustCompile(`(?i)(\.innerHTML\s*=|document\.write\()`),
			".py": regexp.MustCompile(`(?i)(\|safe|mark_safe\()`),
		},
	},
	// ENRICH-001: CWE-categorizable patterns — Command Injection (CWE-78)
	{
		ID:          "ENRICH-001",
		Description: "CWE-categorizable vulnerability: Command Injection",
		Severity:    sdk.SeverityHigh,
		ConfLevel:   sdk.ConfidenceHigh,
		CWE:         "CWE-78",
		OWASPTop10:  "A03:2021-Injection",
		ATTACKTech:  "T1059",
		Remediation: "Avoid shell execution with user input; use safe command APIs with argument arrays",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(exec\.Command\(.*\+|exec\.CommandContext\(.*\+)`),
			".py": regexp.MustCompile(`(?i)(os\.system\(|subprocess\.call\(.*shell=True|subprocess\.Popen\(.*shell=True)`),
			".js": regexp.MustCompile(`(?i)(child_process\.\w+\(.*\+|child_process\.exec\()`),
			".ts": regexp.MustCompile(`(?i)(child_process\.\w+\(.*\+|child_process\.exec\()`),
		},
	},
	// ENRICH-002: OWASP Top 10 — Broken Access Control (A01)
	{
		ID:          "ENRICH-002",
		Description: "OWASP A01:2021 Broken Access Control pattern",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceMedium,
		CWE:         "CWE-284",
		OWASPTop10:  "A01:2021-Broken Access Control",
		ATTACKTech:  "",
		Remediation: "Implement proper access control checks; deny by default; validate authorization on every request",
		// Broken access control: forcing an admin flag on, or disabling auth.
		// Dropped `role == "admin"` (a correct authorization CHECK, not a
		// weakness) and the `= false` default-init variants, which were noise.
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(isAdmin\s*:?=\s*true|SkipAuth|bypassAuth|noAuth)`),
			".py": regexp.MustCompile(`(?i)(is_admin\s*=\s*True|skip_auth|bypass_auth|no_auth|@login_not_required)`),
			".js": regexp.MustCompile(`(?i)(isAdmin\s*=\s*true|skipAuth|bypassAuth|noAuth)`),
			".ts": regexp.MustCompile(`(?i)(isAdmin\s*=\s*true|skipAuth|bypassAuth|noAuth)`),
		},
	},
	// ENRICH-002: OWASP Top 10 — Cryptographic Failures (A02)
	{
		ID:          "ENRICH-002",
		Description: "OWASP A02:2021 Cryptographic Failures pattern",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceMedium,
		CWE:         "CWE-327",
		OWASPTop10:  "A02:2021-Cryptographic Failures",
		ATTACKTech:  "",
		Remediation: "Use strong, modern cryptographic algorithms (AES-256, SHA-256+); avoid MD5, SHA1, DES, RC4",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(md5\.New\(|md5\.Sum\(|sha1\.New\(|sha1\.Sum\(|des\.NewCipher|rc4\.NewCipher)`),
			".py": regexp.MustCompile(`(?i)(hashlib\.md5\(|hashlib\.sha1\(|from\s+Crypto\.Cipher\s+import\s+DES|import\s+md5\b)`),
			".js": regexp.MustCompile(`(?i)(createHash\(\s*['"]md5['"]\)|createHash\(\s*['"]sha1['"]\)|createCipher\(\s*['"]des['"]\))`),
			".ts": regexp.MustCompile(`(?i)(createHash\(\s*['"]md5['"]\)|createHash\(\s*['"]sha1['"]\)|createCipher\(\s*['"]des['"]\))`),
		},
	},
	// ENRICH-003: ATT&CK — Credential Access (T1003/T1110)
	{
		ID:          "ENRICH-003",
		Description: "ATT&CK-mappable pattern: Credential Access technique",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceHigh,
		CWE:         "CWE-522",
		OWASPTop10:  "A07:2021-Identification and Authentication Failures",
		ATTACKTech:  "T1110",
		Remediation: "Store credentials securely using vaults; never hardcode passwords or compare in plaintext",
		// Credential access: comparison against (or assignment of) a NON-EMPTY
		// string literal. Requiring a character inside the quotes excludes
		// empty-string guards (`password == ""`, `credentials = ""`), which are
		// not hardcoded-credential smells.
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(password\s*==\s*"[^"]|password\s*!=\s*"[^"]|hardcoded.?password|plaintext.?password|credentials\s*=\s*"[^"])`),
			".py": regexp.MustCompile(`(?i)(password\s*==\s*['"][^'"]|password\s*!=\s*['"][^'"]|hardcoded.?password|plaintext.?password|credentials\s*=\s*['"][^'"])`),
			".js": regexp.MustCompile(`(?i)(password\s*===?\s*['"][^'"]|password\s*!==?\s*['"][^'"]|hardcoded.?password|plaintext.?password|credentials\s*=\s*['"][^'"])`),
			".ts": regexp.MustCompile(`(?i)(password\s*===?\s*['"][^'"]|password\s*!==?\s*['"][^'"]|hardcoded.?password|plaintext.?password|credentials\s*=\s*['"][^'"])`),
		},
	},
	// ENRICH-003: ATT&CK — Discovery (T1083 File and Directory Discovery)
	{
		ID:          "ENRICH-003",
		Description: "ATT&CK-mappable pattern: Discovery technique",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceHigh,
		CWE:         "CWE-200",
		OWASPTop10:  "",
		ATTACKTech:  "T1083",
		Remediation: "Avoid exposing file system structure; restrict directory listing and path enumeration",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(filepath\.Walk\(.*user|os\.ReadDir\(.*user|ioutil\.ReadDir\(.*req)`),
			".py": regexp.MustCompile(`(?i)(os\.listdir\(.*user|os\.walk\(.*user|glob\.glob\(.*request)`),
			".js": regexp.MustCompile(`(?i)(fs\.readdirSync\(.*req|fs\.readdir\(.*req|glob\(.*req)`),
			".ts": regexp.MustCompile(`(?i)(fs\.readdirSync\(.*req|fs\.readdir\(.*req|glob\(.*req)`),
		},
	},
	// ENRICH-003: ATT&CK — Execution (T1059 Command and Scripting Interpreter)
	{
		ID:          "ENRICH-003",
		Description: "ATT&CK-mappable pattern: Execution technique",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceHigh,
		CWE:         "CWE-78",
		OWASPTop10:  "A03:2021-Injection",
		ATTACKTech:  "T1059",
		Remediation: "Never pass user input to command interpreters; use safe APIs and allow-lists",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(exec\.Command\(.*req\.|exec\.CommandContext\(.*req\.)`),
			".py": regexp.MustCompile(`(?i)(os\.system\(.*request|subprocess\.\w+\(.*request|eval\(.*request)`),
			".js": regexp.MustCompile(`(?i)(child_process\.\w+\(.*req\.|eval\(.*req\.)`),
			".ts": regexp.MustCompile(`(?i)(child_process\.\w+\(.*req\.|eval\(.*req\.)`),
		},
	},
	// ENRICH-004: Common vulnerability pattern with remediation — Insecure Deserialization
	{
		ID:          "ENRICH-004",
		Description: "Common vulnerability pattern: Insecure Deserialization",
		Severity:    sdk.SeverityLow,
		ConfLevel:   sdk.ConfidenceMedium,
		CWE:         "CWE-502",
		OWASPTop10:  "A08:2021-Software and Data Integrity Failures",
		ATTACKTech:  "",
		Remediation: "Avoid deserializing untrusted data; use safe serialization formats (JSON); validate and sanitize input before deserialization",
		// Insecure deserialization: unsafe deserializers only. The previous py
		// pattern `yaml\.load\([^)]*Loader` was INVERTED — it matched the SAFE
		// form (yaml.load with an explicit Loader=) and missed the unsafe one.
		// Now plain `yaml.load(` is flagged and the safe-Loader form suppressed
		// via Mitigations. JSON.parse was removed: JSON is a safe format (the
		// rule's own remediation recommends it), so `JSON.parse(req.body)` is
		// not insecure deserialization.
		Patterns: map[string]*regexp.Regexp{
			".py": regexp.MustCompile(`(?i)(pickle\.loads?\(|yaml\.unsafe_load\(|yaml\.load\(|marshal\.loads?\(|shelve\.open\()`),
			".js": regexp.MustCompile(`(?i)(unserialize\(|deserialize\()`),
			".ts": regexp.MustCompile(`(?i)(unserialize\(|deserialize\()`),
		},
		Mitigations: map[string]*regexp.Regexp{
			".py": regexp.MustCompile(`(?i)Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|C?BaseLoader)`),
		},
	},
	// ENRICH-004: Common vulnerability pattern with remediation — Hardcoded Secrets
	{
		ID:          "ENRICH-004",
		Description: "Common vulnerability pattern: Hardcoded Secret",
		Severity:    sdk.SeverityLow,
		ConfLevel:   sdk.ConfidenceMedium,
		CWE:         "CWE-798",
		OWASPTop10:  "A07:2021-Identification and Authentication Failures",
		ATTACKTech:  "T1552",
		Remediation: "Use environment variables or a secrets manager; never embed secrets in source code",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(apiKey\s*=\s*"|secretKey\s*=\s*"|api_key\s*=\s*"|secret_key\s*=\s*"|private_key\s*=\s*")`),
			".py": regexp.MustCompile(`(?i)(api_key\s*=\s*['"]|secret_key\s*=\s*['"]|apikey\s*=\s*['"]|private_key\s*=\s*['"])`),
			".js": regexp.MustCompile(`(?i)(apiKey\s*=\s*['"]|secretKey\s*=\s*['"]|api_key\s*=\s*['"]|private_key\s*=\s*['"])`),
			".ts": regexp.MustCompile(`(?i)(apiKey\s*=\s*['"]|secretKey\s*=\s*['"]|api_key\s*=\s*['"]|private_key\s*=\s*['"])`),
		},
	},
}

// supportedExtensions lists file extensions the enrichment scanner processes.
var supportedExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/threat-enrich", version).
		Capability("threat-enrich", "Threat intelligence enrichment with CWE, OWASP, and ATT&CK metadata").
		Tool("scan", "Scan source files and enrich findings with CWE, OWASP Top 10, and MITRE ATT&CK metadata", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFile(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

func scanFile(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil // skip unreadable files
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for i := range rules {
			rule := &rules[i]
			pattern, ok := rule.Patterns[ext]
			if !ok {
				continue
			}
			if pattern.MatchString(line) {
				// Suppress when a known-safe variant is present on the line.
				if m, ok := rule.Mitigations[ext]; ok && m.MatchString(line) {
					continue
				}
				fb := resp.Finding(
					rule.ID,
					rule.Severity,
					rule.ConfLevel,
					fmt.Sprintf("%s: %s", rule.Description, strings.TrimSpace(line)),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("language", extToLanguage(ext))

				// Add enrichment metadata.
				if rule.CWE != "" {
					fb = fb.WithMetadata("cwe", rule.CWE)
				}
				if rule.OWASPTop10 != "" {
					fb = fb.WithMetadata("owasp_top10", rule.OWASPTop10)
				}
				if rule.ATTACKTech != "" {
					fb = fb.WithMetadata("mitre_attack", rule.ATTACKTech)
				}
				if rule.Remediation != "" {
					fb = fb.WithMetadata("remediation", rule.Remediation)
				}

				fb.Done()
			}
		}
	}

	return scanner.Err()
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-threat-enrich: %v\n", err)
		return 1
	}
	return 0
}
