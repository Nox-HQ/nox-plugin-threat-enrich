package main

import (
	"regexp"
	"strings"
)

// intel is the threat-intelligence context attached to a finding: where its
// weakness sits in OWASP's taxonomy, which ATT&CK technique an attacker would
// be exercising, and what to do about it.
type intel struct {
	Name        string // human-readable weakness name
	OWASP       string // OWASP Top 10 2021 category
	OWASPASI    string // OWASP Agentic Security Initiative category, where applicable
	ATTACK      string // MITRE ATT&CK technique ID
	Remediation string
}

// cweIntel maps CWE to threat-intelligence context.
//
// Keyed on CWE rather than on the plugin's own pattern matches, because the CWE
// is what nox core already records on a finding (`metadata["cwe"]`). Deriving it
// from a regex sweep meant re-detecting vulnerabilities the scanner had already
// found, at far worse precision, purely to have something to attach metadata to.
//
// The set below covers the CWEs nox core actually emits. A CWE with no entry is
// left alone rather than guessed at: a wrong OWASP category is worse than none,
// because it routes the finding to the wrong owner.
var cweIntel = map[string]intel{
	// --- Injection (OWASP A03) ---
	"CWE-89": {"SQL Injection", "A03:2021-Injection", "", "",
		"Use parameterized queries or prepared statements; never build SQL by concatenation."},
	"CWE-78": {"OS Command Injection", "A03:2021-Injection", "", "T1059",
		"Avoid shell execution with user input; pass arguments as an array to a safe command API."},
	"CWE-77": {"Command Injection", "A03:2021-Injection", "", "T1059",
		"Never pass user input to a command interpreter; use safe APIs and allow-lists."},
	"CWE-79": {"Cross-Site Scripting", "A03:2021-Injection", "", "",
		"Encode all user-supplied output; prefer auto-escaping templates over innerHTML/document.write."},
	"CWE-94": {"Code Injection", "A03:2021-Injection", "", "T1059",
		"Do not evaluate user-supplied code; replace eval-style APIs with explicit parsing."},
	"CWE-95": {"Eval Injection", "A03:2021-Injection", "", "T1059",
		"Remove dynamic evaluation of user input; use a restricted parser or an allow-list of operations."},
	"CWE-116": {"Improper Output Encoding", "A03:2021-Injection", "", "",
		"Encode output for the sink it enters (HTML, SQL, shell, URL) rather than sanitising at input."},
	"CWE-134": {"Externally Controlled Format String", "A03:2021-Injection", "", "",
		"Never pass user input as a format string; pass it as a format argument."},
	"CWE-20": {"Improper Input Validation", "A03:2021-Injection", "", "",
		"Validate input against an allow-list at the trust boundary, and reject rather than sanitise."},
	"CWE-1427": {"Prompt Injection", "A03:2021-Injection", "ASI01", "",
		"Treat model input as untrusted; separate instructions from data and constrain tool access."},

	// --- Broken access control (OWASP A01) ---
	"CWE-284": {"Improper Access Control", "A01:2021-Broken Access Control", "", "",
		"Deny by default and check authorization on every request, server-side."},
	"CWE-269": {"Improper Privilege Management", "A01:2021-Broken Access Control", "", "T1068",
		"Grant least privilege; separate privileged operations behind an explicit check."},
	"CWE-250": {"Execution with Unnecessary Privileges", "A01:2021-Broken Access Control", "", "T1068",
		"Drop privileges before handling untrusted input; never run as root by default."},
	"CWE-22": {"Path Traversal", "A01:2021-Broken Access Control", "", "T1083",
		"Resolve paths and confirm they stay within an allowed root; reject '..' rather than stripping it."},
	"CWE-918": {"Server-Side Request Forgery", "A10:2021-Server-Side Request Forgery", "", "T1090",
		"Allow-list destination hosts; block link-local and private ranges, and re-check after redirects."},
	"CWE-601": {"Open Redirect", "A01:2021-Broken Access Control", "", "T1204",
		"Redirect only to allow-listed paths; never to a URL taken from a request parameter."},
	"CWE-732": {"Incorrect Permission Assignment", "A01:2021-Broken Access Control", "", "",
		"Set least-privilege file modes; never create secrets or sockets world-readable."},
	"CWE-306": {"Missing Authentication", "A07:2021-Identification and Authentication Failures", "", "",
		"Require authentication on every non-public route, enforced centrally rather than per handler."},
	"CWE-200": {"Information Exposure", "A01:2021-Broken Access Control", "", "T1083",
		"Return only what the caller is entitled to; do not expose internal structure in errors or listings."},
	"CWE-359": {"Exposure of Private Information", "A01:2021-Broken Access Control", "", "T1552",
		"Redact personal data from logs and responses; treat it as a separate classification."},
	"CWE-538": {"Sensitive Information in a File", "A01:2021-Broken Access Control", "", "T1552",
		"Keep sensitive files outside served directories and off the build context."},

	// --- Cryptographic failures (OWASP A02) ---
	"CWE-327": {"Broken or Risky Cryptographic Algorithm", "A02:2021-Cryptographic Failures", "", "",
		"Use modern algorithms (AES-GCM, SHA-256+); remove MD5, SHA-1, DES and RC4."},
	"CWE-326": {"Inadequate Encryption Strength", "A02:2021-Cryptographic Failures", "", "",
		"Raise key sizes to current guidance; retire parameters below the recommended minimum."},
	"CWE-311": {"Missing Encryption of Sensitive Data", "A02:2021-Cryptographic Failures", "", "T1040",
		"Encrypt sensitive data in transit and at rest; do not rely on network position."},
	"CWE-319": {"Cleartext Transmission", "A02:2021-Cryptographic Failures", "", "T1040",
		"Require TLS; disable plaintext fallbacks and verify certificates."},
	"CWE-312": {"Cleartext Storage of Sensitive Information", "A02:2021-Cryptographic Failures", "", "T1552",
		"Encrypt at rest, or do not store it — prefer a secrets manager over local storage."},
	"CWE-321": {"Hard-coded Cryptographic Key", "A02:2021-Cryptographic Failures", "", "T1552",
		"Load keys from a secrets manager; rotate any key that has been in source control."},
	"CWE-324": {"Use of a Key Past Its Expiration", "A02:2021-Cryptographic Failures", "", "",
		"Enforce key lifetimes and automate rotation."},
	"CWE-330": {"Insufficiently Random Values", "A02:2021-Cryptographic Failures", "", "",
		"Use a cryptographically secure RNG for anything security-relevant."},
	"CWE-338": {"Cryptographically Weak PRNG", "A02:2021-Cryptographic Failures", "", "",
		"Replace math/rand-style generators with crypto/rand for tokens, IDs and nonces."},
	"CWE-295": {"Improper Certificate Validation", "A07:2021-Identification and Authentication Failures", "", "T1557",
		"Verify certificates and hostnames; never set InsecureSkipVerify in production."},
	"CWE-208": {"Observable Timing Discrepancy", "A02:2021-Cryptographic Failures", "", "",
		"Compare secrets in constant time."},
	"CWE-300": {"Channel Accessible by Non-Endpoint", "A02:2021-Cryptographic Failures", "", "T1557",
		"Authenticate both ends of the channel; pin or verify the peer identity."},
	"CWE-320": {"Key Management Errors", "A02:2021-Cryptographic Failures", "", "T1552",
		"Centralise key custody, rotation and revocation rather than handling keys ad hoc."},

	// --- Authentication and credentials (OWASP A07) ---
	"CWE-798": {"Hard-coded Credentials", "A07:2021-Identification and Authentication Failures", "", "T1552",
		"Load credentials from environment or a secrets manager; rotate anything committed to source control."},
	"CWE-522": {"Insufficiently Protected Credentials", "A07:2021-Identification and Authentication Failures", "", "T1110",
		"Store credentials in a vault; never compare or log them in plaintext."},
	"CWE-287": {"Improper Authentication", "A07:2021-Identification and Authentication Failures", "", "T1078",
		"Use a vetted authentication library; fail closed on any verification error."},
	"CWE-308": {"Single-Factor Authentication", "A07:2021-Identification and Authentication Failures", "", "T1078",
		"Require a second factor for privileged access."},
	"CWE-532": {"Sensitive Information in Log File", "A09:2021-Security Logging and Monitoring Failures", "", "T1552",
		"Redact secrets and personal data before logging; review log sinks as a trust boundary."},
	"CWE-778": {"Insufficient Logging", "A09:2021-Security Logging and Monitoring Failures", "", "T1562",
		"Log authentication, authorization and privilege changes with enough context to investigate."},

	// --- Integrity and supply chain (OWASP A08) ---
	"CWE-502": {"Insecure Deserialization", "A08:2021-Software and Data Integrity Failures", "", "T1059",
		"Do not deserialize untrusted data; prefer JSON and validate before constructing objects."},
	"CWE-829": {"Inclusion of Functionality from an Untrusted Source", "A08:2021-Software and Data Integrity Failures", "", "T1195",
		"Pin dependencies and actions by digest; verify signatures before use."},
	"CWE-494": {"Download of Code Without Integrity Check", "A08:2021-Software and Data Integrity Failures", "", "T1195",
		"Verify a checksum or signature before executing anything fetched at build or run time."},
	"CWE-345": {"Insufficient Verification of Data Authenticity", "A08:2021-Software and Data Integrity Failures", "", "T1195",
		"Authenticate the source of data before trusting it; verify signatures, not just transport."},
	"CWE-346": {"Origin Validation Error", "A08:2021-Software and Data Integrity Failures", "", "",
		"Validate the origin of requests and messages against an allow-list."},
	"CWE-506": {"Embedded Malicious Code", "A08:2021-Software and Data Integrity Failures", "", "T1195",
		"Treat as a supply-chain incident: quarantine the artefact and audit its provenance."},
	"CWE-1104": {"Use of Unmaintained Third Party Components", "A06:2021-Vulnerable and Outdated Components", "", "T1195",
		"Replace or fork unmaintained dependencies; track them explicitly as risk."},
	"CWE-1035": {"Vulnerable Third Party Component", "A06:2021-Vulnerable and Outdated Components", "", "T1195",
		"Upgrade to a patched version; if none exists, isolate or remove the dependency."},
	"CWE-1336": {"Server-Side Template Injection", "A03:2021-Injection", "", "T1059",
		"Never build templates from user input; pass user data as template arguments only."},

	// --- Configuration and design (OWASP A04/A05) ---
	"CWE-693": {"Protection Mechanism Failure", "A05:2021-Security Misconfiguration", "", "T1562",
		"Restore the control that was disabled or bypassed, and add a test that fails without it."},
	"CWE-1188": {"Insecure Default Initialization", "A05:2021-Security Misconfiguration", "", "",
		"Ship secure defaults; require explicit opt-in to relax them."},
	"CWE-209": {"Information Exposure Through an Error Message", "A05:2021-Security Misconfiguration", "", "",
		"Return opaque errors to callers; keep detail in server-side logs."},
	"CWE-400": {"Uncontrolled Resource Consumption", "A04:2021-Insecure Design", "", "T1499",
		"Bound request size, concurrency and runtime; apply timeouts to every external call."},
	"CWE-770": {"Allocation Without Limits", "A04:2021-Insecure Design", "", "T1499",
		"Cap allocations driven by untrusted input; stream rather than buffering whole payloads."},
	"CWE-754": {"Improper Check for Unusual Conditions", "A04:2021-Insecure Design", "", "",
		"Handle every error path explicitly; do not treat a failed check as success."},
	"CWE-755": {"Improper Handling of Exceptional Conditions", "A04:2021-Insecure Design", "", "",
		"Fail closed on unexpected conditions rather than continuing with partial state."},
	"CWE-672": {"Operation on a Resource After Release", "A04:2021-Insecure Design", "", "",
		"Guard against use-after-close; make lifetimes explicit."},
	"CWE-362": {"Race Condition", "A04:2021-Insecure Design", "", "",
		"Serialise access to shared state; prefer atomic check-and-act over check-then-act."},
	"CWE-190": {"Integer Overflow or Wraparound", "A04:2021-Insecure Design", "", "",
		"Use checked arithmetic or a wider type where untrusted input drives the value."},
	"CWE-441": {"Unintended Proxy or Intermediary", "A04:2021-Insecure Design", "", "T1090",
		"Do not forward requests to caller-controlled destinations."},
	"CWE-840": {"Business Logic Errors", "A04:2021-Insecure Design", "", "",
		"Enforce invariants server-side; do not rely on client-side sequencing."},
	"CWE-705": {"Incorrect Control Flow Scoping", "A04:2021-Insecure Design", "", "",
		"Make control flow explicit so a security check cannot be skipped by an early return."},
	"CWE-1059": {"Insufficient Documentation", "A04:2021-Insecure Design", "", "",
		"Document the security assumptions a caller must uphold."},
	"CWE-1395": {"Dependency on Vulnerable Third-Party Component", "A06:2021-Vulnerable and Outdated Components", "", "T1195",
		"Upgrade to a patched release; track exposure with an SBOM."},

	// --- AI/agent-specific ---
	"CWE-1357": {"Reliance on Insufficiently Trustworthy Component", "A08:2021-Software and Data Integrity Failures", "ASI05", "T1195",
		"Verify model and tool provenance; constrain what an unverified component may reach."},
	"CWE-1": {"Design Weakness", "A04:2021-Insecure Design", "", "",
		"Review the design against the threat model before patching symptoms."},
}

// cwePattern matches a CWE identifier in free text, so a finding recording
// "CWE-89" inside a rule ID or message is still enrichable when the dedicated
// metadata key is absent.
var cwePattern = regexp.MustCompile(`CWE-\d+`)

// cweFor extracts the CWE a finding is about.
//
// The `cwe` metadata key is the contract and is checked first. The fallbacks
// exist because not every analyzer sets it — falling back to the rule ID and
// message recovers enrichment for those rather than silently skipping them.
func cweFor(metadata map[string]string, ruleID, message string) string {
	for _, key := range []string{"cwe", "CWE", "cwe_id"} {
		if v, ok := metadata[key]; ok {
			if m := cwePattern.FindString(strings.ToUpper(v)); m != "" {
				return m
			}
		}
	}
	for _, s := range []string{ruleID, message} {
		if m := cwePattern.FindString(strings.ToUpper(s)); m != "" {
			return m
		}
	}
	return ""
}
