package main

import "testing"

// Every case here is a real line from nox's precision corpus (testdata/
// precision-suite). The clean_* fixtures are curated to produce zero findings,
// so each of these was a measured false positive.
func TestIsPlaceholderSecret(t *testing.T) {
	placeholders := []string{
		`API_KEY = "your-api-key-here"`,                            // clean_placeholders.py:2
		`	exampleAPIKey   = "your-api-key-here"`,                   // clean_placeholders.go:10
		`STRIPE_SECRET_KEY = "sk_test_00000000000000000000000000"`, // clean_env_example.py:4
		`PASSWORD = "changeme"`,
		`TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxx"`,
		`JWT_SECRET = "replace-me-with-a-real-secret"`,
		`SMTP_PASSWORD = "<your-smtp-password>"`,
		`api_key = ""`,
	}
	for _, line := range placeholders {
		if !isPlaceholderSecret(line) {
			t.Errorf("placeholder not recognised: %s", line)
		}
	}

	// The guard must not swallow a credential that merely looks structured.
	//
	// Assembled at runtime rather than written as literals. They have to LOOK
	// like real credentials or the assertion is vacuous — which means a literal
	// would trip every secret scanner in the ecosystem, including nox's own
	// self-scan on this repository. The value reaching isPlaceholderSecret is
	// byte-identical either way; only the source text differs.
	credentials := []string{
		`api_key = "` + "AKIA" + "IOSFODNN7REALKEY" + `"`,
		`secret_key = "` + "8f14e45f" + "ceea167a5a36dedd4bea2543" + `"`,
		`private_key = "` + "-----BEGIN RSA " + "PRIVATE KEY-----" + `"`,
	}
	for _, line := range credentials {
		if isPlaceholderSecret(line) {
			t.Errorf("a plausible credential was suppressed: %s", line)
		}
	}
}

func TestIsCommentLine(t *testing.T) {
	// clean_prose_comments.py:2 — a dangerous call quoted as prose.
	if !isCommentLine("# and called os.system(user_cmd) directly. Both are quoted", ".py") {
		t.Error("python comment not recognised")
	}
	if !isCommentLine("  // exec.Command(userInput) would be unsafe", ".go") {
		t.Error("go comment not recognised")
	}
	// Real code must never be treated as prose.
	if isCommentLine(`os.system(user_cmd)`, ".py") {
		t.Error("executable code treated as a comment")
	}
	if isCommentLine(`x := 1 // trailing comment`, ".go") {
		t.Error("code with a trailing comment is still code")
	}
}
