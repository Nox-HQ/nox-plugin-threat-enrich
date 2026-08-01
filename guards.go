package main

import (
	"regexp"
	"strings"
)

// These guards exist because a keyword regex cannot tell the difference between
// code and text about code, or between a credential and a documentation
// example. Both mistakes were measured against nox's own precision corpus,
// whose `clean_*` fixtures are curated to produce zero findings: ENRICH-001
// fired on `os.system(user_cmd)` quoted inside a `#` comment, and ENRICH-004 on
// `API_KEY = "your-api-key-here"`.

// commentPrefixes are the line-comment markers per file extension. Block
// comments are deliberately not tracked: doing it properly needs a lexer, and
// the dominant case by far is a single-line note quoting a dangerous call.
var commentPrefixes = map[string][]string{
	".go":   {"//"},
	".js":   {"//"},
	".ts":   {"//"},
	".py":   {"#"},
	".rb":   {"#"},
	".sh":   {"#"},
	".php":  {"//", "#"},
	".java": {"//"},
}

// isCommentLine reports whether the line is entirely a line comment.
//
// Only applied to the code-construct rules. A secret sitting in a comment is
// still a leaked secret, so ENRICH-004 must keep firing there — the guard is
// about "text describing a dangerous call" and nothing else.
func isCommentLine(line, ext string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	for _, p := range commentPrefixes[ext] {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// placeholderTokens are markers decisive enough that their presence anywhere in
// a value means it is documentation rather than a credential. Mirrors the
// allowlist nox core applies to its own secret rules, and the same one every
// serious secret scanner ships — without it, `.env.example` files and config
// templates are a dominant false-positive source.
var placeholderTokens = []string{
	"changeme", "change-me", "change_me",
	"replace-me", "replace_me", "replaceme",
	"your-", "your_", "yourkey",
	"placeholder", "insertyourkeyhere",
	"xxxx", "...",
	"user:password", "username:password",
	"notarealsecret", "not-a-real",
	"dummy", "sk_test_", "pk_test_",
}

// placeholderWordRE matches generic placeholder words at word boundaries only.
// They must not fire as bare substrings: the canonical AWS documentation key
// ends in "EXAMPLE" and is a required true positive elsewhere, so a substring
// test would suppress a real detection.
var placeholderWordRE = regexp.MustCompile(`(?i)\b(example|sample|test|foo|bar|redacted|todo|fixme)\b`)

// quotedValueRE extracts the first quoted string on the line — the assigned
// value, for the `name = "value"` shape these rules match.
var quotedValueRE = regexp.MustCompile(`["'` + "`" + `]([^"'` + "`" + `]*)["'` + "`" + `]`)

// isPlaceholderSecret reports whether the value assigned on this line is an
// obvious documentation placeholder rather than a live credential.
//
// A value of only repeated filler (all zeros, all x) counts too: `sk_test_0000…`
// is a Stripe test key by construction, not a leak.
func isPlaceholderSecret(line string) bool {
	m := quotedValueRE.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	value := m[1]
	if strings.TrimSpace(value) == "" {
		return true // an empty default is never a credential
	}
	lower := strings.ToLower(value)
	for _, t := range placeholderTokens {
		if strings.Contains(lower, t) {
			return true
		}
	}
	if placeholderWordRE.MatchString(value) {
		return true
	}
	return isFillerRun(value)
}

// isFillerRun reports whether the value's body is a single repeated character —
// the masked/zeroed shape of a template credential.
func isFillerRun(v string) bool {
	body := strings.TrimLeft(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-")
	if len(body) < 8 {
		return false
	}
	first := body[0]
	if first != '0' && first != 'x' && first != 'X' {
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != first {
			return false
		}
	}
	return true
}
