package main

import (
	"context"
	"net"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackAgentAssistance)
}

// The contract: enrich core's findings, do not manufacture findings to enrich.
// The old shape re-detected vulnerabilities purely so it had something of its
// own to attach metadata to, which left core's real findings un-enriched — the
// one job the plugin existed to do.
func TestEnrich_AnnotatesCoreFindingsAndEmitsNoFindings(t *testing.T) {
	resp := invokeEnrich(t, testClient(t), []*pluginv1.Finding{
		findingWithCWE("f1", "CWE-89"),
		findingWithCWE("f2", "CWE-798"),
	})

	if got := len(resp.GetFindings()); got != 0 {
		t.Errorf("enrich must not emit findings of its own, got %d", got)
	}
	if got := len(resp.GetEnrichments()); got != 2 {
		t.Fatalf("expected one enrichment per known finding, got %d", got)
	}

	byFP := map[string]*pluginv1.Enrichment{}
	for _, e := range resp.GetEnrichments() {
		if e.GetKind() != "threat-intel" {
			t.Errorf("kind should be threat-intel, got %q", e.GetKind())
		}
		byFP[e.GetFindingFingerprint()] = e
	}

	sqli, ok := byFP["f1"]
	if !ok {
		t.Fatal("no enrichment attached to the SQL-injection finding")
	}
	if got := sqli.GetMetadata()["owasp_top10"]; got != "A03:2021-Injection" {
		t.Errorf("CWE-89 should map to A03 Injection, got %q", got)
	}
	if sqli.GetMetadata()["remediation"] == "" {
		t.Error("enrichment must carry remediation guidance")
	}

	creds, ok := byFP["f2"]
	if !ok {
		t.Fatal("no enrichment attached to the hardcoded-credentials finding")
	}
	if got := creds.GetMetadata()["attack_technique"]; got != "T1552" {
		t.Errorf("CWE-798 should map to ATT&CK T1552, got %q", got)
	}
}

// A guessed OWASP category is worse than none: it routes the finding to the
// wrong owner and looks authoritative doing it.
func TestEnrich_SkipsFindingsItCannotClassify(t *testing.T) {
	resp := invokeEnrich(t, testClient(t), []*pluginv1.Finding{
		{Fingerprint: "no-cwe", RuleId: "SOME-001", Message: "something happened"},
		{Fingerprint: "unknown-cwe", RuleId: "SOME-002", Metadata: map[string]string{"cwe": "CWE-99999"}},
	})

	if got := len(resp.GetEnrichments()); got != 0 {
		t.Errorf("expected silence on unclassifiable findings, got %d: %v", got, resp.GetEnrichments())
	}
}

func TestEnrich_NoFindingsIsSuccess(t *testing.T) {
	resp := invokeEnrich(t, testClient(t), nil)
	if len(resp.GetEnrichments()) != 0 {
		t.Errorf("a clean scan should produce no enrichments, got %d", len(resp.GetEnrichments()))
	}
}

// The `cwe` metadata key is the contract, but not every analyzer sets it.
// Falling back to the rule ID and message recovers enrichment for those rather
// than silently skipping them.
func TestCweFor(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		ruleID   string
		message  string
		want     string
	}{
		{"metadata key", map[string]string{"cwe": "CWE-89"}, "R1", "msg", "CWE-89"},
		{"uppercase key", map[string]string{"CWE": "CWE-78"}, "R1", "msg", "CWE-78"},
		{"cwe_id key", map[string]string{"cwe_id": "CWE-22"}, "R1", "msg", "CWE-22"},
		{"embedded in a longer value", map[string]string{"cwe": "CWE-918 (SSRF)"}, "R1", "msg", "CWE-918"},
		{"from rule id", nil, "GO-CWE-502-DESERIALIZE", "msg", "CWE-502"},
		{"from message", nil, "R1", "possible CWE-327 weak hash", "CWE-327"},
		{"metadata wins over message", map[string]string{"cwe": "CWE-89"}, "R1", "mentions CWE-79", "CWE-89"},
		{"absent", nil, "R1", "no identifier here", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cweFor(tc.metadata, tc.ruleID, tc.message); got != tc.want {
				t.Errorf("cweFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The table is the plugin's entire value. An entry missing its remediation or
// pointing at no taxonomy at all enriches nothing, so guard the shape.
func TestCweIntelTableIsWellFormed(t *testing.T) {
	for cwe, info := range cweIntel {
		if !strings.HasPrefix(cwe, "CWE-") {
			t.Errorf("key %q is not a CWE identifier", cwe)
		}
		if info.Name == "" {
			t.Errorf("%s has no weakness name", cwe)
		}
		if info.Remediation == "" {
			t.Errorf("%s has no remediation guidance", cwe)
		}
		if info.OWASP == "" && info.OWASPASI == "" && info.ATTACK == "" {
			t.Errorf("%s maps to no taxonomy at all, so it enriches nothing", cwe)
		}
	}
}

// The table exists to cover what nox core actually emits. These are the CWEs
// behind its highest-volume rule families; a regression that drops one turns
// enrichment off for a large share of real findings without failing anything
// else.
func TestCweIntelCoversNoxCoreHighVolumeCWEs(t *testing.T) {
	for _, cwe := range []string{
		"CWE-798", "CWE-693", "CWE-78", "CWE-22", "CWE-89", "CWE-918",
		"CWE-284", "CWE-95", "CWE-79", "CWE-250", "CWE-502", "CWE-829", "CWE-77",
	} {
		if _, ok := cweIntel[cwe]; !ok {
			t.Errorf("%s is emitted by nox core but has no enrichment entry", cwe)
		}
	}
}

// --- helpers ---

func findingWithCWE(fp, cwe string) *pluginv1.Finding {
	return &pluginv1.Finding{
		Id:          fp,
		RuleId:      "CORE-001",
		Severity:    pluginv1.Severity_SEVERITY_HIGH,
		Confidence:  pluginv1.Confidence_CONFIDENCE_HIGH,
		Fingerprint: fp,
		Message:     "example finding",
		Metadata:    map[string]string{"cwe": cwe},
		Location:    &pluginv1.Location{FilePath: "internal/api/handler.go", StartLine: 42},
	}
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

// invokeEnrich calls the tool the way nox's post-scan host does: findings
// arrive in ScanContext, not in Input.
func invokeEnrich(t *testing.T, client pluginv1.PluginServiceClient, findings []*pluginv1.Finding) *pluginv1.InvokeToolResponse {
	t.Helper()
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName:    "enrich",
		ScanContext: &pluginv1.ScanContext{Findings: findings},
	})
	if err != nil {
		t.Fatalf("InvokeTool(enrich): %v", err)
	}
	return resp
}
