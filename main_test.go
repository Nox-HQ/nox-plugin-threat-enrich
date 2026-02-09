package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackIntelligence)
}

func TestScanFindsCWEPatterns(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ENRICH-001")
	if len(found) == 0 {
		t.Fatal("expected at least one ENRICH-001 (CWE-categorizable) finding")
	}

	hasCWE := false
	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("ENRICH-001 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetConfidence() != sdk.ConfidenceHigh {
			t.Errorf("ENRICH-001 confidence should be HIGH, got %v", f.GetConfidence())
		}
		if cwe, ok := f.GetMetadata()["cwe"]; ok && cwe != "" {
			hasCWE = true
		}
		if f.GetLocation() == nil {
			t.Error("finding must include a location")
		}
	}
	if !hasCWE {
		t.Error("ENRICH-001 findings must include CWE metadata")
	}
}

func TestScanFindsOWASPPatterns(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ENRICH-002")
	if len(found) == 0 {
		t.Fatal("expected at least one ENRICH-002 (OWASP Top 10) finding")
	}

	hasOWASP := false
	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("ENRICH-002 severity should be MEDIUM, got %v", f.GetSeverity())
		}
		if owasp, ok := f.GetMetadata()["owasp_top10"]; ok && owasp != "" {
			hasOWASP = true
		}
	}
	if !hasOWASP {
		t.Error("ENRICH-002 findings must include owasp_top10 metadata")
	}
}

func TestScanFindsATTACKPatterns(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ENRICH-003")
	if len(found) == 0 {
		t.Fatal("expected at least one ENRICH-003 (ATT&CK-mappable) finding")
	}

	hasATTACK := false
	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("ENRICH-003 severity should be MEDIUM, got %v", f.GetSeverity())
		}
		if f.GetConfidence() != sdk.ConfidenceHigh {
			t.Errorf("ENRICH-003 confidence should be HIGH, got %v", f.GetConfidence())
		}
		if attack, ok := f.GetMetadata()["mitre_attack"]; ok && attack != "" {
			hasATTACK = true
		}
	}
	if !hasATTACK {
		t.Error("ENRICH-003 findings must include mitre_attack metadata")
	}
}

func TestScanFindsCommonVulnPatterns(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "ENRICH-004")
	if len(found) == 0 {
		t.Fatal("expected at least one ENRICH-004 (common vulnerability pattern) finding")
	}

	hasRemediation := false
	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityLow {
			t.Errorf("ENRICH-004 severity should be LOW, got %v", f.GetSeverity())
		}
		if f.GetConfidence() != sdk.ConfidenceMedium {
			t.Errorf("ENRICH-004 confidence should be MEDIUM, got %v", f.GetConfidence())
		}
		if rem, ok := f.GetMetadata()["remediation"]; ok && rem != "" {
			hasRemediation = true
		}
	}
	if !hasRemediation {
		t.Error("ENRICH-004 findings must include remediation metadata")
	}
}

func TestScanEnrichmentMetadataComplete(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	for _, f := range resp.GetFindings() {
		meta := f.GetMetadata()
		if _, ok := meta["language"]; !ok {
			t.Errorf("finding %s must include language metadata", f.GetRuleId())
		}
		// All findings should have at least CWE or remediation.
		hasCWE := meta["cwe"] != ""
		hasRemediation := meta["remediation"] != ""
		if !hasCWE && !hasRemediation {
			t.Errorf("finding %s should include cwe or remediation metadata", f.GetRuleId())
		}
	}
}

func TestScanMultiLanguage(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	languages := make(map[string]bool)
	for _, f := range resp.GetFindings() {
		if lang, ok := f.GetMetadata()["language"]; ok {
			languages[lang] = true
		}
	}

	for _, lang := range []string{"go", "python", "javascript", "typescript"} {
		if !languages[lang] {
			t.Errorf("expected findings for language %q", lang)
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
