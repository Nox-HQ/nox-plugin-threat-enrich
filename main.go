// Command nox-plugin-threat-enrich attaches threat-intelligence context to the
// findings a nox scan already produced.
//
// It used to run its own regex sweep over the source tree and emit
// ENRICH-001..004 findings of its own. That was self-defeating: a plugin whose
// entire purpose is to *enrich findings* was re-detecting vulnerabilities in
// order to have something of its own to attach metadata to — duplicating the
// core scanner at far worse precision, and leaving core's real findings
// un-enriched, which is the one job it existed to do.
//
// The plugin now runs post-scan. nox hands it the findings, it reads each
// finding's CWE, and it attaches the OWASP category, MITRE ATT&CK technique and
// remediation guidance for that weakness. Output is enrichments keyed by finding
// fingerprint, never findings.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/threat-enrich", version).
		Capability("threat-enrich", "Attaches CWE, OWASP Top 10 and MITRE ATT&CK context to findings").
		ToolWithContext("enrich", "Attach OWASP, MITRE ATT&CK and remediation context to each finding from the completed scan", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("enrich", handleEnrich)
}

// handleEnrich attaches threat-intelligence context to every finding whose CWE
// this plugin knows about.
//
// Findings with no CWE, or with a CWE that has no entry, are passed over in
// silence. A guessed OWASP category is worse than none: it routes the finding to
// the wrong owner and looks authoritative doing it.
func handleEnrich(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	for _, f := range req.Findings() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		cwe := cweFor(f.GetMetadata(), f.GetRuleId(), f.GetMessage())
		if cwe == "" {
			continue
		}
		info, ok := cweIntel[cwe]
		if !ok {
			continue
		}

		eb := resp.Enrichment(f.GetFingerprint(), "threat-intel", fmt.Sprintf("%s: %s", cwe, info.Name)).
			Body(intelBody(cwe, info)).
			WithMetadata("cwe", cwe).
			WithMetadata("weakness", info.Name).
			WithMetadata("remediation", info.Remediation).
			// The scanner's own confidence in the finding carries over: this
			// plugin is confident about the CWE-to-OWASP mapping, but that says
			// nothing about whether the underlying finding is real.
			WithConfidence(f.GetConfidence()).
			Source("nox/threat-enrich")

		if info.OWASP != "" {
			eb = eb.WithMetadata("owasp_top10", info.OWASP)
		}
		if info.OWASPASI != "" {
			eb = eb.WithMetadata("owasp_asi", info.OWASPASI)
		}
		if info.ATTACK != "" {
			eb = eb.WithMetadata("attack_technique", info.ATTACK)
		}
		eb.Done()
	}

	return resp.Build(), nil
}

func intelBody(cwe string, info intel) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**%s — %s**\n\n", cwe, info.Name)
	if info.OWASP != "" {
		fmt.Fprintf(&sb, "- OWASP Top 10 (2021): %s\n", info.OWASP)
	}
	if info.OWASPASI != "" {
		fmt.Fprintf(&sb, "- OWASP Agentic Security: %s\n", info.OWASPASI)
	}
	if info.ATTACK != "" {
		fmt.Fprintf(&sb, "- MITRE ATT&CK: %s\n", info.ATTACK)
	}
	fmt.Fprintf(&sb, "\n**Remediation.** %s\n", info.Remediation)
	return sb.String()
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
