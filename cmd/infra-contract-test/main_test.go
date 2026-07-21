package main

import "testing"

func TestSecurityDefaultGuardRejectsMountDependentService(t *testing.T) {
	contract := serviceContract{Rules: []rule{{ID: "NODE-SEC-001", Severity: "critical", Title: "Preserve mount syscall compatibility", Remediation: "Add a tested exception."}}}
	diff := "+  seccomp_default: true\n"
	context := "command: [\"/bin/sh\", \"-c\", \"mount -t tmpfs tmpfs /mnt/check\"]"
	got := addDeterministicGuards(modelVerdict{Status: "pass", Risk: "none", Summary: "pass", Violations: []violation{}}, diff, context, contract)
	if got.Status != "fail" || len(got.Violations) != 1 || got.Violations[0].RuleID != "NODE-SEC-001" {
		t.Fatalf("unexpected verdict: %#v", got)
	}
}

func TestSecurityDefaultGuardIgnoresUnrelatedService(t *testing.T) {
	contract := serviceContract{Rules: []rule{{ID: "SEARCH-NET-001", Severity: "critical", Title: "Preserve NAT"}}}
	got := addDeterministicGuards(modelVerdict{Status: "pass", Risk: "none", Summary: "pass", Violations: []violation{}}, "+seccomp_default: true", "normal HTTP server", contract)
	if got.Status != "pass" || len(got.Violations) != 0 {
		t.Fatalf("unexpected verdict: %#v", got)
	}
}
