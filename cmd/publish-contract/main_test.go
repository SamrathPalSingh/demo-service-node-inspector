package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNodeInspectorContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "infra-requirements.md"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseContractMarkdown(string(data), contractDocument{})
	if err != nil {
		t.Fatal(err)
	}
	if document.ID != "node-inspector" || document.Owner != "runtime-observability-team" {
		t.Fatalf("unexpected metadata: %#v", document)
	}
	if len(document.Rules) != 1 || document.Rules[0].ID != "NODE-SEC-001" {
		t.Fatalf("unexpected rules: %#v", document.Rules)
	}
	if len(document.Rules[0].Requirements) != 2 {
		t.Fatalf("expected two security requirements, got %#v", document.Rules[0].Requirements)
	}
}
