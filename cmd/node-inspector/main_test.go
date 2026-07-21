package main

import "testing"

func TestEnvironmentFallback(t *testing.T) {
	t.Setenv("NODE_INSPECTOR_TEST_VALUE", "")
	if got := environment("NODE_INSPECTOR_TEST_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("environment fallback = %q", got)
	}
}
