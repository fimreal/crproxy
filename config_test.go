//go:build !lite
// +build !lite

package main

import "testing"

func TestEffectiveRegistryMap_DefaultOverride(t *testing.T) {
	in := map[string]string{
		"default": "https://registry-1.docker.io",
		"gcr":     "https://gcr.io",
	}

	out := effectiveRegistryMap(in, "https://registry.k8s.io")

	// override applied
	if got := out["default"]; got != "https://registry.k8s.io" {
		t.Fatalf("default override not applied, got %q", got)
	}
	// other keys preserved
	if got := out["gcr"]; got != "https://gcr.io" {
		t.Fatalf("key gcr changed unexpectedly, got %q", got)
	}
	// returned map should be a copy (mutating out must not affect in)
	out["gcr"] = "https://example.com"
	if in["gcr"] != "https://gcr.io" {
		t.Fatalf("input map mutated via output map")
	}
}
