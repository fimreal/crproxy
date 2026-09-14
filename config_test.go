//go:build !lite
// +build !lite

package main

import "testing"

func TestEffectiveListen(t *testing.T) {
	cases := []struct {
		name        string
		cfg, cli    string
		cliExplicit bool
		want        string
	}{
		{"config file wins when no flag", "127.0.0.1:5000", ":5000", false, "127.0.0.1:5000"},
		{"explicit flag wins", "127.0.0.1:5000", ":8080", true, ":8080"},
		{"explicit flag equal to default wins", "127.0.0.1:5000", ":5000", true, ":5000"},
		{"empty config falls back to flag", "", ":5000", false, ":5000"},
		{"explicit flag overrides empty config", "", "127.0.0.1:9999", true, "127.0.0.1:9999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveListen(tc.cfg, tc.cli, tc.cliExplicit); got != tc.want {
				t.Fatalf("effectiveListen(%q, %q, %v) = %q, want %q", tc.cfg, tc.cli, tc.cliExplicit, got, tc.want)
			}
		})
	}
}

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
