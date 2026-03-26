package main

import "testing"

func TestFindRegistryURL_WithDomainSuffix(t *testing.T) {
	// Ensure tests don't depend on external state.
	origSuffix := DomainSuffix
	t.Cleanup(func() { DomainSuffix = origSuffix })

	SetRegistryMap(map[string]string{
		"default": "https://registry-1.docker.io",
		"gcr":     "https://gcr.io",
	})

	DomainSuffix = "example.com"

	u, err := findRegistryURL("gcr.example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got := u.String(); got != "https://gcr.io" {
		t.Fatalf("unexpected url: %s", got)
	}

	u, err = findRegistryURL("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got := u.String(); got != "https://registry-1.docker.io" {
		t.Fatalf("unexpected default url: %s", got)
	}
}

func TestFindRegistryURL_WithoutDomainSuffix(t *testing.T) {
	origSuffix := DomainSuffix
	t.Cleanup(func() { DomainSuffix = origSuffix })

	SetRegistryMap(map[string]string{
		"default": "https://registry-1.docker.io",
	})

	DomainSuffix = ""
	if _, err := findRegistryURL("anything.example.com"); err == nil {
		t.Fatalf("expected error when DomainSuffix is empty")
	}
}
