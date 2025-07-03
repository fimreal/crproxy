package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDockerIoLibraryCompletion(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		// docker.io single-segment image name, should complete with library/
		{"/v2/docker.io/abc/manifests/latest", "/v2/library/abc/manifests/latest"},
		// docker.io already has library/ prefix, do not complete
		{"/v2/docker.io/library/abc/manifests/latest", "/v2/library/abc/manifests/latest"},
		// docker.io multi-namespace, do not complete
		{"/v2/docker.io/user1/repo1/manifests/latest", "/v2/user1/repo1/manifests/latest"},
		{"/v2/docker.io/library/abc/def/manifests/latest", "/v2/library/abc/def/manifests/latest"},
		// other registry, do not complete
		{"/v2/gcr.io/org1/repo2/manifests/latest", "/v2/org1/repo2/manifests/latest"},
		{"/v2/quay.io/org2/repo3/manifests/v1", "/v2/org2/repo3/manifests/v1"},
		// other registry single-segment
		{"/v2/myregistry.com/xyz/manifests/latest", "/v2/xyz/manifests/latest"},
	}

	for _, tt := range tests {
		parts := strings.SplitN(strings.TrimPrefix(tt.path, "/v2/"), "/", 2)
		prefix := parts[0]
		rest := ""
		if len(parts) == 2 {
			rest = parts[1]
		}
		resourceKeywords := []string{"/manifests/", "/blobs/", "/tags/", "/uploads/", "/mount/"}
		repoName := rest
		maxIdx := -1
		for _, kw := range resourceKeywords {
			if idx := strings.LastIndex(rest, kw); idx != -1 && idx > maxIdx {
				maxIdx = idx
			}
		}
		if maxIdx != -1 {
			repoName = rest[:maxIdx]
		}
		if prefix == "docker.io" && !strings.Contains(repoName, "/") {
			rest = "library/" + rest
		}
		result := "/v2/" + rest
		assert.Equal(t, tt.expected, result, "input: %s", tt.path)
	}
}
