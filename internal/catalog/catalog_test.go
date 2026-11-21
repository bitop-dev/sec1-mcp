package catalog

import "testing"

func TestParseImage(t *testing.T) {
	cases := []struct{ reference, repository, tag string }{
		{"ghcr.io/berriai/litellm:main-v1.106.6-stable", "berriai/litellm", "main-v1.106.6-stable"},
		{"vllm/vllm-openai:v0.34.0", "vllm/vllm-openai", "v0.34.0"},
		{"registry.gitlab.com/gitlab-org/build/cng/gitlab-webservice-ee:v19.6.1", "gitlab-org/build/cng/gitlab-webservice-ee", "v19.6.1"},
		{"localhost:5000/team/app:1.2.3", "team/app", "1.2.3"},
		{"gitlab/gitlab-ee@sha256:0123abcd", "gitlab/gitlab-ee", ""},
		{"nginx", "nginx", ""},
	}
	for _, c := range cases {
		repository, tag := ParseImage(c.reference)
		if repository != c.repository || tag != c.tag {
			t.Errorf("ParseImage(%q) = %q, %q; want %q, %q", c.reference, repository, tag, c.repository, c.tag)
		}
	}
}

func TestVersionFromTag(t *testing.T) {
	cases := map[string]string{
		"main-v1.106.6-stable": "1.106.6",
		"19.6.1-ee.0":          "19.6.1",
		"v0.34.0":              "0.34.0",
		"v1.111.0-rc.1":        "1.111.0-rc.1",
		"latest":               "",
		"main-latest":          "",
		"":                     "",
	}
	for tag, want := range cases {
		if got := VersionFromTag(tag); got != want {
			t.Errorf("VersionFromTag(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestResolveByNameAliasAndImage(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LiteLLM", "lite-llm", "litellm-proxy"} {
		product, ok := c.Resolve(name)
		if !ok || product.Name != "LiteLLM" {
			t.Errorf("Resolve(%q) = %q, %v", name, product.Name, ok)
		}
	}
	if _, ok := c.Resolve("some-unknown-thing"); ok {
		t.Error("an unknown name must not resolve")
	}

	product, tagVersion, ok := c.ResolveImage("registry.example.edu/mirror/gitlab/gitlab-ee:19.6.1-ee.0")
	if !ok || product.Name != "GitLab" || tagVersion != "19.6.1" {
		t.Errorf("ResolveImage(mirrored gitlab) = %q, %q, %v", product.Name, tagVersion, ok)
	}
	// A repository that merely ends with the same letters is a different image.
	if _, _, ok := c.ResolveImage("evil/notgitlab-ee:1.0.0"); ok {
		t.Error("a look-alike image name must not resolve")
	}
}
