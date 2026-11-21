package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	c, err := New("")
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

func TestOfficialImagesDoNotMatchOtherNamespaces(t *testing.T) {
	cases := []struct {
		repository, image string
		want              bool
	}{
		{"postgres", "postgres", true},
		{"library/postgres", "postgres", true},
		{"mirror/library/postgres", "postgres", true},
		{"someone/postgres", "postgres", false},
		{"notpostgres", "postgres", false},
		{"gitlab/gitlab-ee", "gitlab/gitlab-ee", true},
		{"mirror/gitlab/gitlab-ee", "gitlab/gitlab-ee", true},
		{"evil/notgitlab-ee", "gitlab/gitlab-ee", false},
	}
	for _, c := range cases {
		if got := imageMatches(c.repository, c.image); got != c.want {
			t.Errorf("imageMatches(%q, %q) = %v, want %v", c.repository, c.image, got, c.want)
		}
	}
}

func writeCatalog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOwnCatalogAddsAndReplaces(t *testing.T) {
	path := writeCatalog(t, `products:
  - name: Internal Portal
    aliases: [portal]
    repo: example-org/portal
    images: [example-org/portal]
  - name: litellm
    ecosystem: PyPI
    package: litellm
    images: [team/litellm-fork]
`)
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if product, ok := c.Resolve("portal"); !ok || product.Repo != "example-org/portal" {
		t.Errorf("the added product did not resolve: %+v, %v", product, ok)
	}
	// The file's entry replaces the built-in one whole, so its repo is gone.
	product, _, ok := c.ResolveImage("registry.example.edu/team/litellm-fork:1.2.3")
	if !ok || product.Name != "litellm" || product.Repo != "" {
		t.Errorf("the replaced product = %+v, %v", product, ok)
	}
	if _, ok := c.Resolve("GitLab"); !ok {
		t.Error("built-in products the file does not mention must remain")
	}
}

func TestOwnCatalogIsValidated(t *testing.T) {
	cases := map[string]string{
		"missing file":       "",
		"no name":            "products:\n  - repo: a/b\n",
		"bad repo":           "products:\n  - name: X\n    repo: https://github.com/a/b\n",
		"bad cpe":            "products:\n  - name: X\n    cpe: vendor\n",
		"package alone":      "products:\n  - name: X\n    package: x\n",
		"image with a tag":   "products:\n  - name: X\n    images: ['a/b:1.0']\n",
		"image with a host":  "products:\n  - name: X\n    images: ['Registry.Example.edu/a/b']\n",
		"duplicate name":     "products:\n  - name: X\n  - name: Y\n    aliases: [x]\n",
		"duplicate image":    "products:\n  - name: X\n    images: [a/b]\n  - name: Y\n    images: [a/b]\n",
		"not a catalog file": "products: 7\n",
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "absent.yaml")
		if content != "" {
			path = writeCatalog(t, content)
		}
		if _, err := New(path); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: the error should say what is wrong", name)
		}
	}
}

func TestBuiltInCatalogResolvesItsOwnImages(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Products()) < 20 {
		t.Errorf("the built-in catalog has %d products; did an entry fail to load?", len(c.Products()))
	}
	cases := map[string][2]string{ // image -> product, version
		"postgres:16.4":                                        {"PostgreSQL", "16.4"},
		"docker.io/library/redis:7.4.1-alpine":                 {"Redis", "7.4.1"},
		"registry.k8s.io/kube-apiserver:v1.31.2":               {"Kubernetes", "1.31.2"},
		"registry.k8s.io/ingress-nginx/controller:v1.11.3":     {"ingress-nginx", "1.11.3"},
		"quay.io/argoproj/argocd:v2.13.1":                      {"Argo CD", "2.13.1"},
		"quay.io/jetstack/cert-manager-controller:v1.16.2":     {"cert-manager", "1.16.2"},
		"docker.elastic.co/elasticsearch/elasticsearch:8.16.0": {"Elasticsearch", "8.16.0"},
		"ghcr.io/open-webui/open-webui:v0.5.4":                 {"Open WebUI", "0.5.4"},
		"grafana/grafana:11.3.0":                               {"Grafana", "11.3.0"},
		"nginx:1.27.2":                                         {"nginx", "1.27.2"},
	}
	for image, want := range cases {
		product, tagVersion, ok := c.ResolveImage(image)
		if !ok || product.Name != want[0] || tagVersion != want[1] {
			t.Errorf("ResolveImage(%q) = %q, %q, %v; want %q, %q", image, product.Name, tagVersion, ok, want[0], want[1])
		}
	}
	// The nginx official image must not swallow the ingress controller, nor
	// someone else's image of the same name.
	if product, _, ok := c.ResolveImage("bitnami/nginx:1.27.2"); ok {
		t.Errorf("bitnami/nginx resolved to %q; it is a different image", product.Name)
	}
}
