// Package catalog turns what an agent sees, a product name or a container
// image reference, into the identifiers the advisory sources need. A name it
// does not know is reported as unrecognised; it never guesses.
package catalog

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var builtinYAML []byte

// Product is one known piece of software.
type Product struct {
	Name       string   `yaml:"name"`
	Aliases    []string `yaml:"aliases"`
	Ecosystem  string   `yaml:"ecosystem"`
	Package    string   `yaml:"package"`
	Repo       string   `yaml:"repo"`
	GitLabRepo string   `yaml:"gitlabRepo"`
	CPE        string   `yaml:"cpe"`
	Images     []string `yaml:"images"`
}

// Catalog holds the products the server recognises.
type Catalog struct {
	products []Product
}

// New loads the built-in catalog.
func New() (*Catalog, error) {
	var file struct {
		Products []Product `yaml:"products"`
	}
	if err := yaml.Unmarshal(builtinYAML, &file); err != nil {
		return nil, fmt.Errorf("built-in catalog: %w", err)
	}
	return &Catalog{products: file.Products}, nil
}

// Resolve finds a product by name, alias or package name.
func (c *Catalog) Resolve(name string) (Product, bool) {
	wanted := key(name)
	if wanted == "" {
		return Product{}, false
	}
	for _, product := range c.products {
		if key(product.Name) == wanted || (product.Package != "" && key(product.Package) == wanted) {
			return product, true
		}
		for _, alias := range product.Aliases {
			if key(alias) == wanted {
				return product, true
			}
		}
	}
	return Product{}, false
}

// ResolveImage finds the product a container image belongs to and reads the
// version from its tag. tagVersion is "" when the tag carries none, as with
// "latest" or a bare digest; it is returned even when the image is unknown.
func (c *Catalog) ResolveImage(reference string) (product Product, tagVersion string, ok bool) {
	repository, tag := ParseImage(reference)
	tagVersion = VersionFromTag(tag)
	for _, candidate := range c.products {
		for _, image := range candidate.Images {
			image = strings.ToLower(image)
			if repository == image || strings.HasSuffix(repository, "/"+image) {
				return candidate, tagVersion, true
			}
		}
	}
	return Product{}, tagVersion, false
}

// ParseImage splits an image reference into its repository path, lower-cased
// and without the registry host, and its tag. A digest is discarded: it
// identifies the image but says nothing about the version.
func ParseImage(reference string) (repository, tag string) {
	reference = strings.TrimSpace(reference)
	if at := strings.Index(reference, "@"); at >= 0 {
		reference = reference[:at]
	}
	if colon := strings.LastIndex(reference, ":"); colon > strings.LastIndex(reference, "/") {
		reference, tag = reference[:colon], reference[colon+1:]
	}
	// The first path segment is a registry host when it looks like one.
	if slash := strings.Index(reference, "/"); slash >= 0 {
		first := reference[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			reference = reference[slash+1:]
		}
	}
	return strings.ToLower(reference), tag
}

var tagVersion = regexp.MustCompile(`\d+(?:\.\d+)+(?:[-.]?(?:rc|alpha|beta|dev|nightly)(?:[-.]?\d+)?)?`)

// VersionFromTag extracts a version from an image tag such as
// "main-v1.106.6-stable" or "19.6.1-ee.0". It returns "" when the tag holds
// no dotted version.
func VersionFromTag(tag string) string {
	return tagVersion.FindString(strings.ToLower(tag))
}

// key reduces a name to its letters and digits, so that "LiteLLM",
// "lite-llm" and "litellm" compare equal.
func key(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
