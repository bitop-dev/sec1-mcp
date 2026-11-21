// Package catalog turns what an agent sees, a product name or a container
// image reference, into the identifiers the advisory sources need. A name it
// does not know is reported as unrecognised; it never guesses.
package catalog

import (
	_ "embed"
	"fmt"
	"os"
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

// New loads the built-in catalog and, when extraPath is not empty, a team's
// own catalog file in the same format. An entry in the file replaces a
// built-in entry of the same name; any other entry is added. Both are
// validated, so a mistake in the file stops the server at start-up instead of
// producing wrong answers later.
func New(extraPath string) (*Catalog, error) {
	products, err := parse(builtinYAML, "built-in catalog")
	if err != nil {
		return nil, err
	}
	if extraPath != "" {
		data, err := os.ReadFile(extraPath)
		if err != nil {
			return nil, fmt.Errorf("catalog file: %w", err)
		}
		extra, err := parse(data, extraPath)
		if err != nil {
			return nil, err
		}
		for _, product := range extra {
			replaced := false
			for i := range products {
				if key(products[i].Name) == key(product.Name) {
					products[i], replaced = product, true
				}
			}
			if !replaced {
				products = append(products, product)
			}
		}
	}
	return &Catalog{products: products}, nil
}

// Products returns the catalog's entries.
func (c *Catalog) Products() []Product { return c.products }

var (
	ecosystemPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,39}$`)
	packagePattern   = regexp.MustCompile(`^[@A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)
	repoPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	gitlabPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}(/[A-Za-z0-9_.-]{1,100})+$`)
	cpePattern       = regexp.MustCompile(`^([aoh]:)?[A-Za-z0-9._-]{1,100}:[A-Za-z0-9._-]{1,100}$`)
	imagePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,199}$`)
)

// parse reads and validates one catalog document. source names it in errors.
func parse(data []byte, source string) ([]Product, error) {
	var file struct {
		Products []Product `yaml:"products"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	seen := map[string]string{}
	for index, product := range file.Products {
		if key(product.Name) == "" {
			return nil, fmt.Errorf("%s: product %d has no name", source, index+1)
		}
		fail := func(format string, args ...any) error {
			return fmt.Errorf("%s: product %q: %s", source, product.Name, fmt.Sprintf(format, args...))
		}
		checks := []struct {
			field, value string
			pattern      *regexp.Regexp
			example      string
		}{
			{"ecosystem", product.Ecosystem, ecosystemPattern, "PyPI"},
			{"package", product.Package, packagePattern, "litellm"},
			{"repo", product.Repo, repoPattern, "BerriAI/litellm"},
			{"gitlabRepo", product.GitLabRepo, gitlabPattern, "gitlab-org/gitlab"},
			{"cpe", product.CPE, cpePattern, "gitlab:gitlab"},
		}
		for _, check := range checks {
			if check.value != "" && !check.pattern.MatchString(check.value) {
				return nil, fail("%s %q is not valid; expected something like %q", check.field, check.value, check.example)
			}
		}
		if product.Package != "" && product.Ecosystem == "" {
			return nil, fail("package needs an ecosystem")
		}
		for _, image := range product.Images {
			if !imagePattern.MatchString(image) || strings.Contains(image, ":") {
				return nil, fail("image %q must be a lower-case repository path with no registry host or tag, such as berriai/litellm", image)
			}
		}
		// Two entries answering to the same name or image would make the
		// answer depend on their order.
		claims := append([]string{product.Name}, product.Aliases...)
		for _, claim := range claims {
			if owner, taken := seen["name:"+key(claim)]; taken && owner != product.Name {
				return nil, fail("the name %q is already used by %q", claim, owner)
			}
			seen["name:"+key(claim)] = product.Name
		}
		for _, image := range product.Images {
			if owner, taken := seen["image:"+image]; taken && owner != product.Name {
				return nil, fail("the image %q is already used by %q", image, owner)
			}
			seen["image:"+image] = product.Name
		}
	}
	return file.Products, nil
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
			if imageMatches(repository, image) {
				return candidate, tagVersion, true
			}
		}
	}
	return Product{}, tagVersion, false
}

// imageMatches reports whether an image's repository path is the catalog
// image, allowing for a mirror's path in front of it.
//
// A catalog image with a namespace, such as "gitlab/gitlab-ee", matches any
// path ending in it. One without, such as "postgres", is an official image:
// it matches only on its own or under "library/", because "someone/postgres"
// is a different image that merely shares the name.
func imageMatches(repository, image string) bool {
	if repository == image {
		return true
	}
	if !strings.Contains(image, "/") {
		image = "library/" + image
		if repository == image {
			return true
		}
	}
	return strings.HasSuffix(repository, "/"+image)
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
