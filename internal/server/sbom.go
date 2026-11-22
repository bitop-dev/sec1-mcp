package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/bitop-dev/sec1-mcp/internal/intel"
)

const (
	maxDocumentBytes = 4 << 20
	maxPackages      = 3000
	defaultPackages  = 25
	maxPackagesShown = 100
)

type sbomInput struct {
	Document string   `json:"document,omitempty" jsonschema:"a software bill of materials or scanner report as text: CycloneDX, SPDX, Syft or Trivy output, in JSON or XML. The package URLs in it are extracted. Give this or purls."`
	PURLs    []string `json:"purls,omitempty" jsonschema:"package URLs, such as pkg:pypi/requests@2.25.0. Much smaller than a whole document: jq -r '.. | .purl? // empty' sbom.json lists them."`
	Limit    int      `json:"limit,omitempty" jsonschema:"most affected packages to return, most urgent first; default 25, at most 100"`
}

type sbomOutput struct {
	intel.PackagesResult
	Truncated bool   `json:"truncated" jsonschema:"true when packages holds fewer than affected; raise limit to see more"`
	Guidance  string `json:"guidance"`
	Notice    string `json:"notice"`
}

const sbomGuidance = "Only packages from language registries are checked: PyPI, npm, Go, Maven, Cargo, RubyGems, NuGet, Composer, Hex, pub and Swift. Operating system packages (deb, apk, rpm) are counted in notChecked and were not looked up; say so, and use an image scanner for them. Each package lists its three most urgent advisories; call get_advisory for any other."

func (t *tools) checkSBOM(ctx context.Context, input sbomInput) (sbomOutput, error) {
	if len(input.Document) > maxDocumentBytes {
		return sbomOutput{}, fmt.Errorf("document is %d bytes; the limit is %d. Send the package URLs alone as purls", len(input.Document), maxDocumentBytes)
	}
	limit := input.Limit
	switch {
	case limit < 0:
		return sbomOutput{}, errors.New("limit must not be negative")
	case limit == 0:
		limit = defaultPackages
	case limit > maxPackagesShown:
		limit = maxPackagesShown
	}
	purls := append(append([]string{}, input.PURLs...), intel.PURLPattern.FindAllString(input.Document, -1)...)
	distinct := map[string]bool{}
	var valid []string
	for _, purl := range purls {
		if pkg, ok := intel.ParsePURL(purl); ok && !distinct[pkg.PURL] {
			distinct[pkg.PURL] = true
			valid = append(valid, purl)
		}
	}
	switch {
	case len(valid) == 0:
		return sbomOutput{}, errors.New("no package URLs were given or found; pass purls, or a document that contains them (they start with pkg:)")
	case len(valid) > maxPackages:
		return sbomOutput{}, fmt.Errorf("%d distinct packages; the limit is %d per call", len(valid), maxPackages)
	}

	ctx, cancel := context.WithTimeout(ctx, batchDeadline)
	defer cancel()
	result := t.Intel.CheckPackages(ctx, valid)
	output := sbomOutput{PackagesResult: result, Guidance: sbomGuidance, Notice: untrustedNotice}
	if len(output.Packages) > limit {
		output.Packages, output.Truncated = output.Packages[:limit], true
	}
	return output, nil
}
