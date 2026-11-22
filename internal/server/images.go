package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bitop-dev/sec1-mcp/internal/intel"
)

const (
	maxImages         = 500
	maxImageGroups    = 60
	maxListingText    = 512 << 10
	imagesShown       = 10
	unrecognisedShown = 100
)

type imagesInput struct {
	Images []string `json:"images,omitempty" jsonschema:"container image references, at most 500. Give this or text."`
	Text   string   `json:"text,omitempty" jsonschema:"raw output that lists workloads, such as kubectl get pods -A -o json, -o yaml, or a jsonpath list of images. Image references are extracted from it."`
	Since  string   `json:"since,omitempty" jsonschema:"a date as YYYY-MM-DD. Counts only advisories published, or listed as exploited, on or after it."`
}

// ImageGroup is the answer for every image that is the same product at the
// same version.
type ImageGroup struct {
	Images     []string `json:"images" jsonschema:"up to 10 of the image references in this group"`
	ImageCount int      `json:"imageCount"`
	ComponentSummary
}

type imagesOutput struct {
	ImagesFound       int            `json:"imagesFound" jsonschema:"distinct image references given or extracted"`
	ByStatus          map[string]int `json:"byStatus" jsonschema:"number of images in each status, with unrecognised images counted as unknown"`
	Results           []ImageGroup   `json:"results" jsonschema:"one entry per recognised product and version, most urgent first"`
	Unrecognised      []string       `json:"unrecognised" jsonschema:"up to 100 images the catalog does not recognise. They were NOT checked; never report them as clean."`
	UnrecognisedCount int            `json:"unrecognisedCount"`
	Guidance          string         `json:"guidance"`
	Notice            string         `json:"notice"`
}

const imagesGuidance = "Recognised images are grouped by product and version. Unrecognised images were not checked at all: report them as unchecked, and use find_identifiers or explicit identifiers to check the ones that matter. A group with status unknown and a reason about time ran out before it was checked; call again, earlier answers are cached. This covers each product's own advisories, not the packages inside the images."

var (
	jsonImageField = regexp.MustCompile(`"image"\s*:\s*"([^"\s]+)"`)
	yamlImageField = regexp.MustCompile(`(?m)^\s*(?:-\s*)?image:\s*["']?([^\s"']+)["']?\s*$`)
	anyLetter      = regexp.MustCompile(`[A-Za-z]`)
)

// extractImages pulls image references out of a workload listing. JSON and
// YAML listings name them in "image" fields, and those are used when there
// are any. Otherwise the text is taken to be a plain list, and every token
// that looks like an image reference is kept.
func extractImages(text string) []string {
	var found []string
	for _, pattern := range []*regexp.Regexp{jsonImageField, yamlImageField} {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			found = append(found, match[1])
		}
	}
	if len(found) > 0 {
		return found
	}
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == '"' || r == '\''
	}) {
		// A reference has a name with letters in it and a tag, digest or
		// path. That leaves out table cells such as "1/1" and "Running".
		if strings.Contains(token, "://") || !strings.ContainsAny(token, ":/@") || !anyLetter.MatchString(token) || strings.HasSuffix(token, ":") {
			continue
		}
		found = append(found, token)
	}
	return found
}

func (t *tools) checkImages(ctx context.Context, input imagesInput) (imagesOutput, error) {
	if len(input.Text) > maxListingText {
		return imagesOutput{}, fmt.Errorf("text is %d bytes; the limit is %d. Send the image references alone, or split the listing", len(input.Text), maxListingText)
	}
	since, err := parseSince(input.Since)
	if err != nil {
		return imagesOutput{}, err
	}
	candidates := append(append([]string{}, input.Images...), extractImages(input.Text)...)
	seen := map[string]bool{}
	var images []string
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] || !imagePattern.MatchString(candidate) {
			continue
		}
		seen[candidate] = true
		images = append(images, candidate)
	}
	switch {
	case len(images) == 0:
		return imagesOutput{}, errors.New("no image references were given or found; pass images, or text that lists them")
	case len(images) > maxImages:
		return imagesOutput{}, fmt.Errorf("%d distinct images; the limit is %d per call", len(images), maxImages)
	}

	// Images that are the same product at the same version share one check.
	type group struct {
		component intel.Component
		resolved  ResolvedComponent
		images    []string
	}
	var groups []*group
	byKey := map[string]*group{}
	output := imagesOutput{
		ImagesFound: len(images), ByStatus: map[string]int{}, Results: []ImageGroup{}, Unrecognised: []string{},
		Guidance: imagesGuidance, Notice: untrustedNotice,
	}
	for _, image := range images {
		component, resolved, err := t.resolve(ComponentInput{Image: image})
		if err != nil || resolved.ResolvedFrom != fromCatalog {
			output.UnrecognisedCount++
			output.ByStatus[intel.StatusUnknown]++
			if len(output.Unrecognised) < unrecognisedShown {
				output.Unrecognised = append(output.Unrecognised, image)
			}
			continue
		}
		key := component.Name + "\n" + component.Version
		if byKey[key] == nil {
			byKey[key] = &group{component: component, resolved: resolved}
			groups = append(groups, byKey[key])
		}
		byKey[key].images = append(byKey[key].images, image)
	}

	checked := groups[:min(len(groups), maxImageGroups)]
	components := make([]intel.Component, len(checked))
	resolved := make([]ResolvedComponent, len(checked))
	for i, g := range checked {
		components[i], resolved[i] = g.component, g.resolved
	}
	summaries := t.summarize(ctx, components, resolved, since).Results
	for i, g := range groups {
		var summary ComponentSummary
		if i < len(summaries) {
			summary = summaries[i]
		} else {
			summary = ComponentSummary{
				Component: g.resolved, Status: intel.StatusUnknown, VersionStatus: "unknown",
				Reason:        fmt.Sprintf("Not checked: this call covers %d product versions. Send the remaining images in another call. Do not treat this as safe.", maxImageGroups),
				Support:       intel.Support{Status: intel.SupportUnknown},
				TopAdvisories: []string{}, Failed: []string{},
			}
		}
		output.ByStatus[summary.Status] += len(g.images)
		output.Results = append(output.Results, ImageGroup{
			Images: g.images[:min(len(g.images), imagesShown)], ImageCount: len(g.images), ComponentSummary: summary,
		})
	}

	rank := map[string]int{intel.StatusAffected: 0, intel.StatusPossiblyAffected: 1, intel.StatusUnknown: 2, intel.StatusVersionNeeded: 3, intel.StatusNoKnown: 4}
	sort.SliceStable(output.Results, func(i, j int) bool {
		a, b := output.Results[i], output.Results[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		if a.Counts.Urgent != b.Counts.Urgent {
			return a.Counts.Urgent > b.Counts.Urgent
		}
		return a.Counts.High > b.Counts.High
	})
	return output, nil
}
