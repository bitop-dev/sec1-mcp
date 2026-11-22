package intel

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Package is one entry of a software bill of materials, identified by its
// package URL (purl).
type Package struct {
	// PURL is the package URL without qualifiers or subpath.
	PURL    string
	Type    string
	Name    string
	Version string
}

// checkedTypes are the purl types OSV matches reliably by exact version.
//
// Operating system packages (deb, apk, rpm) are deliberately absent. OSV
// does hold advisories for them, but lookups by purl gave different answers
// for the same package depending on how the distribution was written, and
// none at all for Alpine. A result built on that would look more certain
// than it is, so those packages are reported as not checked.
var checkedTypes = map[string]bool{
	"pypi": true, "npm": true, "golang": true, "maven": true, "cargo": true, "gem": true,
	"nuget": true, "composer": true, "hex": true, "pub": true, "swift": true,
}

var (
	purlType = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)
	// PURLPattern finds package URLs in any text: JSON, XML or plain.
	PURLPattern = regexp.MustCompile(`pkg:[a-z][a-z0-9.+-]*/[^\s"'<>,;]+`)
)

// ParsePURL reads a package URL. ok is false when the text is not one.
func ParsePURL(text string) (Package, bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(text), "pkg:")
	if !found {
		return Package{}, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	rest = strings.TrimRight(rest, "/.)]}")
	version := ""
	if at := strings.LastIndex(rest, "@"); at > strings.LastIndex(rest, "/") {
		rest, version = rest[:at], rest[at+1:]
	}
	segments := strings.Split(rest, "/")
	if len(segments) < 2 || !purlType.MatchString(segments[0]) {
		return Package{}, false
	}
	kind := segments[0]
	var parts []string
	for _, segment := range segments[1:] {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "" {
			return Package{}, false
		}
		parts = append(parts, decoded)
	}
	if decodedVersion, err := url.PathUnescape(version); err == nil {
		version = decodedVersion
	}
	// OSV names a Maven package group:artifact; everything else joins the
	// namespace and name with a slash.
	separator := "/"
	if kind == "maven" {
		separator = ":"
	}
	canonical := "pkg:" + rest
	if version != "" {
		canonical += "@" + version
	}
	return Package{PURL: canonical, Type: kind, Name: strings.Join(parts, separator), Version: version}, true
}

// PackageResult is what was found for one package.
type PackageResult struct {
	PURL            string     `json:"purl"`
	Name            string     `json:"name"`
	Version         string     `json:"version"`
	Type            string     `json:"type" jsonschema:"the purl type, such as pypi, npm or golang"`
	Counts          Counts     `json:"counts"`
	TotalAdvisories int        `json:"totalAdvisories"`
	Advisories      []Advisory `json:"advisories" jsonschema:"the most urgent advisories for this package, at most 3; use get_advisory for the rest"`
}

// PackagesResult is the answer for a list of packages.
type PackagesResult struct {
	Status string `json:"status" jsonschema:"affected: at least one package has advisories. no_known_advisories: every package was checked and none has any. unknown: some or all packages could not be checked; never treat this as safe."`
	Reason string `json:"reason"`
	// PackagesFound counts distinct package URLs.
	PackagesFound int `json:"packagesFound"`
	Checked       int `json:"checked" jsonschema:"packages looked up by exact version"`
	Affected      int `json:"affected" jsonschema:"checked packages with at least one advisory"`
	// NotChecked says how many packages could not be checked, by purl type.
	NotChecked      map[string]int  `json:"notChecked" jsonschema:"packages that were NOT checked, by purl type: operating system packages (deb, apk, rpm) and types the advisory database does not cover"`
	NotCheckedCount int             `json:"notCheckedCount"`
	NoVersion       int             `json:"noVersion" jsonschema:"packages with no version in their package URL, which cannot be checked"`
	Counts          Counts          `json:"counts" jsonschema:"advisories across all affected packages"`
	Unranked        int             `json:"unranked" jsonschema:"advisories whose details could not be fetched, or belong to packages beyond the 300 that are detailed in one call; they are counted as normal priority but may be worse"`
	Packages        []PackageResult `json:"packages" jsonschema:"affected packages, most urgent first"`
	Coverage        []Coverage      `json:"coverage"`
}

const (
	osvBatchSize        = 500
	maxDetailedPackages = 300
	detailConcurrency   = 8
	advisoriesPerEntry  = 3
)

// CheckPackages looks every package up in OSV by exact version, then ranks
// what it finds the same way single lookups are ranked.
func (c *Client) CheckPackages(ctx context.Context, purls []string) PackagesResult {
	result := PackagesResult{NotChecked: map[string]int{}, Packages: []PackageResult{}, Coverage: []Coverage{}}

	seen := map[string]bool{}
	var checkable []Package
	for _, text := range purls {
		pkg, ok := ParsePURL(text)
		if !ok || seen[pkg.PURL] {
			continue
		}
		seen[pkg.PURL] = true
		result.PackagesFound++
		switch {
		case !checkedTypes[pkg.Type]:
			result.NotChecked[pkg.Type]++
			result.NotCheckedCount++
		case pkg.Version == "":
			result.NoVersion++
		default:
			checkable = append(checkable, pkg)
		}
	}

	// 1. Which advisories apply to each package. The batch call returns ids only.
	idsOf := make([][]string, len(checkable))
	incomplete := 0
	for start := 0; start < len(checkable); start += osvBatchSize {
		group := checkable[start:min(start+osvBatchSize, len(checkable))]
		queries := make([]map[string]any, len(group))
		for i, pkg := range group {
			queries[i] = map[string]any{"package": map[string]string{"purl": pkg.PURL}}
		}
		var response struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if _, err := c.fetch(ctx, request{method: "POST", url: c.Endpoints.OSV + "/v1/querybatch", body: map[string]any{"queries": queries}, ttl: ttlOSV}, &response); err != nil {
			result.Coverage = append(result.Coverage, Coverage{"osv", "failed", describe(err)})
			result.Status = StatusUnknown
			result.Reason = "The packages could not be checked: the advisory database could not be reached. Do not treat this as safe."
			return result
		}
		if len(response.Results) != len(group) {
			result.Coverage = append(result.Coverage, Coverage{"osv", "failed", "the advisory database answered for a different number of packages than were asked about"})
			result.Status = StatusUnknown
			result.Reason = "The packages could not be checked reliably. Do not treat this as safe."
			return result
		}
		for i, entry := range response.Results {
			for _, vuln := range entry.Vulns {
				idsOf[start+i] = append(idsOf[start+i], vuln.ID)
			}
			if entry.NextPageToken != "" {
				incomplete++
			}
		}
	}
	result.Checked = len(checkable)
	detail := fmt.Sprintf("%d packages checked", len(checkable))
	if incomplete > 0 {
		detail += fmt.Sprintf("; %d have more advisories than one page holds, so their lists are partial", incomplete)
	}
	result.Coverage = append(result.Coverage, Coverage{"osv", "checked", detail})

	// 2. Full records for each affected package, so that records describing
	// the same flaw can be merged and everything can be ranked. One request
	// per affected package returns all of its advisories. The number of
	// packages detailed is capped; beyond it, advisories are counted unranked.
	var affected []int
	for i, ids := range idsOf {
		if len(ids) > 0 {
			affected = append(affected, i)
		}
	}
	records := c.osvRecords(ctx, checkable, affected[:min(len(affected), maxDetailedPackages)])

	// 3. Per package: merge the records that describe the same flaw.
	var all []*Advisory
	type entry struct {
		pkg    Package
		merged *merger
	}
	var entries []entry
	for _, i := range affected {
		pkg := checkable[i]
		merged := &merger{byID: map[string]*Advisory{}}
		if vulns, detailed := records[i]; detailed {
			for _, vuln := range vulns {
				merged.add(Advisory{
					ID: vuln.ID, Aliases: vuln.Aliases, Title: vuln.title(), Severity: normalizeSeverity(vuln.DatabaseSpecific.Severity),
					FixedIn: vuln.fixedFor(pkg.Name), Published: vuln.Published, Sources: []string{"osv"},
					URL: "https://osv.dev/vulnerability/" + url.PathEscape(vuln.ID),
				})
			}
		} else {
			for _, id := range idsOf[i] {
				result.Unranked++
				merged.add(Advisory{ID: id, Title: id, Severity: "unknown", Sources: []string{"osv"},
					URL: "https://osv.dev/vulnerability/" + url.PathEscape(id), Note: "Details were not fetched; use get_advisory."})
			}
		}
		entries = append(entries, entry{pkg, merged})
		all = append(all, merged.list...)
	}

	// 4. Exploited, likely to be exploited, public exploit tools; then rank.
	result.Coverage = append(result.Coverage, c.enrich(ctx, all)...)

	for _, e := range entries {
		advisories := make([]Advisory, len(e.merged.list))
		for i, advisory := range e.merged.list {
			advisories[i] = *advisory
		}
		sortAdvisories(advisories)
		counts := Count(advisories)
		result.Counts.Urgent += counts.Urgent
		result.Counts.High += counts.High
		result.Counts.Normal += counts.Normal
		result.Counts.Exploited += counts.Exploited
		result.Counts.PublicExploit += counts.PublicExploit
		result.Packages = append(result.Packages, PackageResult{
			PURL: e.pkg.PURL, Name: e.pkg.Name, Version: e.pkg.Version, Type: e.pkg.Type, Counts: counts,
			TotalAdvisories: len(advisories), Advisories: advisories[:min(len(advisories), advisoriesPerEntry)],
		})
	}
	result.Affected = len(result.Packages)
	sort.SliceStable(result.Packages, func(i, j int) bool {
		a, b := result.Packages[i].Counts, result.Packages[j].Counts
		if a.Exploited != b.Exploited {
			return a.Exploited > b.Exploited
		}
		if a.Urgent != b.Urgent {
			return a.Urgent > b.Urgent
		}
		if a.High != b.High {
			return a.High > b.High
		}
		return a.Normal > b.Normal
	})

	unchecked := result.NotCheckedCount + result.NoVersion
	gap := ""
	if unchecked > 0 {
		gap = fmt.Sprintf(" %d of the %d packages were not checked", unchecked, result.PackagesFound)
		if result.NotCheckedCount > 0 {
			gap += " (" + describeTypes(result.NotChecked) + ")"
		}
		gap += "; use an image scanner for operating system packages."
	}
	switch {
	case result.Affected > 0:
		result.Status = StatusAffected
		result.Reason = fmt.Sprintf("%d of %d checked packages have known advisories.%s", result.Affected, result.Checked, gap)
	case result.PackagesFound == 0:
		result.Status = StatusUnknown
		result.Reason = "No package URLs were found, so nothing was checked."
	case unchecked > 0:
		result.Status = StatusUnknown
		result.Reason = fmt.Sprintf("The %d packages that could be checked have no known advisories, but the rest could not be checked.%s Do not treat this as safe.", result.Checked, gap)
	default:
		result.Status = StatusNoKnown
		result.Reason = fmt.Sprintf("All %d packages were checked by exact version and none has a known advisory.", result.Checked)
	}
	return result
}

func describeTypes(counts map[string]int) string {
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		if counts[kinds[i]] != counts[kinds[j]] {
			return counts[kinds[i]] > counts[kinds[j]]
		}
		return kinds[i] < kinds[j]
	})
	parts := make([]string, len(kinds))
	for i, kind := range kinds {
		parts[i] = fmt.Sprintf("%d %s", counts[kind], kind)
	}
	return strings.Join(parts, ", ")
}

// osvRecords fetches the full advisory records for the packages at the given
// indexes, a few at a time. A package whose records cannot be fetched is
// left out of the result; the caller then counts its advisories as unranked.
func (c *Client) osvRecords(ctx context.Context, packages []Package, indexes []int) map[int][]osvVuln {
	records := make(map[int][]osvVuln, len(indexes))
	var mu sync.Mutex
	var wait sync.WaitGroup
	slots := make(chan struct{}, detailConcurrency)
	for _, index := range indexes {
		wait.Add(1)
		go func() {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			query := map[string]any{"package": map[string]string{"purl": packages[index].PURL}}
			var vulns []osvVuln
			for page := 0; page < maxPages; page++ {
				var response struct {
					Vulns         []osvVuln `json:"vulns"`
					NextPageToken string    `json:"next_page_token"`
				}
				if _, err := c.fetch(ctx, request{method: "POST", url: c.Endpoints.OSV + "/v1/query", body: query, ttl: ttlOSV}, &response); err != nil {
					return
				}
				vulns = append(vulns, response.Vulns...)
				if response.NextPageToken == "" {
					break
				}
				query["page_token"] = response.NextPageToken
			}
			mu.Lock()
			records[index] = vulns
			mu.Unlock()
		}()
	}
	wait.Wait()
	return records
}

// enrich marks which advisories are exploited in the wild, scores them, flags
// public exploit tools and sets each one's priority.
func (c *Client) enrich(ctx context.Context, advisories []*Advisory) []Coverage {
	merged := &merger{list: advisories, byID: map[string]*Advisory{}}
	for _, advisory := range advisories {
		for _, id := range append([]string{advisory.ID}, advisory.Aliases...) {
			merged.byID[id] = advisory
		}
	}
	var coverage []Coverage
	if index, err := c.kev(ctx); err != nil {
		coverage = append(coverage, Coverage{"cisa-kev", "failed", describe(err)})
	} else {
		for _, advisory := range advisories {
			for _, id := range append([]string{advisory.ID}, advisory.Aliases...) {
				if entry, ok := index.byCVE[id]; ok {
					advisory.Exploited, advisory.ExploitedSince = true, entry.DateAdded
				}
			}
		}
		coverage = append(coverage, Coverage{"cisa-kev", "checked", ""})
	}
	coverage = append(coverage, c.applyEPSS(ctx, merged), c.applyExploits(ctx, merged))
	for _, advisory := range advisories {
		triage(advisory)
	}
	return coverage
}
