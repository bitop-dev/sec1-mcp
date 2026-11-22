package intel

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bitop-dev/sec1-mcp/internal/version"
)

const (
	titleLimit     = 200
	maxPages       = 10
	recentWindow   = 120 * 24 * time.Hour
	noVersionNote  = "No version given; compare the fixed versions with what is running."
	epssPerRequest = 100
)

// ---- OSV: registry packages, matched by exact version.

type osvVuln struct {
	ID               string   `json:"id"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Aliases          []string `json:"aliases"`
	Published        string   `json:"published"`
	Modified         string   `json:"modified"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func (v osvVuln) title() string {
	if v.Summary != "" {
		return clean(v.Summary, titleLimit)
	}
	if first := strings.SplitN(strings.TrimSpace(v.Details), "\n", 2)[0]; first != "" {
		return clean(first, titleLimit)
	}
	return v.ID
}

func (v osvVuln) fixedFor(packageName string) []string {
	var fixed []string
	for _, affected := range v.Affected {
		if packageName != "" && !strings.EqualFold(affected.Package.Name, packageName) {
			continue
		}
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				// A Go pseudo-version names a commit, not a release anyone
				// can upgrade to.
				if !goPseudoVersion.MatchString(event.Fixed) {
					fixed = appendUnique(fixed, event.Fixed)
				}
			}
		}
	}
	return fixed
}

var goPseudoVersion = regexp.MustCompile(`\d{14}-[0-9a-f]{12}$`)

var goMajorSuffix = regexp.MustCompile(`/v(\d+)$`)

// packages returns the package names to ask OSV about for this version.
//
// A Go module changes its path with each major version from 2 onward
// (".../v2", ".../v3"), and a product may be published under several. Asking
// about a module of a different major version returns advisories that were
// never fixed in that abandoned module, which do not apply. So for Go, with a
// version given, only the module for that major version is asked: the path
// ending in /vN when there is one, otherwise the paths with no suffix.
func (component Component) packages() []string {
	all := appendUnique([]string{component.packageName()}, component.OtherPackages...)
	major := ""
	if match := regexp.MustCompile(`^[vV]?(\d+)`).FindStringSubmatch(component.Version); match != nil {
		major = match[1]
	}
	if !strings.EqualFold(component.Ecosystem, "Go") || major == "" {
		return all
	}
	var forMajor, unsuffixed []string
	for _, name := range all {
		switch suffix := goMajorSuffix.FindStringSubmatch(name); {
		case suffix == nil:
			unsuffixed = append(unsuffixed, name)
		case suffix[1] == major:
			forMajor = append(forMajor, name)
		}
	}
	if len(forMajor) > 0 {
		return forMajor
	}
	return unsuffixed
}

func (c *Client) osvAdvisories(ctx context.Context, component Component) ([]Advisory, error) {
	var advisories []Advisory
	seen := map[string]bool{}
	for _, packageName := range component.packages() {
		found, err := c.osvPackage(ctx, component, packageName)
		if err != nil {
			return nil, err
		}
		for _, advisory := range found {
			if !seen[advisory.ID] {
				seen[advisory.ID] = true
				advisories = append(advisories, advisory)
			}
		}
	}
	return advisories, nil
}

func (c *Client) osvPackage(ctx context.Context, component Component, packageName string) ([]Advisory, error) {
	query := map[string]any{
		"package": map[string]string{"name": packageName, "ecosystem": component.Ecosystem},
	}
	if component.Version != "" {
		query["version"] = component.Version
	}
	var advisories []Advisory
	for page := 0; page < maxPages; page++ {
		var response struct {
			Vulns         []osvVuln `json:"vulns"`
			NextPageToken string    `json:"next_page_token"`
		}
		if _, err := c.fetch(ctx, request{method: "POST", url: c.Endpoints.OSV + "/v1/query", body: query, ttl: ttlOSV}, &response); err != nil {
			return nil, err
		}
		for _, vuln := range response.Vulns {
			advisory := Advisory{
				ID:         vuln.ID,
				Aliases:    vuln.Aliases,
				Title:      vuln.title(),
				Severity:   normalizeSeverity(vuln.DatabaseSpecific.Severity),
				FixedIn:    vuln.fixedFor(packageName),
				Published:  vuln.Published,
				URL:        "https://osv.dev/vulnerability/" + url.PathEscape(vuln.ID),
				Sources:    []string{"osv"},
				Workaround: workaround(vuln.Details),
			}
			// OSV's MAL- records mark releases that contained malware. That is
			// worse than any vulnerability and carries no severity of its own.
			if strings.HasPrefix(vuln.ID, "MAL-") {
				advisory.Severity = "critical"
				advisory.Note = "This release is reported to contain malicious code."
			}
			if component.Version == "" {
				advisory.Note = strings.TrimSpace(advisory.Note + " " + noVersionNote)
			}
			advisories = append(advisories, advisory)
		}
		if response.NextPageToken == "" {
			return advisories, nil
		}
		query["page_token"] = response.NextPageToken
	}
	return nil, fmt.Errorf("osv: more than %d pages of advisories; refusing to report a partial list", maxPages)
}

// osvKnownIDs returns every identifier OSV holds for the package, at any
// version. One that OSV knows and did not return for the running version
// does not affect that version.
func (c *Client) osvKnownIDs(ctx context.Context, component Component) (map[string]bool, error) {
	versionless := component
	versionless.Version = ""
	advisories, err := c.osvAdvisories(ctx, versionless)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, advisory := range advisories {
		known[advisory.ID] = true
		for _, alias := range advisory.Aliases {
			known[alias] = true
		}
	}
	return known, nil
}

// ---- GitHub: the upstream repository's own security advisories.

type githubAdvisory struct {
	GHSAID          string  `json:"ghsa_id"`
	CVEID           *string `json:"cve_id"`
	Summary         string  `json:"summary"`
	Description     *string `json:"description"`
	Severity        *string `json:"severity"`
	HTMLURL         string  `json:"html_url"`
	PublishedAt     *string `json:"published_at"`
	Vulnerabilities []struct {
		Range   *string `json:"vulnerable_version_range"`
		Patched *string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

// sourceResult is what one version-aware source found.
type sourceResult struct {
	advisories []Advisory
	// cleared holds identifiers of advisories the source knows about and has
	// determined do not affect the version. A name-only match for one of
	// them is a false alarm.
	cleared map[string]bool
	// detail is added to the source's coverage entry.
	detail string
}

func (c *Client) githubAdvisories(ctx context.Context, component Component) (sourceResult, error) {
	next := fmt.Sprintf("%s/repos/%s/security-advisories?state=published&per_page=100", c.Endpoints.GitHub, component.Repo)
	result := sourceResult{cleared: map[string]bool{}}
	assumedFixed := 0
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return result, fmt.Errorf("github: more than %d pages of advisories; refusing to report a partial list", maxPages)
		}
		var batch []githubAdvisory
		var err error
		if next, err = c.fetch(ctx, request{url: next, headers: c.githubHeaders(), ttl: ttlGitHub}, &batch); err != nil {
			return result, err
		}
		for _, item := range batch {
			advisory, verdict := githubApplies(component.Version, item)
			switch verdict {
			case verdictApplies:
				result.advisories = append(result.advisories, advisory)
				continue
			case verdictAssumedFixed:
				assumedFixed++
			}
			result.cleared[item.GHSAID] = true
			if item.CVEID != nil {
				result.cleared[*item.CVEID] = true
			}
		}
	}
	if assumedFixed > 0 {
		result.detail = fmt.Sprintf("%d advisories treated as fixed: the version is newer than every fix they publish", assumedFixed)
	}
	return result, nil
}

// How a repository advisory relates to the running version.
const (
	// verdictApplies: listed. Either it affects the version, or that could
	// not be ruled out.
	verdictApplies = iota
	// verdictNotAffected: the published ranges exclude the version, or a fix
	// is published on its release line at or below it.
	verdictNotAffected
	// verdictAssumedFixed: no range excludes the version, but it is newer
	// than every fix the advisory publishes. This assumes fixes are carried
	// forward into later releases, so it is counted and reported.
	verdictAssumedFixed
)

// githubApplies turns a repository advisory into an Advisory and decides
// whether it applies to the running version.
//
// Project advisories are free text, and many give only where a flaw starts
// (">= 9.2.0") beside the version that fixes it. Read literally, that range
// covers every later release for ever. So the decision uses the published
// fixes as well as the ranges, in this order:
//
//  1. A fix published on the version's release line: the version is fixed
//     if it is at or above the highest such fix.
//  2. A range bounded on both sides that contains the version: it applies,
//     unless rule 1 found a fix and the range does not start after it. A
//     range that starts after the fix says the flaw came back.
//  3. No fix on its line, and the version is newer than every published
//     fix: assumed fixed.
//  4. Otherwise an open-ended range that contains the version applies.
//  5. If no range contains it and all could be read, it does not apply. If
//     some range could not be read, it is listed with a note.
func githubApplies(running string, item githubAdvisory) (Advisory, int) {
	advisory := Advisory{
		ID:       item.GHSAID,
		Title:    clean(item.Summary, titleLimit),
		Severity: "unknown",
		URL:      item.HTMLURL,
		Sources:  []string{"github"},
	}
	if item.CVEID != nil {
		advisory.Aliases = []string{*item.CVEID}
	}
	if item.Severity != nil {
		advisory.Severity = normalizeSeverity(*item.Severity)
	}
	if item.PublishedAt != nil {
		advisory.Published = *item.PublishedAt
	}
	if item.Description != nil {
		advisory.Workaround = workaround(*item.Description)
	}

	var fixes []string
	var clauses []version.Clause
	unreadable := len(item.Vulnerabilities) == 0
	for _, entry := range item.Vulnerabilities {
		if entry.Patched != nil {
			fixes = appendUnique(fixes, version.List(*entry.Patched)...)
		}
		if entry.Range == nil {
			unreadable = true
			continue
		}
		parsed, ok := version.ParseRange(*entry.Range)
		if !ok {
			unreadable = true
			continue
		}
		clauses = append(clauses, parsed...)
	}
	advisory.FixedIn = fixes

	if running == "" {
		advisory.Note = noVersionNote
		return advisory, verdictApplies
	}
	if !version.Valid(running) {
		advisory.Note = "The version could not be compared with the affected range; check it by hand."
		return advisory, verdictApplies
	}

	lineFix, highestFix := "", ""
	for _, fix := range fixes {
		if highestFix == "" || isAbove(fix, highestFix) {
			highestFix = fix
		}
		if version.SameLine(running, fix) && (lineFix == "" || isAbove(fix, lineFix)) {
			lineFix = fix
		}
	}
	fixedOnLine := lineFix != "" && !isAbove(lineFix, running)

	inOpenRange := false
	for _, clause := range clauses {
		if in, _ := clause.Contains(running); !in {
			continue
		}
		if !clause.Bounded() {
			inOpenRange = true
			continue
		}
		// A bounded range often spans several release lines, each with its
		// own backported fix, so a fix on this line still counts. It does
		// not when the range starts after that fix: that says the flaw came
		// back.
		startsAfterFix := fixedOnLine && clause.LowerBound() != "" && isAbove(clause.LowerBound(), lineFix)
		if !fixedOnLine || startsAfterFix {
			return advisory, verdictApplies
		}
	}

	switch {
	case fixedOnLine:
		return advisory, verdictNotAffected
	case lineFix == "" && highestFix != "" && isAbove(running, highestFix):
		return advisory, verdictAssumedFixed
	case inOpenRange:
		if len(fixes) == 0 {
			advisory.Note = "The advisory gives where the flaw starts but no fixed version, so it may be long fixed; check it by hand."
		}
		return advisory, verdictApplies
	case unreadable:
		advisory.Note = "The affected range could not be read; check it by hand."
		return advisory, verdictApplies
	}
	return advisory, verdictNotAffected
}

// isAbove reports whether a is a higher version than b. Both are known to
// parse.
func isAbove(a, b string) bool {
	comparison, ok := version.Compare(a, b)
	return ok && comparison > 0
}

// ---- NVD: products with no registry package, matched through their CPE.

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		Type         string `json:"type"`
		BaseSeverity string `json:"baseSeverity"`
		CVSSData     struct {
			BaseSeverity string  `json:"baseSeverity"`
			BaseScore    float64 `json:"baseScore"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

var nvdMetricOrder = []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}

func (cve nvdCVE) description() string {
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

func (cve nvdCVE) severity() (severity, vector string, score float64) {
	for _, key := range nvdMetricOrder {
		metrics := cve.Metrics[key]
		if len(metrics) == 0 {
			continue
		}
		metric := metrics[0]
		for _, candidate := range metrics {
			if candidate.Type == "Primary" {
				metric = candidate
				break
			}
		}
		text := metric.CVSSData.BaseSeverity
		if text == "" {
			text = metric.BaseSeverity
		}
		if normalized := normalizeSeverity(text); normalized != "unknown" {
			return normalized, metric.CVSSData.VectorString, metric.CVSSData.BaseScore
		}
	}
	return "unknown", "", 0
}

// cpeBase turns vendor:product into the CPE 2.3 prefix NVD matches on. A
// leading "o:" or "h:" selects operating systems and hardware; the default
// is an application.
func cpeBase(cpe string) string {
	if strings.HasPrefix(cpe, "a:") || strings.HasPrefix(cpe, "o:") || strings.HasPrefix(cpe, "h:") {
		return "cpe:2.3:" + cpe
	}
	return "cpe:2.3:a:" + cpe
}

func (c *Client) nvdQuery(ctx context.Context, parameters url.Values) ([]nvdCVE, error) {
	var cves []nvdCVE
	headers := map[string]string{}
	if c.NVDKey != "" {
		headers["apiKey"] = c.NVDKey
	}
	for start := 0; ; {
		parameters.Set("startIndex", fmt.Sprint(start))
		var page struct {
			TotalResults    int `json:"totalResults"`
			ResultsPerPage  int `json:"resultsPerPage"`
			Vulnerabilities []struct {
				CVE nvdCVE `json:"cve"`
			} `json:"vulnerabilities"`
		}
		// NVD spells its flag parameters without "=", which url.Values cannot
		// express, so "hasKev=" is rewritten after encoding.
		query := strings.ReplaceAll(parameters.Encode(), "hasKev=", "hasKev")
		if _, err := c.fetch(ctx, request{url: c.Endpoints.NVD + "?" + query, headers: headers, ttl: ttlNVD, paced: true}, &page); err != nil {
			return nil, err
		}
		for _, entry := range page.Vulnerabilities {
			if entry.CVE.VulnStatus != "Rejected" {
				cves = append(cves, entry.CVE)
			}
		}
		start += page.ResultsPerPage
		if page.ResultsPerPage == 0 || start >= page.TotalResults {
			return cves, nil
		}
	}
}

// cpeSafeVersion matches versions that can be written into a CPE name as
// they are.
var cpeSafeVersion = regexp.MustCompile(`^[vV]?[A-Za-z0-9._-]+$`)

// vulnerableIn reports whether the CVE marks the product itself as
// vulnerable. NVD also lists a product as the platform some other vulnerable
// software runs on; those CVEs are not about the product. A CVE with no
// applicability data for the product is kept.
func (cve nvdCVE) vulnerableIn(prefix string) bool {
	listed := false
	for _, configuration := range cve.Configurations {
		for _, node := range configuration.Nodes {
			for _, match := range node.CPEMatch {
				if !strings.HasPrefix(match.Criteria, prefix) {
					continue
				}
				if match.Vulnerable {
					return true
				}
				listed = true
			}
		}
	}
	return !listed
}

// cpes returns every NVD name the component is filed under.
func (component Component) cpes() []string {
	return appendUnique([]string{component.CPE}, component.OtherCPEs...)
}

func (c *Client) nvdAdvisories(ctx context.Context, component Component) ([]Advisory, error) {
	var advisories []Advisory
	seen := map[string]bool{}
	for _, cpe := range component.cpes() {
		base := cpeBase(cpe)
		parameters := url.Values{}
		switch {
		case component.Version == "":
			// A product's full history can run to thousands of CVEs.
			now := time.Now().UTC()
			parameters.Set("virtualMatchString", base)
			parameters.Set("pubStartDate", now.Add(-recentWindow).Format("2006-01-02T15:04:05.000Z"))
			parameters.Set("pubEndDate", now.Format("2006-01-02T15:04:05.000Z"))
		case cpeSafeVersion.MatchString(component.Version):
			// cpeName finds everything virtualMatchString does, and also CVEs
			// recorded against every version of a product with no range.
			parameters.Set("cpeName", base+":"+strings.TrimLeft(component.Version, "vV")+":*:*:*:*:*:*:*")
		default:
			parameters.Set("virtualMatchString", base+":"+component.Version)
		}
		cves, err := c.nvdQuery(ctx, parameters)
		if err != nil {
			return nil, err
		}
		for _, cve := range cves {
			if seen[cve.ID] || !cve.vulnerableIn(base+":") {
				continue
			}
			seen[cve.ID] = true
			severity, _, _ := cve.severity()
			advisory := Advisory{
				ID:        cve.ID,
				Title:     clean(cve.description(), titleLimit),
				Severity:  severity,
				FixedIn:   nvdFixed(component.Version, cve, base+":"),
				Published: cve.Published,
				URL:       "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(cve.ID),
				Sources:   []string{"nvd"},
			}
			if advisory.Title == "" {
				advisory.Title = cve.ID
			}
			if component.Version == "" {
				advisory.Note = "No version given; only CVEs from the last 120 days are listed. " + noVersionNote
			}
			advisories = append(advisories, advisory)
		}
	}
	return advisories, nil
}

// nvdExploitedWithVersionData returns the exploited CVEs for which NVD holds
// version ranges for this product. A CVE in this set that NVD did not return
// for the running version is known not to affect it.
func (c *Client) nvdExploitedWithVersionData(ctx context.Context, component Component) (map[string]bool, error) {
	known := map[string]bool{}
	for _, cpe := range component.cpes() {
		cves, err := c.nvdQuery(ctx, url.Values{"virtualMatchString": {cpeBase(cpe)}, "hasKev": {""}})
		if err != nil {
			return nil, err
		}
		for _, cve := range cves {
			known[cve.ID] = true
		}
	}
	return known, nil
}

// nvdFixed lists the "fixed in" bounds of the affected ranges that may
// contain the running version (all ranges when it is unknown).
func nvdFixed(running string, cve nvdCVE, prefix string) []string {
	var fixed []string
	for _, configuration := range cve.Configurations {
		for _, node := range configuration.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable || !strings.HasPrefix(match.Criteria, prefix) || match.VersionEndExcluding == "" {
					continue
				}
				if running != "" && !mayContain(running, match) {
					continue
				}
				fixed = appendUnique(fixed, match.VersionEndExcluding)
			}
		}
	}
	return fixed
}

// mayContain is false only when the version is known to fall outside the range.
func mayContain(running string, match nvdMatch) bool {
	check := func(bound string, holds func(comparison int) bool) bool {
		if bound == "" {
			return true
		}
		comparison, ok := version.Compare(running, bound)
		return !ok || holds(comparison)
	}
	return check(match.VersionStartIncluding, func(c int) bool { return c >= 0 }) &&
		check(match.VersionStartExcluding, func(c int) bool { return c > 0 }) &&
		check(match.VersionEndIncluding, func(c int) bool { return c <= 0 }) &&
		check(match.VersionEndExcluding, func(c int) bool { return c < 0 })
}

// ---- CISA KEV: what is being exploited. It names products, not versions.

type kevEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

type kevIndex struct {
	entries []kevEntry
	byCVE   map[string]kevEntry
}

func (c *Client) kev(ctx context.Context) (*kevIndex, error) {
	c.kevMu.Lock()
	defer c.kevMu.Unlock()
	if c.kevIndex != nil && time.Since(c.kevAt) < ttlKEV {
		return c.kevIndex, nil
	}
	var catalog struct {
		Vulnerabilities []kevEntry `json:"vulnerabilities"`
	}
	if _, err := c.fetch(ctx, request{url: c.Endpoints.KEV, ttl: ttlKEV}, &catalog); err != nil {
		return nil, err
	}
	index := &kevIndex{entries: catalog.Vulnerabilities, byCVE: make(map[string]kevEntry, len(catalog.Vulnerabilities))}
	for _, entry := range catalog.Vulnerabilities {
		index.byCVE[entry.CVE] = entry
	}
	c.kevIndex, c.kevAt = index, time.Now()
	return index, nil
}

// matching returns the catalog entries whose vendor or product mentions the
// component by name or alias.
func (k *kevIndex) matching(component Component) []kevEntry {
	terms := append([]string{component.Name}, component.Aliases...)
	var matches []kevEntry
	for _, entry := range k.entries {
		text := entry.Vendor + " " + entry.Product
		for _, term := range terms {
			if mentions(text, term) {
				matches = append(matches, entry)
				break
			}
		}
	}
	return matches
}

// mentions reports whether term appears in text as a whole word or phrase,
// so that "go" does not match "django".
func mentions(text, term string) bool {
	text, term = strings.ToLower(text), strings.ToLower(strings.TrimSpace(term))
	if term == "" {
		return false
	}
	isWord := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
	for offset := 0; ; {
		index := strings.Index(text[offset:], term)
		if index < 0 {
			return false
		}
		start, end := offset+index, offset+index+len(term)
		if (start == 0 || !isWord(text[start-1])) && (end == len(text) || !isWord(text[end])) {
			return true
		}
		offset = start + 1
	}
}

// ---- EPSS: how likely a CVE is to be exploited soon.

func (c *Client) epss(ctx context.Context, cves []string) (map[string]float64, error) {
	scores := map[string]float64{}
	for start := 0; start < len(cves); start += epssPerRequest {
		group := cves[start:min(start+epssPerRequest, len(cves))]
		var response struct {
			Data []struct {
				CVE  string  `json:"cve"`
				EPSS float64 `json:"epss,string"`
			} `json:"data"`
		}
		if _, err := c.fetch(ctx, request{url: c.Endpoints.EPSS + "?cve=" + strings.Join(group, ","), ttl: ttlEPSS}, &response); err != nil {
			return nil, err
		}
		for _, row := range response.Data {
			scores[row.CVE] = row.EPSS
		}
	}
	return scores, nil
}

// ---- Latest release.

// Latest returns the newest final release of the component, or "" when none
// of its identifiers can answer.
func (c *Client) Latest(ctx context.Context, component Component) (string, error) {
	switch {
	case strings.EqualFold(component.Ecosystem, "PyPI"):
		var data struct {
			Info struct {
				Version string `json:"version"`
			} `json:"info"`
		}
		_, err := c.fetch(ctx, request{url: c.Endpoints.PyPI + "/pypi/" + url.PathEscape(component.packageName()) + "/json", ttl: ttlLatest}, &data)
		return data.Info.Version, err
	case strings.EqualFold(component.Ecosystem, "npm"):
		var data struct {
			Version string `json:"version"`
		}
		_, err := c.fetch(ctx, request{url: c.Endpoints.NPM + "/" + url.PathEscape(component.packageName()) + "/latest", ttl: ttlLatest}, &data)
		return data.Version, err
	case component.Repo != "":
		var releases []struct {
			TagName    string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		releasesURL := fmt.Sprintf("%s/repos/%s/releases?per_page=100", c.Endpoints.GitHub, component.Repo)
		if _, err := c.fetch(ctx, request{url: releasesURL, headers: c.githubHeaders(), ttl: ttlLatest}, &releases); err != nil {
			return "", err
		}
		var tags []string
		for _, release := range releases {
			if release.Draft || release.Prerelease {
				continue
			}
			// A repository that releases several things tags each with its
			// own prefix; only the product's own tags count.
			tag, isProduct := strings.CutPrefix(release.TagName, component.TagPrefix)
			if isProduct {
				tags = append(tags, tag)
			}
		}
		return version.Highest(tags), nil
	case component.GitLabRepo != "":
		var tags []struct {
			Name string `json:"name"`
		}
		tagsURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/tags?per_page=50&order_by=version", c.Endpoints.GitLab, url.PathEscape(component.GitLabRepo))
		if _, err := c.fetch(ctx, request{url: tagsURL, ttl: ttlLatest}, &tags); err != nil {
			return "", err
		}
		names := make([]string, len(tags))
		for i, tag := range tags {
			names[i] = tag.Name
		}
		return version.Highest(names), nil
	}
	return "", nil
}
