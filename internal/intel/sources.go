package intel

import (
	"context"
	"fmt"
	"net/url"
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
				fixed = appendUnique(fixed, event.Fixed)
			}
		}
	}
	return fixed
}

func (c *Client) osvAdvisories(ctx context.Context, component Component) ([]Advisory, error) {
	query := map[string]any{
		"package": map[string]string{"name": component.packageName(), "ecosystem": component.Ecosystem},
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
				ID:        vuln.ID,
				Aliases:   vuln.Aliases,
				Title:     vuln.title(),
				Severity:  normalizeSeverity(vuln.DatabaseSpecific.Severity),
				FixedIn:   vuln.fixedFor(component.packageName()),
				Published: vuln.Published,
				URL:       "https://osv.dev/vulnerability/" + url.PathEscape(vuln.ID),
				Sources:   []string{"osv"},
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

// ---- GitHub: the upstream repository's own security advisories.

type githubAdvisory struct {
	GHSAID          string  `json:"ghsa_id"`
	CVEID           *string `json:"cve_id"`
	Summary         string  `json:"summary"`
	Severity        *string `json:"severity"`
	HTMLURL         string  `json:"html_url"`
	PublishedAt     *string `json:"published_at"`
	Vulnerabilities []struct {
		Range   *string `json:"vulnerable_version_range"`
		Patched *string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

func (c *Client) githubAdvisories(ctx context.Context, component Component) ([]Advisory, error) {
	next := fmt.Sprintf("%s/repos/%s/security-advisories?state=published&per_page=100", c.Endpoints.GitHub, component.Repo)
	var advisories []Advisory
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return nil, fmt.Errorf("github: more than %d pages of advisories; refusing to report a partial list", maxPages)
		}
		var batch []githubAdvisory
		var err error
		if next, err = c.fetch(ctx, request{url: next, headers: c.githubHeaders(), ttl: ttlGitHub}, &batch); err != nil {
			return nil, err
		}
		for _, item := range batch {
			advisory, applies := githubApplies(component.Version, item)
			if applies {
				advisories = append(advisories, advisory)
			}
		}
	}
	return advisories, nil
}

// githubApplies turns a repository advisory into an Advisory, and reports
// false only when every affected range is known to exclude the version.
func githubApplies(running string, item githubAdvisory) (Advisory, bool) {
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

	var allFixed, affectedFixed []string
	affected, undetermined := false, len(item.Vulnerabilities) == 0
	for i, entry := range item.Vulnerabilities {
		patched := ""
		if entry.Patched != nil {
			patched = *entry.Patched
		}
		allFixed = appendUnique(allFixed, patched)
		if running == "" || entry.Range == nil {
			undetermined = true
			continue
		}
		inRange, known := version.Satisfies(running, *entry.Range)
		switch {
		case !known:
			undetermined = true
		case inRange && backported(running, item, i):
			// Fixed on this release line; the open-ended range is for a later one.
		case inRange:
			affected = true
			affectedFixed = appendUnique(affectedFixed, patched)
		}
	}
	switch {
	case affected:
		advisory.FixedIn = affectedFixed
	case running == "":
		advisory.FixedIn = allFixed
		advisory.Note = noVersionNote
	case undetermined:
		advisory.FixedIn = allFixed
		advisory.Note = "The affected range could not be compared with the version; check it by hand."
	default:
		return advisory, false
	}
	return advisory, true
}

// backported reports whether the running version already has the fix even
// though it falls inside entry i's range.
//
// Projects that backport a fix often list one open-ended range per release
// line: "< 1.106.9" and "< 1.108.6". Read literally, the second says 1.106.12
// is vulnerable, although the first fixed it on that line. So an open-ended
// range is set aside when another entry of the same advisory publishes a fix
// on the running version's release line at or below it. A range with a lower
// bound is always taken as written.
func backported(running string, item githubAdvisory, i int) bool {
	constraint := strings.TrimSpace(*item.Vulnerabilities[i].Range)
	if strings.Contains(constraint, ",") || !strings.HasPrefix(constraint, "<") {
		return false
	}
	for j, other := range item.Vulnerabilities {
		if j == i || other.Patched == nil {
			continue
		}
		for _, fix := range strings.Split(*other.Patched, ",") {
			fix = strings.TrimSpace(fix)
			if !version.SameLine(running, fix) {
				continue
			}
			if comparison, ok := version.Compare(running, fix); ok && comparison >= 0 {
				return true
			}
		}
	}
	return false
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

func (c *Client) nvdAdvisories(ctx context.Context, component Component) ([]Advisory, error) {
	base := cpeBase(component.CPE)
	parameters := url.Values{}
	if component.Version != "" {
		parameters.Set("virtualMatchString", base+":"+component.Version)
	} else {
		// A product's full history can run to thousands of CVEs.
		now := time.Now().UTC()
		parameters.Set("virtualMatchString", base)
		parameters.Set("pubStartDate", now.Add(-recentWindow).Format("2006-01-02T15:04:05.000Z"))
		parameters.Set("pubEndDate", now.Format("2006-01-02T15:04:05.000Z"))
	}
	cves, err := c.nvdQuery(ctx, parameters)
	if err != nil {
		return nil, err
	}
	advisories := make([]Advisory, 0, len(cves))
	for _, cve := range cves {
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
	return advisories, nil
}

// nvdExploitedWithVersionData returns the exploited CVEs for which NVD holds
// version ranges for this product. A CVE in this set that NVD did not return
// for the running version is known not to affect it.
func (c *Client) nvdExploitedWithVersionData(ctx context.Context, component Component) (map[string]bool, error) {
	cves, err := c.nvdQuery(ctx, url.Values{"virtualMatchString": {cpeBase(component.CPE)}, "hasKev": {""}})
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, cve := range cves {
		known[cve.ID] = true
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
			if !release.Draft && !release.Prerelease {
				tags = append(tags, release.TagName)
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
