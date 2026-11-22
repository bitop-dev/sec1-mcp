package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fake stands in for every advisory service. Each handler is small enough to
// read as the scenario it sets up.
type fake struct {
	t              *testing.T
	osvDown        bool
	metasploitDown bool
	nvdCalls       atomic.Int32
}

func (f *fake) client() *Client {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, value any) { _ = json.NewEncoder(w).Encode(value) }

	// OSV: one advisory affects 1.106.6 and nothing affects 1.106.9.
	mux.HandleFunc("/osv/v1/query", func(w http.ResponseWriter, r *http.Request) {
		if f.osvDown {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		vulns := []map[string]any{}
		if strings.Contains(string(body), `"purl"`) {
			// Full records for one package of a bill of materials: the same
			// flaw under two databases' ids.
			if strings.Contains(string(body), "pkg:pypi/requests@2.25.0") {
				vulns = append(vulns,
					map[string]any{"id": "GHSA-aaaa-bbbb-cccc", "aliases": []string{"CVE-2026-1111"}, "summary": "Secret exfiltration",
						"database_specific": map[string]string{"severity": "HIGH"},
						"affected": []map[string]any{{"package": map[string]string{"name": "requests", "ecosystem": "PyPI"},
							"ranges": []map[string]any{{"events": []map[string]string{{"introduced": "0"}, {"fixed": "2.31.0"}}}}}}},
					map[string]any{"id": "PYSEC-2026-1", "aliases": []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-1111"}, "details": "Same flaw."},
					map[string]any{"id": "GHSA-dddd-eeee-ffff", "summary": "Another flaw", "database_specific": map[string]string{"severity": "LOW"}})
			}
			reply(w, map[string]any{"vulns": vulns})
			return
		}
		if strings.Contains(string(body), `"1.106.6"`) || !strings.Contains(string(body), `"version"`) {
			vulns = append(vulns, map[string]any{
				"id": "GHSA-aaaa-bbbb-cccc", "aliases": []string{"CVE-2026-1111"},
				"summary":           "Secret exfiltration\u0000 via   request body",
				"published":         "2026-11-12T00:00:00Z",
				"database_specific": map[string]string{"severity": "HIGH"},
				"affected": []map[string]any{{
					"package": map[string]string{"name": "litellm", "ecosystem": "PyPI"},
					"ranges":  []map[string]any{{"events": []map[string]string{{"introduced": "0"}, {"fixed": "1.106.9"}}}},
				}},
			})
		}
		reply(w, map[string]any{"vulns": vulns})
	})
	mux.HandleFunc("/osv/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/GHSA-aaaa-bbbb-cccc"):
			reply(w, map[string]any{"id": "GHSA-aaaa-bbbb-cccc", "aliases": []string{"CVE-2026-1111"}, "summary": "Secret exfiltration", "details": "Long text.",
				"database_specific": map[string]string{"severity": "HIGH"},
				"affected": []map[string]any{{"package": map[string]string{"name": "requests", "ecosystem": "PyPI"},
					"ranges": []map[string]any{{"events": []map[string]string{{"introduced": "0"}, {"fixed": "2.31.0"}}}}}}})
		case strings.HasSuffix(r.URL.Path, "/PYSEC-2026-1"):
			// The same flaw under another database's id.
			reply(w, map[string]any{"id": "PYSEC-2026-1", "aliases": []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-1111"}, "details": "Same flaw."})
		default:
			http.NotFound(w, r)
		}
	})
	// Batch lookups by package URL: requests is affected, anything else is not.
	mux.HandleFunc("/osv/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		if f.osvDown {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			Queries []struct {
				Package struct {
					PURL string `json:"purl"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		results := []map[string]any{}
		for _, query := range body.Queries {
			vulns := []map[string]string{}
			if query.Package.PURL == "pkg:pypi/requests@2.25.0" {
				vulns = append(vulns, map[string]string{"id": "GHSA-aaaa-bbbb-cccc"}, map[string]string{"id": "PYSEC-2026-1"}, map[string]string{"id": "GHSA-gone-gone-gone"})
			}
			results = append(results, map[string]any{"vulns": vulns})
		}
		reply(w, map[string]any{"results": results})
	})

	// GitHub: one advisory whose range excludes 1.106.6, one that includes it.
	mux.HandleFunc("/github/repos/BerriAI/litellm/security-advisories", func(w http.ResponseWriter, r *http.Request) {
		reply(w, []map[string]any{
			{"ghsa_id": "GHSA-old0-old0-old0", "cve_id": "CVE-2026-2222", "summary": "Old bug", "severity": "critical", "html_url": "https://example.invalid/old",
				"vulnerabilities": []map[string]any{{"vulnerable_version_range": "< 1.83.7", "patched_versions": "1.83.7"}}},
			{"ghsa_id": "GHSA-dddd-eeee-ffff", "summary": "Key metadata leak", "severity": "medium", "html_url": "https://example.invalid/new",
				"vulnerabilities": []map[string]any{{"vulnerable_version_range": "< 1.106.12", "patched_versions": "1.106.12"}}},
		})
	})
	mux.HandleFunc("/github/repos/BerriAI/litellm/releases", func(w http.ResponseWriter, r *http.Request) {
		reply(w, []map[string]any{{"tag_name": "v1.110.2"}})
	})
	mux.HandleFunc("/pypi/pypi/litellm/json", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"info": map[string]string{"version": "1.110.2"}})
	})

	// NVD: nothing affects the running version. It holds version data for
	// one of the two exploited CVEs that name the product.
	mux.HandleFunc("/nvd", func(w http.ResponseWriter, r *http.Request) {
		f.nvdCalls.Add(1)
		cves := []map[string]any{}
		if _, exploitedOnly := r.URL.Query()["hasKev"]; exploitedOnly {
			cves = append(cves, map[string]any{"cve": map[string]any{"id": "CVE-2026-2222"}})
		}
		reply(w, map[string]any{"totalResults": len(cves), "resultsPerPage": len(cves), "vulnerabilities": cves})
	})

	// Lifecycle data: line 16 is supported, line 12 has ended.
	mux.HandleFunc("/lifecycle/postgresql/", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"result": map[string]any{"releases": []map[string]any{
			{"name": "17", "isEol": false, "eolFrom": "2029-11-08", "latest": map[string]string{"name": "17.2"}},
			{"name": "16", "isEol": false, "eolFrom": "2028-11-09", "latest": map[string]string{"name": "16.6"}},
			{"name": "12", "isEol": true, "eolFrom": "2024-11-21", "latest": map[string]string{"name": "12.22"}},
		}}})
	})
	// Public exploit lists: a scanner template for one CVE, a module for another.
	mux.HandleFunc("/nuclei", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ID":"CVE-2026-1111","Info":{"Name":"x"},"file_path":"a.yaml"}` + "\n" + `{"ID":"CVE-2020-0001","Info":{},"file_path":"b.yaml"}` + "\n"))
	})
	mux.HandleFunc("/metasploit", func(w http.ResponseWriter, r *http.Request) {
		if f.metasploitDown {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		reply(w, map[string]any{
			"exploit_multi/http/example": map[string]any{"references": []string{"CVE-2026-5555", "URL-https://example.invalid"}},
		})
	})

	// Name searches, for find_identifiers.
	mux.HandleFunc("/pypi/pypi/redis/json", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"info": map[string]string{"name": "redis", "summary": "Python client for Redis database and key-value store", "version": "6.0.0"}})
	})
	mux.HandleFunc("/github/search/repositories", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"items": []map[string]any{
			{"full_name": "someone/redis-commander", "name": "redis-commander", "description": "A web UI", "stargazers_count": 90000},
			{"full_name": "redis/redis", "name": "redis", "description": "The database", "stargazers_count": 70000},
			{"full_name": "fork/redis", "name": "redis", "description": "A fork", "stargazers_count": 5, "fork": true},
		}})
	})
	mux.HandleFunc("/nvdproducts", func(w http.ResponseWriter, r *http.Request) {
		names := []string{
			"cpe:2.3:a:redis:redis:7.0.0:*:*:*:*:*:*:*", "cpe:2.3:a:redis:redis:7.2.0:*:*:*:*:*:*:*",
			"cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*", "cpe:2.3:a:redis:redis-py:4.0.0:*:*:*:*:*:*:*",
			"cpe:2.3:a:other:unrelated:1.0:*:*:*:*:*:*:*",
		}
		products := []map[string]any{}
		for i, name := range names {
			products = append(products, map[string]any{"cpe": map[string]any{"cpeName": name, "deprecated": i == 2}})
		}
		reply(w, map[string]any{"products": products})
	})

	// KEV: the OSV advisory's CVE is exploited; two more name the product.
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"vulnerabilities": []map[string]string{
			{"cveID": "CVE-2026-1111", "vendorProject": "BerriAI", "product": "LiteLLM", "vulnerabilityName": "LiteLLM secret exfiltration", "dateAdded": "2026-11-17"},
			{"cveID": "CVE-2026-2222", "vendorProject": "BerriAI", "product": "LiteLLM", "vulnerabilityName": "LiteLLM old SQL injection", "dateAdded": "2026-04-30"},
			{"cveID": "CVE-2026-3333", "vendorProject": "BerriAI", "product": "LiteLLM", "vulnerabilityName": "LiteLLM unanalysed flaw", "dateAdded": "2026-11-01"},
			{"cveID": "CVE-2026-4444", "vendorProject": "Other", "product": "NotLiteLLMAtAll", "vulnerabilityName": "Unrelated", "dateAdded": "2026-11-01"},
		}})
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"data": []map[string]string{{"cve": "CVE-2026-1111", "epss": "0.780000000"}}})
	})

	server := httptest.NewServer(mux)
	f.t.Cleanup(server.Close)
	return &Client{
		HTTP:  server.Client(),
		Cache: NewCache(""),
		Endpoints: Endpoints{
			OSV: server.URL + "/osv", GitHub: server.URL + "/github", NVD: server.URL + "/nvd", NVDProducts: server.URL + "/nvdproducts",
			KEV: server.URL + "/kev", EPSS: server.URL + "/epss", PyPI: server.URL + "/pypi", NPM: server.URL + "/npm",
			Lifecycle: server.URL + "/lifecycle", Nuclei: server.URL + "/nuclei", Metasploit: server.URL + "/metasploit",
		},
	}
}

var litellm = Component{Name: "LiteLLM", Version: "1.106.6", Ecosystem: "PyPI", Package: "litellm", Repo: "BerriAI/litellm", CPE: "litellm:litellm"}

func find(t *testing.T, result Result, id string) *Advisory {
	t.Helper()
	for i := range result.Advisories {
		if result.Advisories[i].ID == id {
			return &result.Advisories[i]
		}
	}
	return nil
}

func TestCheckCombinesSources(t *testing.T) {
	f := &fake{t: t}
	result := f.client().Check(context.Background(), litellm)

	if result.Status != StatusAffected {
		t.Fatalf("status = %q (%s), want affected", result.Status, result.Reason)
	}
	exploited := find(t, result, "GHSA-aaaa-bbbb-cccc")
	if exploited == nil {
		t.Fatal("the OSV advisory is missing")
	}
	if !exploited.Exploited || exploited.ExploitedSince != "2026-11-17" || exploited.Priority != "urgent" {
		t.Errorf("exploited flag was not merged in from KEV: %+v", exploited)
	}
	if exploited.EPSS == nil || *exploited.EPSS != 0.78 {
		t.Errorf("EPSS = %v, want 0.78", exploited.EPSS)
	}
	if exploited.Title != "Secret exfiltration via request body" {
		t.Errorf("title was not cleaned: %q", exploited.Title)
	}
	if result.Advisories[0].ID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("the exploited advisory should sort first, got %s", result.Advisories[0].ID)
	}

	if find(t, result, "GHSA-dddd-eeee-ffff") == nil {
		t.Error("the GitHub advisory whose range includes the version is missing")
	}
	if find(t, result, "GHSA-old0-old0-old0") != nil {
		t.Error("the GitHub advisory fixed before this version should not be listed")
	}
	if find(t, result, "CVE-2026-2222") != nil {
		t.Error("an exploited CVE that NVD shows as not affecting this version should be dropped")
	}
	kept := find(t, result, "CVE-2026-3333")
	if kept == nil || !kept.NameOnly {
		t.Errorf("an exploited CVE with no version data must stay, marked name-only: %+v", kept)
	}
	if find(t, result, "CVE-2026-4444") != nil {
		t.Error("a product whose name merely contains ours must not match")
	}
	if result.LatestVersion != "1.110.2" || result.VersionStatus != "behind" {
		t.Errorf("latest = %q, versionStatus = %q", result.LatestVersion, result.VersionStatus)
	}
}

func TestCheckReportsCleanVersion(t *testing.T) {
	f := &fake{t: t}
	// No name-only matches to reconcile here, so drop the aliases KEV would hit.
	component := Component{Name: "pkg-litellm", Version: "1.106.12", Ecosystem: "PyPI", Package: "litellm"}
	result := f.client().Check(context.Background(), component)
	if result.Status != StatusNoKnown {
		t.Fatalf("status = %q (%s), want no_known_advisories", result.Status, result.Reason)
	}
}

func TestFailedSourceIsNeverClean(t *testing.T) {
	f := &fake{t: t, osvDown: true}
	component := Component{Name: "pkg-litellm", Version: "1.106.12", Ecosystem: "PyPI", Package: "litellm"}
	client := f.client()
	result := client.Check(context.Background(), component)
	if result.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown when a source is down", result.Status)
	}
	if !strings.Contains(result.Reason, "osv") {
		t.Errorf("the reason should name the failed source: %q", result.Reason)
	}
}

func TestUnrecognisedComponentIsUnknown(t *testing.T) {
	f := &fake{t: t}
	result := f.client().Check(context.Background(), Component{Name: "mystery-daemon", Version: "1.0.0"})
	if result.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown when no source can check by version", result.Status)
	}
}

func TestNoVersionAsksForOne(t *testing.T) {
	f := &fake{t: t}
	component := litellm
	component.Version = ""
	result := f.client().Check(context.Background(), component)
	if result.Status != StatusVersionNeeded {
		t.Fatalf("status = %q, want version_needed", result.Status)
	}
}

func TestSuggestVerifiesTheUpgrade(t *testing.T) {
	f := &fake{t: t}
	suggestion := f.client().Suggest(context.Background(), litellm)
	if suggestion.MinimumFixed == nil || suggestion.MinimumFixed.Version != "1.106.12" {
		t.Fatalf("minimumFixed = %+v, want 1.106.12 (the higher of the two fixes)", suggestion.MinimumFixed)
	}
	if suggestion.Latest == nil || suggestion.Latest.Version != "1.110.2" {
		t.Errorf("latest = %+v, want 1.110.2", suggestion.Latest)
	}
	if len(suggestion.Unfixed) != 0 {
		t.Errorf("unfixed = %v, want none", suggestion.Unfixed)
	}
}

func TestAdvisoryDetail(t *testing.T) {
	f := &fake{t: t}
	client := f.client()
	detail, err := client.Advisory(context.Background(), "GHSA-aaaa-bbbb-cccc")
	if err != nil {
		t.Fatal(err)
	}
	if !detail.Exploited || detail.EPSS == nil {
		t.Errorf("KEV and EPSS should be looked up through the CVE alias: %+v", detail)
	}
	if _, err := client.Advisory(context.Background(), "GHSA-zzzz-zzzz-zzzz"); err == nil {
		t.Error("an unknown advisory id should be an error, not an empty record")
	}
}

func TestResponsesAreCached(t *testing.T) {
	f := &fake{t: t}
	client := f.client()
	component := Component{Name: "GitLab", Version: "19.6.1", CPE: "gitlab:gitlab"}
	client.Check(context.Background(), component)
	first := f.nvdCalls.Load()
	client.Check(context.Background(), component)
	if first == 0 || f.nvdCalls.Load() != first {
		t.Errorf("NVD was called %d times, then %d; the second check should be served from cache", first, f.nvdCalls.Load())
	}
}

func TestNVDRequestsArePaced(t *testing.T) {
	f := &fake{t: t}
	client := f.client()
	client.NVDPause = 150 * time.Millisecond
	started := time.Now()
	client.Check(context.Background(), Component{Name: "A", Version: "1.0.0", CPE: "a:a"})
	client.Check(context.Background(), Component{Name: "B", Version: "1.0.0", CPE: "b:b"})
	if elapsed := time.Since(started); elapsed < client.NVDPause {
		t.Errorf("two NVD requests took %v; they should be at least %v apart", elapsed, client.NVDPause)
	}
}

func TestMentions(t *testing.T) {
	cases := []struct {
		text, term string
		want       bool
	}{
		{"Apache Log4j2", "log4j2", true},
		{"Django REST framework", "go", false},
		{"GitLab Community Edition", "gitlab", true},
		{"NotGitLab", "gitlab", false},
		{"anything", "", false},
	}
	for _, c := range cases {
		if got := mentions(c.text, c.term); got != c.want {
			t.Errorf("mentions(%q, %q) = %v, want %v", c.text, c.term, got, c.want)
		}
	}
}

// advisoryWith builds a repository advisory from "range => fixes" pairs.
func advisoryWith(entries ...[2]string) githubAdvisory {
	item := githubAdvisory{GHSAID: "GHSA-test-test-test"}
	for _, entry := range entries {
		affected, patched := entry[0], entry[1]
		item.Vulnerabilities = append(item.Vulnerabilities, struct {
			Range   *string `json:"vulnerable_version_range"`
			Patched *string `json:"patched_versions"`
		}{&affected, &patched})
	}
	return item
}

// These range styles are all taken from real project advisories.
func TestGitHubAdvisoryVerdicts(t *testing.T) {
	perLine := advisoryWith([2]string{"< 1.106.9", "1.106.9"}, [2]string{"< 1.108.6", "1.108.6"}, [2]string{"< 1.110.0-rc.2", "1.110.0-rc.2"})
	startOnly := advisoryWith([2]string{">= 9.2.0", "9.2.4"})
	hyphen := advisoryWith([2]string{"8.0.0 - 8.3.0", "8.3.1, 8.2.7, 8.1.8, 8.0.7"})
	twoBounded := advisoryWith([2]string{">=9.2.0 <9.2.10 >=9.3.0 <9.3.4", ""})
	wildcards := advisoryWith([2]string{"<9.x, <8.x", ""})
	wildcardsWithFix := advisoryWith([2]string{"<9.x, <8.x", "9.2.4, 8.5.15"})
	noFix := advisoryWith([2]string{">=8.1", ""})
	regression := advisoryWith([2]string{"< 1.106.9", "1.106.9"}, [2]string{">= 1.106.10, < 1.108.6", "1.108.6"})

	cases := []struct {
		name    string
		item    githubAdvisory
		running string
		want    int
	}{
		{"below the fix on its own line", perLine, "1.106.6", verdictApplies},
		{"the fix itself", perLine, "1.106.9", verdictNotAffected},
		{"a later patch on a fixed line", perLine, "1.106.12", verdictNotAffected},
		{"a line that never got the fix", perLine, "1.107.0", verdictApplies},
		{"just below a later line's fix", perLine, "1.108.5", verdictApplies},
		{"at a release candidate fix's final release", perLine, "1.110.2", verdictNotAffected},

		{"start-only range, before the fix", startOnly, "9.2.2", verdictApplies},
		{"start-only range, a later patch", startOnly, "9.2.6", verdictNotAffected},
		{"start-only range, a later major", startOnly, "10.0.0", verdictAssumedFixed},
		{"start-only range, before it starts", startOnly, "9.1.0", verdictNotAffected},

		{"hyphen range, inside", hyphen, "8.2.3", verdictApplies},
		{"hyphen range, a fixed line", hyphen, "8.2.7", verdictNotAffected},
		{"hyphen range, long after", hyphen, "10.0.0", verdictAssumedFixed},

		{"two bounded clauses, in the second", twoBounded, "9.3.1", verdictApplies},
		{"two bounded clauses, between them", twoBounded, "9.2.10", verdictNotAffected},

		{"unreadable range, no fix: cannot be ruled out", wildcards, "10.0.0", verdictApplies},
		{"unreadable range, newer than every fix", wildcardsWithFix, "10.0.0", verdictAssumedFixed},
		{"unreadable range, fix on the same line", wildcardsWithFix, "9.2.1", verdictApplies},

		{"no fixed version published", noFix, "10.0.0", verdictApplies},
		{"a bounded range is taken as written", regression, "1.106.12", verdictApplies},
		{"no version given", startOnly, "", verdictApplies},
	}
	for _, c := range cases {
		if _, got := githubApplies(c.running, c.item); got != c.want {
			t.Errorf("%s (version %q): verdict = %d, want %d", c.name, c.running, got, c.want)
		}
	}

	if advisory, _ := githubApplies("10.0.0", noFix); !strings.Contains(advisory.Note, "no fixed version") {
		t.Errorf("an advisory with no fix should say so: %q", advisory.Note)
	}
}

func TestNameOnlyMatchClearedByTheRepository(t *testing.T) {
	// The repository's own advisory for CVE-2026-2222 shows the version is
	// fixed, so CISA's name match for that CVE must not come back.
	f := &fake{t: t}
	component := Component{Name: "LiteLLM", Version: "1.106.6", Repo: "BerriAI/litellm"}
	result := f.client().Check(context.Background(), component)
	if find(t, result, "CVE-2026-2222") != nil {
		t.Error("a name-only match the repository advisory rules out should be dropped")
	}
	if kept := find(t, result, "CVE-2026-3333"); kept == nil || !kept.NameOnly {
		t.Error("a name-only match no source knows about must stay")
	}
}

func TestCandidates(t *testing.T) {
	f := &fake{t: t}
	candidates, coverage := f.client().Candidates(context.Background(), "Redis")
	byKind := map[string][]Candidate{}
	for _, candidate := range candidates {
		byKind[candidate.Kind] = append(byKind[candidate.Kind], candidate)
	}

	if packages := byKind["registry-package"]; len(packages) != 1 || packages[0].Ecosystem != "PyPI" || !strings.Contains(packages[0].Description, "client") {
		t.Errorf("registry candidates = %+v; the description must be kept so a client library can be told apart", packages)
	}
	repos := byKind["github-repo"]
	if len(repos) != 2 || repos[0].Repo != "redis/redis" || !repos[0].ExactName || repos[1].ExactName {
		t.Errorf("github candidates = %+v; the exactly-named repository should come first, and forks be left out", repos)
	}
	products := byKind["nvd-product"]
	if len(products) != 2 || products[0].CPE != "redis:redis" || !products[0].ExactName || products[1].CPE != "redis:redis-py" {
		t.Errorf("nvd candidates = %+v; want redis:redis first, deprecated and unrelated entries left out", products)
	}
	for _, entry := range coverage {
		if entry.Status != "checked" {
			t.Errorf("coverage %+v: a registry with no such package is checked, not failed", entry)
		}
	}
}

func coverageOf(result Result, source string) Coverage {
	for _, entry := range result.Coverage {
		if entry.Source == source {
			return entry
		}
	}
	return Coverage{}
}

func TestSupportStatus(t *testing.T) {
	f := &fake{t: t}
	client := f.client()
	postgres := func(v string) Component {
		return Component{Name: "pg-test", Version: v, CPE: "postgresql:postgresql", Lifecycle: "postgresql"}
	}

	supported := client.Check(context.Background(), postgres("16.4"))
	if s := supported.Support; s.Status != SupportSupported || s.ReleaseLine != "16" || s.LatestInLine != "16.6" || s.EndOfLife != "2028-11-09" {
		t.Errorf("16.4: support = %+v", s)
	}
	// The lifecycle data supplies the latest release when nothing else does.
	if supported.LatestVersion != "17.2" || supported.VersionStatus != "behind" {
		t.Errorf("16.4: latest = %q, versionStatus = %q", supported.LatestVersion, supported.VersionStatus)
	}

	ended := client.Check(context.Background(), postgres("12.5"))
	if ended.Support.Status != SupportEnded {
		t.Errorf("12.5: support = %+v, want end_of_life", ended.Support)
	}
	if !strings.Contains(ended.Reason, "end of life on 2024-11-21") {
		t.Errorf("12.5: the reason should say the line has ended: %q", ended.Reason)
	}

	for name, component := range map[string]Component{
		"a line the data does not list": postgres("9.6.1"),
		"no version":                    postgres(""),
		"no lifecycle data":             {Name: "pg-test", Version: "16.4", CPE: "postgresql:postgresql"},
	} {
		if got := client.Check(context.Background(), component).Support.Status; got != SupportUnknown {
			t.Errorf("%s: support status = %q, want unknown", name, got)
		}
	}
	// "160" must not be read as release line "16".
	if got := client.Check(context.Background(), postgres("160.1")).Support.Status; got != SupportUnknown {
		t.Errorf("160.1 matched a release line: %q", got)
	}
}

func TestPublicExploitsRaisePriority(t *testing.T) {
	f := &fake{t: t}
	result := f.client().Check(context.Background(), litellm)

	targeted := find(t, result, "GHSA-aaaa-bbbb-cccc") // alias CVE-2026-1111 has a scanner template
	if targeted == nil || len(targeted.PublicExploits) != 1 || targeted.PublicExploits[0] != "nuclei-template" {
		t.Fatalf("publicExploits = %+v", targeted)
	}
	if !strings.Contains(targeted.Rationale, "public scanner or exploit tool") {
		t.Errorf("the rationale should mention it: %q", targeted.Rationale)
	}
	if other := find(t, result, "GHSA-dddd-eeee-ffff"); other == nil || len(other.PublicExploits) != 0 {
		t.Errorf("an advisory with no CVE must carry no exploit flags: %+v", other)
	}
	if result.Counts.PublicExploit != 1 {
		t.Errorf("counts.publicExploit = %d, want 1", result.Counts.PublicExploit)
	}

	medium := Advisory{Severity: "medium", PublicExploits: []string{"metasploit-module"}}
	triage(&medium)
	if medium.Priority != "high" {
		t.Errorf("a medium advisory with a public exploit should be high, got %s", medium.Priority)
	}
}

func TestOneExploitListDownIsReportedNotHidden(t *testing.T) {
	f := &fake{t: t, metasploitDown: true}
	client := f.client()
	client.RetryDelays = nil
	result := client.Check(context.Background(), litellm)
	entry := coverageOf(result, "public-exploits")
	if entry.Status != "checked" || !strings.Contains(entry.Detail, "metasploit-module") {
		t.Errorf("coverage = %+v; want checked, naming the list that failed", entry)
	}
	if targeted := find(t, result, "GHSA-aaaa-bbbb-cccc"); targeted == nil || len(targeted.PublicExploits) != 1 {
		t.Error("the list that did load should still be applied")
	}
}

func TestWorkaroundExtraction(t *testing.T) {
	cases := map[string]string{
		"### Impact\nBad.\n\n### Patches\n1.2.3\n\n### Workarounds\nSet `auth.enabled: true`\nand restart.\n\n### References\nnone": "Set `auth.enabled: true` and restart.",
		"## Workaround\nBlock the /admin path at the proxy.":                                                                        "Block the /admin path at the proxy.",
		"### Workarounds\nNone.\n\n### References":                                                                                  "",
		"### Workarounds\n_No workarounds are available._":                                                                          "",
		"### Workarounds\nThere are no known workarounds.":                                                                          "",
		"### Impact\nNo workarounds heading here.":                                                                                  "",
		"": "",
	}
	for markdown, want := range cases {
		if got := workaround(markdown); got != want {
			t.Errorf("workaround(%q) = %q, want %q", markdown, got, want)
		}
	}
}

func TestProductFiledUnderTwoNVDNames(t *testing.T) {
	f := &fake{t: t}
	client := f.client()
	client.Check(context.Background(), Component{Name: "two-names", Version: "1.0.0", CPE: "f5:nginx", OtherCPEs: []string{"f5:nginx_open_source"}})
	if f.nvdCalls.Load() != 2 {
		t.Errorf("NVD was asked %d times, want once per product name", f.nvdCalls.Load())
	}
}

func TestGoModuleForTheVersionsMajor(t *testing.T) {
	traefik := Component{Ecosystem: "Go", Package: "github.com/traefik/traefik", OtherPackages: []string{"github.com/traefik/traefik/v2", "github.com/traefik/traefik/v3"}}
	grafana := Component{Ecosystem: "Go", Package: "github.com/grafana/grafana"}
	cases := []struct {
		component Component
		version   string
		want      string
	}{
		{traefik, "3.1.0", "github.com/traefik/traefik/v3"},
		{traefik, "v2.10.0", "github.com/traefik/traefik/v2"},
		{traefik, "1.7.34", "github.com/traefik/traefik"},
		{traefik, "4.0.0", "github.com/traefik/traefik"}, // no /v4 path is known, so the base path is asked
		{traefik, "", "github.com/traefik/traefik,github.com/traefik/traefik/v2,github.com/traefik/traefik/v3"},
		{grafana, "11.3.0", "github.com/grafana/grafana"}, // Grafana never adopted /vN paths
		{Component{Ecosystem: "PyPI", Package: "litellm", OtherPackages: []string{"litellm-proxy"}}, "2.0.0", "litellm,litellm-proxy"},
	}
	for _, c := range cases {
		c.component.Version = c.version
		if got := strings.Join(c.component.packages(), ","); got != c.want {
			t.Errorf("version %q: packages = %s, want %s", c.version, got, c.want)
		}
	}
}

func TestNVDSkipsCVEsWhereTheProductIsOnlyAPlatform(t *testing.T) {
	match := func(criteria string, vulnerable bool) nvdCVE {
		var cve nvdCVE
		_ = json.Unmarshal([]byte(`{"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"`+criteria+`","vulnerable":`+map[bool]string{true: "true", false: "false"}[vulnerable]+`}]}]}]}`), &cve)
		return cve
	}
	prefix := "cpe:2.3:a:postgresql:postgresql:"
	if !match(prefix+"*:*:*:*:*:*:*:*", true).vulnerableIn(prefix) {
		t.Error("a CVE marking the product vulnerable must be kept")
	}
	if match(prefix+"*:*:*:*:*:*:*:*", false).vulnerableIn(prefix) {
		t.Error("a CVE listing the product only as a platform must be skipped")
	}
	if !(nvdCVE{}).vulnerableIn(prefix) {
		t.Error("a CVE with no applicability data must be kept")
	}
}

func TestGoPseudoVersionsAreNotOfferedAsFixes(t *testing.T) {
	var vuln osvVuln
	_ = json.Unmarshal([]byte(`{"affected":[{"package":{"name":"github.com/grafana/grafana"},"ranges":[{"events":[
		{"introduced":"0"},{"fixed":"1.9.2-0.20260616075434-82ef13993059"},{"fixed":"11.6.14"}]}]}]}`), &vuln)
	if got := strings.Join(vuln.fixedFor("github.com/grafana/grafana"), ","); got != "11.6.14" {
		t.Errorf("fixedFor = %q, want only the release", got)
	}
}

const atomFeed = `<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Patch Releases</title>
<link href="https://example.invalid/releases/" rel="alternate"/>
<entry><title>Critical Patch Release: 19.6.2, 19.5.9 &amp; 19.4.11</title>
  <link href="https://example.invalid/self.xml" rel="self"/><link href="https://example.invalid/patch-19-6-2/" rel="alternate"/>
  <id>one</id><published>%s</published></entry>
<entry><title>Patch Release: 19.6.1, 19.5.8</title><link href="https://example.invalid/patch-19-6-1/" rel="alternate"/><published>%s</published></entry>
<entry><title>Old Patch Release: 30.0.0</title><link href="https://example.invalid/old/" rel="alternate"/><published>2020-01-01T00:00:00Z</published></entry>
<entry><title>No usable link</title><link href="javascript:alert(1)" rel="alternate"/><published>%s</published></entry>
</feed>`

func TestVendorNoticesKeepWhatMayConcernTheVersion(t *testing.T) {
	recent := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	mux := http.NewServeMux()
	mux.HandleFunc("/feed.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, atomFeed, recent, recent, recent)
	})
	served := httptest.NewServer(mux)
	defer served.Close()
	client := &Client{HTTP: served.Client(), Cache: NewCache("")}

	titles := func(running string) string {
		notices, err := client.vendorNotices(context.Background(), Component{Name: "GitLab", Version: running, Feeds: []string{served.URL + "/feed.xml"}})
		if err != nil {
			t.Fatal(err)
		}
		var list []string
		for _, notice := range notices {
			if !strings.HasPrefix(notice.URL, "https://example.invalid/patch-") {
				t.Errorf("unexpected link %q", notice.URL)
			}
			list = append(list, notice.Title)
		}
		return strings.Join(list, " | ")
	}
	// Running 19.6.1: the release that names a newer version is news; the
	// one that only names versions already included is not; the old one and
	// the one with an unusable link are dropped.
	if got := titles("19.6.1"); got != "Critical Patch Release: 19.6.2, 19.5.9 & 19.4.11" {
		t.Errorf("for 19.6.1: %q", got)
	}
	if got := titles("19.6.2"); got != "" {
		t.Errorf("for 19.6.2 nothing should remain: %q", got)
	}
	if got := titles(""); !strings.Contains(got, "19.6.2") || !strings.Contains(got, "19.6.1") {
		t.Errorf("with no version both recent notices should be listed: %q", got)
	}
}

func TestRSSFeedsAreReadToo(t *testing.T) {
	notices, dates, err := parseFeed([]byte(`<rss version="2.0"><channel><title>Bulletins</title><link>https://example.invalid/</link>
<item><title><![CDATA[Security Bulletin: Driver <2026>]]></title><link>https://example.invalid/bulletin/1</link>
<pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>`))
	if err != nil || len(notices) != 1 {
		t.Fatalf("notices = %+v, err = %v", notices, err)
	}
	if notices[0].Title != "Security Bulletin: Driver <2026>" || notices[0].URL != "https://example.invalid/bulletin/1" || dates[0].Year() != 2026 {
		t.Errorf("notice = %+v, date = %v", notices[0], dates[0])
	}
	if _, _, err := parseFeed([]byte("this is not xml <")); err == nil {
		t.Error("an unreadable feed should be an error, not an empty list")
	}
}

func TestLatestUsesTheProductsOwnTags(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kubernetes/ingress-nginx/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"tag_name": "helm-chart-4.15.1"}, {"tag_name": "controller-v1.15.1"}, {"tag_name": "controller-v1.14.5"},
		})
	})
	served := httptest.NewServer(mux)
	defer served.Close()
	client := &Client{HTTP: served.Client(), Cache: NewCache(""), Endpoints: Endpoints{GitHub: served.URL}}
	latest, err := client.Latest(context.Background(), Component{Name: "ingress-nginx", Repo: "kubernetes/ingress-nginx", TagPrefix: "controller-v"})
	if err != nil || latest != "1.15.1" {
		t.Errorf("latest = %q, err = %v; the chart's tag must not be mistaken for the controller's", latest, err)
	}
}

func TestParsePURL(t *testing.T) {
	cases := []struct {
		text, purl, kind, name, version string
	}{
		{"pkg:pypi/requests@2.25.0", "pkg:pypi/requests@2.25.0", "pypi", "requests", "2.25.0"},
		{"pkg:npm/%40babel/traverse@7.0.0", "pkg:npm/%40babel/traverse@7.0.0", "npm", "@babel/traverse", "7.0.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "maven", "org.apache.logging.log4j:log4j-core", "2.14.1"},
		{"pkg:golang/k8s.io/kubernetes@v1.28.4#pkg/api", "pkg:golang/k8s.io/kubernetes@v1.28.4", "golang", "k8s.io/kubernetes", "v1.28.4"},
		{"pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12", "pkg:deb/debian/openssl@3.0.11-1~deb12u2", "deb", "debian/openssl", "3.0.11-1~deb12u2"},
		{"pkg:pypi/django", "pkg:pypi/django", "pypi", "django", ""},
	}
	for _, c := range cases {
		pkg, ok := ParsePURL(c.text)
		if !ok || pkg.PURL != c.purl || pkg.Type != c.kind || pkg.Name != c.name || pkg.Version != c.version {
			t.Errorf("ParsePURL(%q) = %+v, %v", c.text, pkg, ok)
		}
	}
	for _, text := range []string{"", "requests@2.25.0", "pkg:", "pkg:pypi", "pkg:PyPI/x@1", "https://example.invalid/pkg:pypi/x"} {
		if pkg, ok := ParsePURL(text); ok {
			t.Errorf("ParsePURL(%q) = %+v; want it refused", text, pkg)
		}
	}
}

func TestCheckPackages(t *testing.T) {
	f := &fake{t: t}
	result := f.client().CheckPackages(context.Background(), []string{
		"pkg:pypi/requests@2.25.0",
		"pkg:pypi/requests@2.25.0?extra=1", // the same package again
		"pkg:npm/lodash@4.17.21",
		"pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12",
		"pkg:apk/alpine/busybox@1.36.1-r5",
		"pkg:pypi/django",
		"not a purl",
	})
	if result.Status != StatusAffected {
		t.Fatalf("status = %q (%s)", result.Status, result.Reason)
	}
	if result.PackagesFound != 5 || result.Checked != 2 || result.Affected != 1 || result.NotCheckedCount != 2 || result.NoVersion != 1 {
		t.Errorf("found %d, checked %d, affected %d, not checked %d, no version %d", result.PackagesFound, result.Checked, result.Affected, result.NotCheckedCount, result.NoVersion)
	}
	if result.NotChecked["deb"] != 1 || result.NotChecked["apk"] != 1 {
		t.Errorf("notChecked = %v", result.NotChecked)
	}
	if !strings.Contains(result.Reason, "3 of the 5 packages were not checked") {
		t.Errorf("the reason must say what was not checked: %q", result.Reason)
	}

	requests := result.Packages[0]
	// GHSA and PYSEC describe one flaw, so three records make two advisories.
	if requests.Name != "requests" || requests.TotalAdvisories != 2 {
		t.Fatalf("requests = %+v", requests)
	}
	merged := requests.Advisories[0]
	if merged.ID != "GHSA-aaaa-bbbb-cccc" || !merged.Exploited || merged.Priority != "urgent" || len(merged.PublicExploits) != 1 {
		t.Errorf("the merged advisory should be exploited, urgent and carry the scanner template: %+v", merged)
	}
	if strings.Join(merged.FixedIn, ",") != "2.31.0" {
		t.Errorf("fixedIn = %v", merged.FixedIn)
	}
	if result.Unranked != 0 || result.Counts.Urgent != 1 || result.Counts.Normal != 1 {
		t.Errorf("unranked = %d, counts = %+v", result.Unranked, result.Counts)
	}
}

func TestCheckPackagesIsOnlyCleanWhenEverythingWasChecked(t *testing.T) {
	f := &fake{t: t}
	client := f.client()
	if clean := client.CheckPackages(context.Background(), []string{"pkg:npm/lodash@4.17.21", "pkg:cargo/serde@1.0.200"}); clean.Status != StatusNoKnown {
		t.Errorf("all checked and clean: status = %q (%s)", clean.Status, clean.Reason)
	}
	mixed := client.CheckPackages(context.Background(), []string{"pkg:npm/lodash@4.17.21", "pkg:deb/debian/openssl@3.0.11"})
	if mixed.Status != StatusUnknown || !strings.Contains(mixed.Reason, "Do not treat this as safe") {
		t.Errorf("an unchecked OS package must keep the answer from being clean: %q (%s)", mixed.Status, mixed.Reason)
	}
	if none := client.CheckPackages(context.Background(), []string{"nothing here"}); none.Status != StatusUnknown {
		t.Errorf("no packages at all: status = %q", none.Status)
	}

	down := &fake{t: t, osvDown: true}
	offline := down.client()
	offline.RetryDelays = nil
	if failed := offline.CheckPackages(context.Background(), []string{"pkg:npm/lodash@4.17.21"}); failed.Status != StatusUnknown {
		t.Errorf("database down: status = %q", failed.Status)
	}
}
