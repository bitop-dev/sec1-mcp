package intel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fake stands in for every advisory service. Each handler is small enough to
// read as the scenario it sets up.
type fake struct {
	t        *testing.T
	osvDown  bool
	nvdCalls int
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
		if strings.HasSuffix(r.URL.Path, "/GHSA-aaaa-bbbb-cccc") {
			reply(w, map[string]any{"id": "GHSA-aaaa-bbbb-cccc", "aliases": []string{"CVE-2026-1111"}, "summary": "Secret exfiltration", "details": "Long text."})
			return
		}
		http.NotFound(w, r)
	})

	// GitHub: one advisory whose range excludes 1.106.6, one that includes it.
	mux.HandleFunc("/github/repos/BerriAI/litellm/security-advisories", func(w http.ResponseWriter, r *http.Request) {
		reply(w, []map[string]any{
			{"ghsa_id": "GHSA-old0-old0-old0", "summary": "Old bug", "severity": "critical", "html_url": "https://example.invalid/old",
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
		f.nvdCalls++
		cves := []map[string]any{}
		if _, exploitedOnly := r.URL.Query()["hasKev"]; exploitedOnly {
			cves = append(cves, map[string]any{"cve": map[string]any{"id": "CVE-2026-2222"}})
		}
		reply(w, map[string]any{"totalResults": len(cves), "resultsPerPage": len(cves), "vulnerabilities": cves})
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
			OSV: server.URL + "/osv", GitHub: server.URL + "/github", NVD: server.URL + "/nvd",
			KEV: server.URL + "/kev", EPSS: server.URL + "/epss", PyPI: server.URL + "/pypi",
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
	first := f.nvdCalls
	client.Check(context.Background(), component)
	if first == 0 || f.nvdCalls != first {
		t.Errorf("NVD was called %d times, then %d; the second check should be served from cache", first, f.nvdCalls)
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

func TestBackportedFixClearsLaterLinesRange(t *testing.T) {
	text := func(s string) *string { return &s }
	item := githubAdvisory{GHSAID: "GHSA-test-test-test"}
	for _, entry := range [][2]string{{"< 1.106.9", "1.106.9"}, {"< 1.108.6", "1.108.6"}, {"< 1.110.0-rc.2", "1.110.0-rc.2"}} {
		item.Vulnerabilities = append(item.Vulnerabilities, struct {
			Range   *string `json:"vulnerable_version_range"`
			Patched *string `json:"patched_versions"`
		}{text(entry[0]), text(entry[1])})
	}
	cases := map[string]bool{
		"1.106.6":  true,  // below the fix on its own line
		"1.106.9":  false, // the fix itself
		"1.106.12": false, // later patch on a fixed line
		"1.107.0":  true,  // a line that never got the fix
		"1.108.5":  true,
		"1.110.2":  false,
	}
	for running, want := range cases {
		if _, applies := githubApplies(running, item); applies != want {
			t.Errorf("version %s: applies = %v, want %v", running, applies, want)
		}
	}

	// A range with a lower bound is taken as written, even when an earlier
	// entry published a fix on the same line.
	item.Vulnerabilities[1].Range = text(">= 1.106.10, < 1.108.6")
	if _, applies := githubApplies("1.106.12", item); !applies {
		t.Error("a bounded range that includes the version must still apply")
	}
}
