package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bitop-dev/sec1-mcp/internal/catalog"
	"github.com/bitop-dev/sec1-mcp/internal/metrics"
)

// tokens builds a token set from a shared token and the contents of a token
// file, either of which may be empty.
func tokens(t *testing.T, shared, file string) *Tokens {
	t.Helper()
	path := ""
	if file != "" {
		path = filepath.Join(t.TempDir(), "tokens")
		if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set, err := NewTokens(shared, path)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

const teamTokens = "# issued 2026-11\nplatform  platform-token-0123456789\ndata-science data-science-token-abcdef\n"

// service starts the HTTP handler with a log and a metrics registry the
// test can read.
func service(t *testing.T, options HTTPOptions) (url string, log *bytes.Buffer, registry *metrics.Registry) {
	t.Helper()
	products, err := catalog.New("")
	if err != nil {
		t.Fatal(err)
	}
	log, registry = &bytes.Buffer{}, metrics.New()
	logger := slog.New(slog.NewJSONHandler(log, nil))
	options.Logger, options.Metrics = logger, registry
	served := httptest.NewServer(NewHTTPHandler(New(Deps{Intel: offline(), Catalog: products, Logger: logger, Metrics: registry}), options))
	t.Cleanup(served.Close)
	return served.URL + "/mcp", log, registry
}

func resolveAs(t *testing.T, endpoint, token string) error {
	t.Helper()
	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &http.Client{Transport: bearer{token}}, MaxRetries: -1, DisableStandaloneSSE: true}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "resolve_component", Arguments: map[string]any{"name": "LiteLLM", "version": "1.106.6"}})
	return err
}

func TestNamedTokensIdentifyTheCallerInTheAuditLog(t *testing.T) {
	endpoint, log, registry := service(t, HTTPOptions{Tokens: tokens(t, "", teamTokens)})

	if err := resolveAs(t, endpoint, "data-science-token-abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := resolveAs(t, endpoint, "not-a-token-anyone-was-given"); err == nil {
		t.Error("an unknown token should be refused")
	}

	entries := log.String()
	if !strings.Contains(entries, `"client":"data-science"`) || !strings.Contains(entries, `"tool":"resolve_component"`) || !strings.Contains(entries, `"outcome":"ok"`) {
		t.Errorf("the audit log should name the team, the tool and the outcome:\n%s", entries)
	}
	// What a team looks up says what it runs, so the log must not hold it;
	// nor may it hold the token.
	for _, secret := range []string{"LiteLLM", "1.106.6", "data-science-token-abcdef"} {
		if strings.Contains(entries, secret) {
			t.Errorf("the audit log must not contain %q:\n%s", secret, entries)
		}
	}

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	text := recorder.Body.String()
	for _, want := range []string{
		`sec1_tool_calls_total{tool="resolve_component",outcome="ok"} 1`,
		`sec1_tool_duration_seconds_count{tool="resolve_component"} 1`,
		`sec1_http_requests_total{code="401"}`,
		`sec1_http_requests_total{code="200"}`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics are missing %q:\n%s", want, text)
		}
	}
}

func TestSharedAndNamedTokensWorkTogether(t *testing.T) {
	set := tokens(t, "the-one-shared-token-xyz", teamTokens)
	cases := map[string]string{
		"the-one-shared-token-xyz":   "shared",
		"platform-token-0123456789":  "platform",
		"data-science-token-abcdef":  "data-science",
		"platform-token-012345678":   "",
		"":                           "",
		"platform-token-0123456789 ": "",
	}
	for presented, want := range cases {
		if name, ok := set.Lookup(presented); name != want || ok != (want != "") {
			t.Errorf("Lookup(%q) = %q, %v; want %q", presented, name, ok, want)
		}
	}
	if !set.Required() || (&Tokens{}).Required() || (*Tokens)(nil).Required() {
		t.Error("tokens are required exactly when some are configured")
	}
}

func TestTokenFileIsValidatedWithoutEchoingSecrets(t *testing.T) {
	cases := map[string]string{
		"a token with no name": "just-one-field-here-000000\n",
		"too many fields":      "team token-0123456789abcdef extra\n",
		"a short token":        "team short\n",
		"a reserved name":      "shared token-0123456789abcdef\n",
		"a bad name":           "team/one token-0123456789abcdef\n",
		"a name used twice":    "team token-0123456789abcdef\nteam token-fedcba9876543210\n",
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "tokens")
		_ = os.WriteFile(path, []byte(content), 0o600)
		_, err := NewTokens("", path)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), "line") || strings.Contains(err.Error(), "0123456789abcdef") {
			t.Errorf("%s: the error should name the line and never show a token: %v", name, err)
		}
	}
	if _, err := NewTokens("", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing token file should stop the server at start-up")
	}
}

func TestTokenFileIsRereadWhenItChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	_ = os.WriteFile(path, []byte("platform platform-token-0123456789\n"), 0o600)
	set, err := NewTokens("", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Lookup("platform-token-0123456789"); !ok {
		t.Fatal("the token should work before the change")
	}

	// Revoke the token and issue another; make the change look later, and
	// the last check older, than they are.
	_ = os.WriteFile(path, []byte("platform platform-token-rotated-9876\n"), 0o600)
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, later, later)
	set.checked = time.Now().Add(-time.Hour)

	if _, ok := set.Lookup("platform-token-0123456789"); ok {
		t.Error("the revoked token still works")
	}
	if name, ok := set.Lookup("platform-token-rotated-9876"); !ok || name != "platform" {
		t.Error("the new token does not work")
	}

	// A bad edit must not lock everyone out.
	_ = os.WriteFile(path, []byte("this is not valid\n"), 0o600)
	evenLater := later.Add(time.Minute)
	_ = os.Chtimes(path, evenLater, evenLater)
	set.checked = time.Now().Add(-time.Hour)
	if _, ok := set.Lookup("platform-token-rotated-9876"); !ok {
		t.Error("an invalid file should leave the previous tokens in force")
	}
}

func TestEachClientHasItsOwnRateLimit(t *testing.T) {
	endpoint, _, registry := service(t, HTTPOptions{Tokens: tokens(t, "", teamTokens), RatePerMinute: 3})
	post := func(token string) *http.Response {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
		request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", "2026-07-28")
		request.Header.Set("Mcp-Method", "tools/list")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response
	}
	for i := 1; i <= 3; i++ {
		if response := post("platform-token-0123456789"); response.StatusCode != http.StatusOK {
			t.Fatalf("request %d within the limit: status %d", i, response.StatusCode)
		}
	}
	limited := post("platform-token-0123456789")
	if limited.StatusCode != http.StatusTooManyRequests || limited.Header.Get("Retry-After") == "" {
		t.Errorf("the fourth request: status %d, Retry-After %q; want 429 with a Retry-After", limited.StatusCode, limited.Header.Get("Retry-After"))
	}
	// One team using up its allowance must not slow another.
	if response := post("data-science-token-abcdef"); response.StatusCode != http.StatusOK {
		t.Errorf("another client was limited too: status %d", response.StatusCode)
	}
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(recorder.Body.String(), `sec1_rate_limited_total{client="platform"} 1`) {
		t.Errorf("the rate-limit metric should name the client:\n%s", recorder.Body.String())
	}
}

func TestLimiterRefills(t *testing.T) {
	l := newLimiter(60) // one a second
	for i := 0; i < 60; i++ {
		if _, ok := l.allow("a"); !ok {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	wait, ok := l.allow("a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("after the burst: ok = %v, wait = %v; want refused, under a second", ok, wait)
	}
	l.buckets["a"].at = time.Now().Add(-2 * time.Second)
	if _, ok := l.allow("a"); !ok {
		t.Error("two seconds later a request should be allowed again")
	}
	if _, ok := newLimiter(0).allow("a"); !ok {
		t.Error("a limit of zero means no limit")
	}
}
