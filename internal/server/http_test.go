package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bitop-dev/sec1-mcp/internal/catalog"
)

func httpServer(t *testing.T, options HTTPOptions) *httptest.Server {
	t.Helper()
	products, err := catalog.New()
	if err != nil {
		t.Fatal(err)
	}
	served := httptest.NewServer(NewHTTPHandler(New(Deps{Intel: offline(), Catalog: products}), options))
	t.Cleanup(served.Close)
	return served
}

// bearer adds a token to every request a client makes.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// resolveOverHTTP connects a real MCP client over Streamable HTTP and calls
// a tool, which exercises discovery, listing and a call end to end.
func resolveOverHTTP(t *testing.T, endpoint string, client *http.Client) (map[string]any, error) {
	t.Helper()
	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	if len(list.Tools) != 5 {
		t.Errorf("listed %d tools over HTTP, want 5", len(list.Tools))
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "resolve_component", Arguments: map[string]any{"image": "vllm/vllm-openai:v0.34.0"}})
	if err != nil {
		return nil, err
	}
	structured, _ := result.StructuredContent.(map[string]any)
	return structured, nil
}

func TestStreamableHTTPEndToEnd(t *testing.T) {
	for name, options := range map[string]HTTPOptions{"event stream": {}, "plain JSON": {JSON: true}} {
		t.Run(name, func(t *testing.T) {
			served := httpServer(t, options)
			structured, err := resolveOverHTTP(t, served.URL+"/mcp", nil)
			if err != nil {
				t.Fatal(err)
			}
			component, _ := structured["component"].(map[string]any)
			if component["name"] != "vLLM" || component["version"] != "0.34.0" {
				t.Errorf("component = %v", component)
			}
		})
	}
}

func TestHTTPResponseKinds(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	post := func(served *httptest.Server, headers map[string]string) *http.Response {
		request, _ := http.NewRequest(http.MethodPost, served.URL+"/mcp", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", "2026-07-28")
		request.Header.Set("Mcp-Method", "tools/list")
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		return response
	}

	stream := post(httpServer(t, HTTPOptions{}), nil)
	if stream.StatusCode != http.StatusOK || !strings.HasPrefix(stream.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("default response: %d %q, want 200 text/event-stream", stream.StatusCode, stream.Header.Get("Content-Type"))
	}
	if stream.Header.Get("Mcp-Session-Id") != "" {
		t.Error("the server must not mint a session id")
	}

	plain := post(httpServer(t, HTTPOptions{JSON: true}), nil)
	if plain.StatusCode != http.StatusOK || !strings.HasPrefix(plain.Header.Get("Content-Type"), "application/json") {
		t.Errorf("JSON response: %d %q, want 200 application/json", plain.StatusCode, plain.Header.Get("Content-Type"))
	}

	crossOrigin := post(httpServer(t, HTTPOptions{}), map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
	if crossOrigin.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin request: %d, want 403", crossOrigin.StatusCode)
	}
}

func TestHTTPGetIsNotAllowedAndHealthIsOpen(t *testing.T) {
	served := httpServer(t, HTTPOptions{Token: "s3cret"})
	get := func(path string) int {
		response, err := http.Get(served.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if status := get("/healthz"); status != http.StatusOK {
		t.Errorf("/healthz = %d, want 200 without a token", status)
	}
	if status := get("/mcp"); status != http.StatusUnauthorized {
		t.Errorf("GET /mcp without a token = %d, want 401", status)
	}
}

func TestHTTPToken(t *testing.T) {
	served := httpServer(t, HTTPOptions{Token: "s3cret"})
	if _, err := resolveOverHTTP(t, served.URL+"/mcp", nil); err == nil {
		t.Error("a client with no token should be refused")
	}
	if _, err := resolveOverHTTP(t, served.URL+"/mcp", &http.Client{Transport: bearer{"wrong"}}); err == nil {
		t.Error("a client with the wrong token should be refused")
	}
	if _, err := resolveOverHTTP(t, served.URL+"/mcp", &http.Client{Transport: bearer{"s3cret"}}); err != nil {
		t.Errorf("a client with the right token was refused: %v", err)
	}
}
