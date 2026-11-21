package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPOptions configure the Streamable HTTP transport.
type HTTPOptions struct {
	// Token, when set, must be presented by every MCP request as
	// "Authorization: Bearer <token>". When empty there is no authentication,
	// and the server must only be reachable by callers you trust.
	Token string
	// JSON answers each request with a single application/json body instead
	// of a text/event-stream. Both are valid Streamable HTTP; the stream is
	// the default, and plain JSON suits proxies that buffer responses.
	JSON   bool
	Logger *slog.Logger
}

// NewHTTPHandler serves the MCP server over Streamable HTTP as the
// 2026-07-28 revision describes it: one endpoint at /mcp that accepts POST,
// no sessions, and requests from other browser origins refused. /healthz
// answers 200 for load balancers and container probes, and needs no token.
func NewHTTPHandler(mcpServer *mcp.Server, options HTTPOptions) http.Handler {
	var handler http.Handler = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: options.JSON, Logger: options.Logger},
	)
	if options.Token != "" {
		handler = requireToken(options.Token, handler)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", http.NewCrossOriginProtection().Handler(handler))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// requireToken rejects requests that do not carry the expected bearer token.
// Both sides are hashed first so that the comparison takes the same time
// whatever the length of what was sent.
func requireToken(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(presented))
		if !ok || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sec1-mcp"`)
			http.Error(w, "missing or wrong bearer token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
