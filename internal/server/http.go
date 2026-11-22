package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bitop-dev/sec1-mcp/internal/metrics"
)

// maxRequestBytes bounds a request body. The largest legitimate one is a
// bill of materials passed to check_sbom.
const maxRequestBytes = 8 << 20

// HTTPOptions configure the Streamable HTTP transport.
type HTTPOptions struct {
	// Tokens says who may call. When it holds none, there is no
	// authentication, and the server must only be reachable by callers you
	// trust.
	Tokens *Tokens
	// JSON answers each request with a single application/json body instead
	// of a text/event-stream. Both are valid Streamable HTTP; the stream is
	// the default, and plain JSON suits proxies that buffer responses.
	JSON bool
	// RatePerMinute caps the requests each client may make in a minute.
	// Zero means no cap.
	RatePerMinute int
	Metrics       *metrics.Registry
	Logger        *slog.Logger
}

// NewHTTPHandler serves the MCP server over Streamable HTTP as the
// 2026-07-28 revision describes it: one endpoint at /mcp that accepts POST,
// no sessions, and requests from other browser origins refused. /healthz
// answers 200 for load balancers and container probes, and needs no token.
func NewHTTPHandler(mcpServer *mcp.Server, options HTTPOptions) http.Handler {
	var handler http.Handler = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: options.JSON, Logger: options.Logger, MaxRequestBodyBytes: maxRequestBytes},
	)
	handler = gate(options, handler)
	mux := http.NewServeMux()
	mux.Handle("/mcp", http.NewCrossOriginProtection().Handler(handler))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// gate decides whether a request may proceed and who it is from. It checks
// the bearer token, applies the caller's rate limit, records the outcome,
// and passes the caller's name on to the tools for the audit log.
func gate(options HTTPOptions, next http.Handler) http.Handler {
	limiter := newLimiter(options.RatePerMinute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			options.Metrics.Inc("sec1_http_requests_total", "HTTP requests to the MCP endpoint, by status code.", "code", strconv.Itoa(recorder.status))
		}()

		client := anonymous
		if options.Tokens.Required() {
			presented, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			name, ok := options.Tokens.Lookup(presented)
			if !ok {
				recorder.Header().Set("WWW-Authenticate", `Bearer realm="sec1-mcp"`)
				http.Error(recorder, "missing or wrong bearer token", http.StatusUnauthorized)
				return
			}
			client = name
		}
		if wait, ok := limiter.allow(client); !ok {
			options.Metrics.Inc("sec1_rate_limited_total", "Requests refused because a client exceeded its rate limit.", "client", client)
			recorder.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			http.Error(recorder, fmt.Sprintf("rate limit of %d requests a minute exceeded", options.RatePerMinute), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), clientKey{}, client)))
	})
}

// anonymous names the caller when the server has no tokens.
const anonymous = "anonymous"

type clientKey struct{}

// clientFrom returns who made the request: a token's name over HTTP, and
// "local" for stdio, where the only caller is the process that started the
// server.
func clientFrom(ctx context.Context) string {
	if name, ok := ctx.Value(clientKey{}).(string); ok {
		return name
	}
	return "local"
}

// statusRecorder notes the status code written, for the request metric. It
// keeps streaming working by passing Flush through.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// limiter is a token bucket per client: each may burst up to a minute's
// allowance, which then refills evenly.
type limiter struct {
	perMinute float64
	mu        sync.Mutex
	buckets   map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(perMinute int) *limiter {
	if perMinute <= 0 {
		return nil
	}
	return &limiter{perMinute: float64(perMinute), buckets: map[string]*bucket{}}
}

// allow reports whether the client may make a request now, and if not, how
// long until it may.
func (l *limiter) allow(client string) (wait time.Duration, ok bool) {
	if l == nil {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[client]
	if b == nil {
		b = &bucket{tokens: l.perMinute, at: now}
		l.buckets[client] = b
	}
	b.tokens = min(l.perMinute, b.tokens+now.Sub(b.at).Minutes()*l.perMinute)
	b.at = now
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) / l.perMinute * float64(time.Minute)), false
	}
	b.tokens--
	return 0, true
}
