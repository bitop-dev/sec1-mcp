// Command sec1-mcp is an MCP server that reports known security advisories
// for the software you run, by product name, version or container image.
//
// By default it speaks MCP over stdin and stdout, which is how an agent on
// the same machine starts it. With -http it serves Streamable HTTP instead,
// for agents elsewhere on the network.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bitop-dev/sec1-mcp/internal/catalog"
	"github.com/bitop-dev/sec1-mcp/internal/intel"
	"github.com/bitop-dev/sec1-mcp/internal/metrics"
	"github.com/bitop-dev/sec1-mcp/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sec1-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	catalogPath := flag.String("catalog", os.Getenv("SEC1_CATALOG"),
		"path to a catalog file of your own products, added to the built-in catalog (also $SEC1_CATALOG)")
	httpAddr := flag.String("http", os.Getenv("SEC1_HTTP_ADDR"),
		"serve Streamable HTTP on this address, such as 127.0.0.1:8080, instead of stdio (also $SEC1_HTTP_ADDR)")
	httpJSON := flag.Bool("http-json", false,
		"answer HTTP requests with plain JSON bodies instead of event streams")
	tokenFile := flag.String("http-token-file", os.Getenv("SEC1_HTTP_TOKEN_FILE"),
		"file of named bearer tokens, one \"name token\" per line, for telling callers apart (also $SEC1_HTTP_TOKEN_FILE)")
	httpRate := flag.Int("http-rate", envInt("SEC1_HTTP_RATE"),
		"most requests each client may make in a minute over HTTP; 0 for no limit (also $SEC1_HTTP_RATE)")
	metricsAddr := flag.String("metrics", os.Getenv("SEC1_METRICS_ADDR"),
		"serve Prometheus metrics at http://<addr>/metrics, on a listener of its own (also $SEC1_METRICS_ADDR)")
	logFormat := flag.String("log-format", "text", "log format: text or json")
	cacheDir := flag.String("cache-dir", defaultCacheDir(),
		`directory for cached lookups; "" keeps the cache in memory only`)
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(server.BuildVersion())
		return nil
	}

	// stdout carries the protocol on stdio, so every log line goes to stderr.
	var logger *slog.Logger
	switch *logFormat {
	case "text":
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	case "json":
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	default:
		return fmt.Errorf("-log-format must be text or json, not %q", *logFormat)
	}

	products, err := catalog.New(*catalogPath)
	if err != nil {
		return err
	}
	var registry *metrics.Registry
	if *metricsAddr != "" {
		registry = metrics.New()
	}
	lookups := intel.NewClient(*cacheDir)
	lookups.Observe = func(source, outcome string) {
		registry.Inc("sec1_upstream_requests_total", "Lookups sent to each advisory service, by outcome: cached, ok or error.", "source", source, "outcome", outcome)
	}
	mcpServer := server.New(server.Deps{Intel: lookups, Catalog: products, Logger: logger, Metrics: registry})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpAddr == "" {
		err := mcpServer.Run(ctx, &mcp.StdioTransport{})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	// Tokens come from the environment or a file, never from a flag, so
	// that they do not show up in a process listing.
	tokens, err := server.NewTokens(os.Getenv("SEC1_HTTP_TOKEN"), *tokenFile)
	if err != nil {
		return err
	}
	if *httpRate < 0 {
		return errors.New("-http-rate must not be negative")
	}
	if *metricsAddr != "" {
		go serveMetrics(ctx, *metricsAddr, registry, logger)
	}
	return serveHTTP(ctx, *httpAddr, mcpServer, server.HTTPOptions{
		Tokens: tokens, JSON: *httpJSON, RatePerMinute: *httpRate, Metrics: registry, Logger: logger,
	})
}

// serveHTTP runs the Streamable HTTP transport until ctx is cancelled.
func serveHTTP(ctx context.Context, addr string, mcpServer *mcp.Server, options server.HTTPOptions) error {
	logger := options.Logger
	if !options.Tokens.Required() {
		logger.Warn("HTTP transport has no authentication: set SEC1_HTTP_TOKEN or SEC1_HTTP_TOKEN_FILE, or make sure only trusted callers can reach it")
	}
	httpServer := &http.Server{Addr: addr, Handler: server.NewHTTPHandler(mcpServer, options), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	logger.Info("serving MCP over Streamable HTTP", "endpoint", "http://"+addr+"/mcp",
		"authenticated", options.Tokens.Required(), "named_tokens", options.Tokens.Names(), "rate_per_minute", options.RatePerMinute)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serveMetrics exposes the metrics on a listener of their own, so that they
// can be kept off whatever exposes the MCP endpoint. They carry tool names,
// client names and request counts, and need no token.
func serveMetrics(ctx context.Context, addr string, registry *metrics.Registry, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", registry.Handler())
	metricsServer := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metricsServer.Shutdown(shutdown)
	}()
	logger.Info("serving metrics", "endpoint", "http://"+addr+"/metrics")
	if err := metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("metrics listener stopped", "error", err)
	}
}

// envInt reads a whole number from the environment, or 0 when it is unset
// or not a number.
func envInt(name string) int {
	value, _ := strconv.Atoi(os.Getenv(name))
	return value
}

func defaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "sec1-mcp")
}
