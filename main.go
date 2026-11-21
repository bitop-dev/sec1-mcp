// Command sec1-mcp is an MCP server that reports known security advisories
// for the software you run, by product name, version or container image.
//
// By default it speaks MCP over stdin and stdout, which is how an agent on
// the same machine starts it. With -http it serves Streamable HTTP instead.
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
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bitop-dev/sec1-mcp/internal/catalog"
	"github.com/bitop-dev/sec1-mcp/internal/intel"
	"github.com/bitop-dev/sec1-mcp/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sec1-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	httpAddr := flag.String("http", "",
		"serve Streamable HTTP on this address, such as 127.0.0.1:8080, instead of stdio")
	cacheDir := flag.String("cache-dir", defaultCacheDir(),
		`directory for cached lookups; "" keeps the cache in memory only`)
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(server.Version)
		return nil
	}

	// stdout carries the protocol on stdio, so every log line goes to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	products, err := catalog.New()
	if err != nil {
		return err
	}
	mcpServer := server.New(server.Deps{Intel: intel.NewClient(*cacheDir), Catalog: products, Logger: logger})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpAddr == "" {
		err := mcpServer.Run(ctx, &mcp.StdioTransport{})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return serveHTTP(ctx, *httpAddr, mcpServer, logger)
}

// serveHTTP runs the Streamable HTTP transport the way the 2026-07-28
// revision describes it: one endpoint, no sessions, and requests from other
// browser origins refused.
//
// There is no authentication here. Bind it to localhost, or put it behind a
// proxy that authenticates callers, before letting anything else reach it.
func serveHTTP(ctx context.Context, addr string, mcpServer *mcp.Server, logger *slog.Logger) error {
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, Logger: logger},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", http.NewCrossOriginProtection().Handler(handler))
	httpServer := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	logger.Info("serving MCP over HTTP", "url", "http://"+addr+"/mcp")
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func defaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "sec1-mcp")
}
