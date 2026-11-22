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
	catalogPath := flag.String("catalog", os.Getenv("SEC1_CATALOG"),
		"path to a catalog file of your own products, added to the built-in catalog (also $SEC1_CATALOG)")
	httpAddr := flag.String("http", os.Getenv("SEC1_HTTP_ADDR"),
		"serve Streamable HTTP on this address, such as 127.0.0.1:8080, instead of stdio (also $SEC1_HTTP_ADDR)")
	httpJSON := flag.Bool("http-json", false,
		"answer HTTP requests with plain JSON bodies instead of event streams")
	cacheDir := flag.String("cache-dir", defaultCacheDir(),
		`directory for cached lookups; "" keeps the cache in memory only`)
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(server.BuildVersion())
		return nil
	}

	// stdout carries the protocol on stdio, so every log line goes to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	products, err := catalog.New(*catalogPath)
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
	// The token comes from the environment only, so that it never shows up
	// in a process listing.
	return serveHTTP(ctx, *httpAddr, mcpServer, server.HTTPOptions{
		Token: os.Getenv("SEC1_HTTP_TOKEN"), JSON: *httpJSON, Logger: logger,
	})
}

// serveHTTP runs the Streamable HTTP transport until ctx is cancelled.
func serveHTTP(ctx context.Context, addr string, mcpServer *mcp.Server, options server.HTTPOptions) error {
	logger := options.Logger
	if options.Token == "" {
		logger.Warn("HTTP transport has no authentication: set SEC1_HTTP_TOKEN, or make sure only trusted callers can reach it")
	}
	httpServer := &http.Server{Addr: addr, Handler: server.NewHTTPHandler(mcpServer, options), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	logger.Info("serving MCP over Streamable HTTP", "endpoint", "http://"+addr+"/mcp", "authenticated", options.Token != "")
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
