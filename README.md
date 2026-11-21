# sec1-mcp

An MCP server that tells an AI agent which known security advisories apply to
the software you run or are about to deploy.

It is a lookup tool: it holds no inventory and needs no configuration. An
agent that can see your systems (for example, one listing the container
images in a Kubernetes cluster) passes what it finds to this server and gets
back, for each item: whether advisories apply to that version, which are being
exploited, what version fixes them, and how sure the answer is.

It follows the MCP specification revision **2026-07-28**, through the official
Go SDK.

## Build and run

Requires Go 1.26 or later.

```sh
git clone https://github.com/bitop-dev/sec1-mcp.git
cd sec1-mcp
go build -o bin/sec1-mcp .
go test ./...
```

Or install the binary straight into your Go bin directory:

```sh
go install github.com/bitop-dev/sec1-mcp@latest
```

The server speaks MCP over stdin and stdout by default, which is how an agent
on the same machine starts it:

```sh
bin/sec1-mcp
```

| Flag | Meaning |
| --- | --- |
| `-http <addr>` | Serve Streamable HTTP at `http://<addr>/mcp` instead of stdio. |
| `-cache-dir <dir>` | Where lookups are cached. Defaults to your user cache directory; `""` keeps the cache in memory. |
| `-version` | Print the version. |

Two optional environment variables raise rate limits: `GITHUB_TOKEN` (GitHub
allows 60 requests an hour without one) and `NVD_API_KEY` (NVD allows one
request every six seconds without one). They are read from the environment
only, and are never logged or cached.

### Connecting an agent

Most MCP clients take a command to start. The entry looks like this, with
absolute paths:

```json
{
  "mcpServers": {
    "sec1": {
      "command": "/path/to/sec1-mcp/bin/sec1-mcp"
    }
  }
}
```

### HTTP mode

`-http 127.0.0.1:8080` serves one endpoint, `/mcp`, with no sessions, and
refuses requests from other browser origins.

**There is no authentication.** Keep it bound to localhost, or put it behind
a proxy that authenticates callers before anything else can reach it.

## Tools

All five are read-only.

| Tool | Use it to |
| --- | --- |
| `check_component` | Get the advisories that apply to one component at one version. |
| `check_components` | Check up to 25 components at once and get a summary of each. |
| `suggest_version` | Find the smallest upgrade that fixes what affects the running version. |
| `get_advisory` | Get the full record for one CVE, GHSA or other advisory id. |
| `resolve_component` | See how a name or image is identified, without any lookups. |

### Identifying a component

A component can be given three ways:

- **By name:** `{"name": "LiteLLM", "version": "1.106.6"}`.
- **By container image:** `{"image": "ghcr.io/berriai/litellm:main-v1.106.6-stable"}`.
  The product comes from the image repository and the version from the tag.
  A registry mirror in front of the name is fine.
- **By explicit identifiers:** `ecosystem` and `package` (a registry package),
  `repo` (a GitHub repository), or `cpe` (NVD's `vendor:product`). These work
  for software the catalog does not know.

### Reading an answer

Every answer has a `status`:

| Status | Meaning |
| --- | --- |
| `affected` | Advisories apply to this version. |
| `possibly_affected` | An exploited vulnerability names the product, but the version could not be checked against it. |
| `no_known_advisories` | Every applicable source answered and none lists this version. |
| `version_needed` | Advisories exist for the product; without a version it cannot say which apply. |
| `unknown` | It could not be determined. **This never means safe.** |

`unknown` is what you get when a source could not be reached, when a call ran
out of time, or when the product is not recognised and no identifiers were
given. The `coverage` list says what each source did: `checked`, `skipped`
(with the reason) or `failed`.

Priorities (`urgent`, `high`, `normal`) come from fixed rules, and each
advisory's `rationale` names the rule that applied: exploited in the wild or
critical severity is urgent; high severity is high; an EPSS score of 10% or
more raises a normal advisory to high.

## What it covers, and what it does not

Sources: OSV, the upstream GitHub repository's security advisories, NVD,
CISA's Known Exploited Vulnerabilities catalog, and EPSS. The latest release
comes from PyPI, npm, GitHub releases or GitLab tags.

- **It recognises only products in its catalog**, plus anything you identify
  explicitly. The catalog is `internal/catalog/catalog.yaml`; the comments in
  it explain how to add a product. Rebuild after editing it.
- **It reports each product's own advisories.** It does not scan the
  libraries or operating system packages inside a container image. Use an
  image scanner for that.
- **A tag such as `latest`, or a bare digest, carries no version**, so the
  answer is `version_needed`.
- **Advisory text is untrusted.** Titles, summaries and reference URLs are
  written by third parties. The server strips control characters, cuts them
  to length, and labels them as untrusted in the tool schemas; the agent
  reading them must still treat them as data.
- **Backported fixes are interpreted.** Some projects list one open-ended
  range per release line (`< 1.106.9`, `< 1.108.6`). The server treats a
  version as fixed when the same advisory publishes a fix on that version's
  release line at or below it. See `backported` in `internal/intel/sources.go`.

## Layout

```
main.go                    flags, stdio and HTTP transports
internal/server            the tools, input validation, output shapes
internal/intel             sources, merging, priority rules, cache, NVD pacing
internal/catalog           product names and image names to identifiers
internal/version           version comparison and ranges
```

`SEC1_LIVE=1 go test ./internal/server -run TestLive -v` runs the tools
against the real services.
