# sec1-mcp

[![CI](https://github.com/bitop-dev/sec1-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/bitop-dev/sec1-mcp/actions/workflows/ci.yml)
[![Container](https://github.com/bitop-dev/sec1-mcp/actions/workflows/container.yml/badge.svg)](https://github.com/bitop-dev/sec1-mcp/actions/workflows/container.yml)

An MCP server that tells an AI agent which known security advisories apply to
the software you run or are about to deploy.

It is a lookup tool: it holds no inventory and needs no configuration. An
agent that can see your systems (for example, one listing the container
images in a Kubernetes cluster) passes what it finds to this server and gets
back, for each item: whether advisories apply to that version, which are being
exploited, what version fixes them, and how sure the answer is.

```json
{"image": "ghcr.io/berriai/litellm:main-v1.106.6-stable"}
```

```json
{
  "status": "affected",
  "reason": "2 advisories apply to version 1.106.6.",
  "latestVersion": "1.110.2",
  "versionStatus": "behind"
}
```

It follows the MCP specification revision **2026-07-28**, through the official
Go SDK, over stdio or Streamable HTTP.

## Quick start

With Go 1.26 or later:

```sh
go install github.com/bitop-dev/sec1-mcp@latest
```

Or build from a checkout:

```sh
git clone https://github.com/bitop-dev/sec1-mcp.git
cd sec1-mcp
go build -o bin/sec1-mcp .
```

Or use the container image:

```sh
docker run -i --rm ghcr.io/bitop-dev/sec1-mcp:latest
```

Then register it with your agent. For Claude Code:

```sh
claude mcp add sec1 -- /path/to/sec1-mcp/bin/sec1-mcp
```

For other clients, and for connecting over HTTP, see
[docs/agents.md](docs/agents.md).

## Tools

All six are read-only.

| Tool | Use it to |
| --- | --- |
| `check_component` | Get the advisories that apply to one component at one version. |
| `check_components` | Check up to 25 components at once and get a summary of each. |
| `suggest_version` | Find the smallest upgrade that fixes what affects the running version. |
| `get_advisory` | Get the full record for one CVE, GHSA or other advisory id. |
| `resolve_component` | See how a name or image is identified, without any lookups. |
| `find_identifiers` | Search for candidate identifiers for a product the catalog does not know. |

A component can be given by name (`LiteLLM`), by container image reference,
or by explicit identifiers: a registry package, a GitHub repository, or an
NVD product. The built-in catalog recognises about twenty common products by
name and image, and you can add your own with a catalog file. Anything else
is checked by passing identifiers.

Every answer has a `status`:

| Status | Meaning |
| --- | --- |
| `affected` | Advisories apply to this version. |
| `possibly_affected` | An exploited vulnerability names the product, but the version could not be checked against it. |
| `no_known_advisories` | Every applicable source answered and none lists this version. |
| `version_needed` | Advisories exist for the product; without a version it cannot say which apply. |
| `unknown` | It could not be determined. **This never means safe.** |

## Documentation

| Page | What it covers |
| --- | --- |
| [Using it from an agent](docs/agents.md) | Connecting, what to tell the agent, and worked workflows such as auditing a Kubernetes cluster. |
| [Tool reference](docs/tools.md) | Every tool's inputs and outputs, with real example answers. |
| [How it works](docs/how-it-works.md) | The sources, how answers are combined, the status and priority rules, caching and deadlines. |
| [Running the server](docs/deployment.md) | stdio and HTTP, authentication, the container image, and a Kubernetes example. |
| [The product catalog](docs/catalog.md) | How names and images are matched, and how to add a product. |

## What it covers, and what it does not

Sources: OSV, the upstream GitHub repository's security advisories, NVD,
CISA's Known Exploited Vulnerabilities catalog, and EPSS.

- **It reports each product's own advisories.** It does not scan the
  libraries or operating system packages inside a container image. Use an
  image scanner for that.
- **It does not guess.** A product outside the catalog is unrecognised until
  you give identifiers for it. `find_identifiers` suggests candidates, which
  someone must confirm.
- **Advisory text is untrusted.** Titles, summaries and reference URLs are
  written by third parties. The server cleans and labels them, and the agent
  reading them must still treat them as data.
- **The HTTP transport has no authentication unless you set a token.** See
  [docs/deployment.md](docs/deployment.md#authentication).

## Development

```sh
go vet ./...
go test -race ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are recorded in
[CHANGELOG.md](CHANGELOG.md), and security reports go through
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
