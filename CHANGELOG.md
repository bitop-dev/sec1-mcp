# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first version. Nothing has been tagged yet; these entries become 0.1.0.

### Added

- Five read-only tools: `check_component`, `check_components`,
  `suggest_version`, `get_advisory` and `resolve_component`.
- Components can be identified by product name, by container image
  reference (the product comes from the repository, the version from the
  tag), or by explicit identifiers: registry package, GitHub repository or
  NVD product.
- Advisory sources: OSV, upstream GitHub repository security advisories,
  NVD, CISA's Known Exploited Vulnerabilities catalog, and EPSS scores.
- Latest-release lookup from PyPI, npm, GitHub releases and GitLab tags.
- A `status` on every answer, where `unknown` is returned whenever a source
  fails, a call runs out of time, or a product is not recognised, and a
  `coverage` list saying what each source did.
- Upgrade suggestions that re-check the suggested version against every
  source before calling it clean.
- A built-in catalog covering LiteLLM, vLLM, GitLab and Onyx.
- stdio and Streamable HTTP transports, following MCP specification revision
  2026-07-28. The HTTP transport has optional bearer-token authentication, a
  `/healthz` endpoint, and a plain-JSON response mode.
- Response caching in memory and on disk, and request pacing for NVD.
- A container image, built for `linux/amd64` and `linux/arm64`.

### Security

- Every tool input that reaches a request URL is validated against a
  pattern, and the hosts the server calls are fixed, so a caller cannot make
  it fetch an arbitrary address.
- Advisory text from third parties is stripped of control characters, cut to
  length, and labelled as untrusted in the tool schemas.
- Credentials are read from the environment only and are never logged or
  cached.
