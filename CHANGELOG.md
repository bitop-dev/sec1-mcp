# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Running as a service several teams share:
  - `SEC1_HTTP_TOKEN_FILE`: a file of named bearer tokens, one per team,
    re-read when it changes so a team can be added or revoked without a
    restart.
  - `SEC1_HTTP_RATE`: a request limit per team, so one cannot starve the
    others.
  - An audit log line per tool call with the team's name, the tool and the
    outcome, and never what was looked up. `-log-format json` for log
    collectors.
  - `SEC1_METRICS_ADDR`: Prometheus metrics on a listener of their own.
  - `deploy/kubernetes.yaml` and a guide, `docs/shared-service.md`.

### Fixed

- The in-memory cache grew without limit in a long-running server. It now
  holds at most 128 MB, most recently used first, and disk cache files older
  than two days are deleted.
- HTTP request bodies are limited to 8 MB.

## [0.2.0] - 2026-11-22

### Added

- `check_sbom`: checks the packages inside an image from a software bill of
  materials or scanner report (CycloneDX, SPDX, Syft, Trivy), or from a
  list of package URLs. Packages from eleven language registries are checked
  by exact version. Operating system packages are counted and reported as
  not checked, and keep the answer from being reported as clean.
- `check_images`: checks up to 500 container images in one call, given as a
  list or as raw `kubectl` output. Images that are the same product at the
  same version share one check; unrecognised images are listed and not
  checked.
- `vendorNotices` on answers: recent entries from the vendor's own security
  feed that may concern the version. GitLab's patch-release feed is the
  first in the catalog.
- Three prompts: `audit_cluster_images`, `plan_upgrade` and
  `triage_advisory`.
- The resource `sec1://catalog`, listing the recognised products.
- Catalog fields `feeds` and `tagPrefix`.
- ingress-nginx is now looked up as a Go module, and its latest release is
  found from the controller's own tags.

## [0.1.1] - 2026-11-21

### Added

- `support` on every answer: whether the version's release line still
  receives fixes, when it ends or ended, and the newest release on that
  line. An ended line is also stated in `reason`.
- `publicExploits` on advisories, from the nuclei-templates and Metasploit
  indexes. A public scanner template or exploit module raises a normal
  advisory to high.
- `workaround` on advisories, taken from the advisory's own workaround
  section.
- A `since` date on `check_component` and `check_components`, to list only
  what is new. `status` still describes everything that applies.
- Go-based catalog products (Kubernetes, Grafana, Traefik, Argo CD, Harbor,
  cert-manager, Vault and Ollama) are now also looked up as Go modules in
  OSV.
- Catalog fields `lifecycle`, `otherCpes` and `otherPackages`.
- The latest release for PostgreSQL and nginx, from lifecycle data.

### Fixed

- NVD lookups missed CVEs recorded against every version of a product with
  no version range. Kubernetes 1.28.4 was reported as having no known
  advisories; it now reports ten.
- NVD lookups listed CVEs where the product is only the platform some other
  vulnerable software runs on.
- nginx is searched under both names NVD files it under.
- Go pseudo-versions, which name a commit and not a release, are no longer
  offered as fixed versions.

## [0.1.0] - 2026-11-21

The first release.

### Added

- Six read-only tools: `check_component`, `check_components`,
  `suggest_version`, `get_advisory`, `resolve_component` and
  `find_identifiers`.
- `find_identifiers` searches PyPI, npm, GitHub and NVD for a product the
  catalog does not know and returns candidates to confirm. It applies none.
- A catalog file of your own (`-catalog`, `SEC1_CATALOG`), validated at
  start-up, that adds products or replaces built-in ones.
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
- A built-in catalog of 21 products, each identifier checked against
  GitHub, NVD and the image registries: LiteLLM, vLLM, GitLab, Onyx,
  PostgreSQL, Redis, Valkey, nginx, ingress-nginx, Kubernetes, Traefik,
  cert-manager, Argo CD, Harbor, Grafana, Prometheus, Elasticsearch,
  Keycloak, Vault, Ollama and Open WebUI.
- Handling for the free-text version ranges that project advisories use:
  hyphen ranges, several ranges with no separator, start-only ranges, and
  fixes backported to more than one release line.
- Name-only matches from the exploited list are dropped when the upstream
  repository, OSV or NVD shows the version is not affected.
- stdio and Streamable HTTP transports, following MCP specification revision
  2026-07-28. The HTTP transport has optional bearer-token authentication, a
  `/healthz` endpoint, and a plain-JSON response mode.
- Response caching in memory and on disk, and request pacing for NVD.
- A container image, built for `linux/amd64` and `linux/arm64`.

- Official container images, such as `postgres`, match only under their own
  name or `library/`, so another publisher's image of the same name is not
  mistaken for them.

### Security

- Every tool input that reaches a request URL is validated against a
  pattern, and the hosts the server calls are fixed, so a caller cannot make
  it fetch an arbitrary address.
- Advisory text from third parties is stripped of control characters, cut to
  length, and labelled as untrusted in the tool schemas.
- Credentials are read from the environment only and are never logged or
  cached.

[Unreleased]: https://github.com/bitop-dev/sec1-mcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/bitop-dev/sec1-mcp/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/bitop-dev/sec1-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bitop-dev/sec1-mcp/releases/tag/v0.1.0
