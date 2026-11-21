# Roadmap

sec1-mcp is a lookup tool: an agent passes in software, and gets back which
known advisories apply. The roadmap keeps it that. It does not grow an
inventory, a scheduler, alerting or a dashboard.

Stages are in order. Stage 1 comes first because every later stage
multiplies whatever inaccuracy is left in the answers.

## 1. Trustworthy answers

Done, apart from the release:

- [x] Verify the catalog's image names against the registries.
- [x] Grow the catalog to the infrastructure most teams run. It now covers
  21 products.
- [x] Load a team's own catalog file at start-up, so adding a product does
  not need a rebuild.
- [x] Tighten lookups by GitHub repository alone: read the free-text ranges
  project advisories use, and drop name-only matches that the repository,
  OSV or NVD rules out.
- [x] `find_identifiers`, which proposes identifiers for a product the
  catalog does not know and applies none of them.
- [ ] **Release 0.1.0**, so there are versioned container images and a
  stable install target.

Still open here:

- Several NVD product names for one product, as nginx needs.
- A source for the latest release of PostgreSQL, nginx and ingress-nginx.

## 2. More signal in each answer

- **End-of-life status.** A version that is out of support gets no fixes,
  and no advisory says so.
- **Public exploit availability**, and a wider exploited-in-the-wild list
  than CISA's alone.
- **Vendor security feeds**, for products whose vendor announces fixes
  before the databases catch up.
- **Workarounds** from the advisory, as their own field, for when upgrading
  has to wait.
- **Recent advisories for a product since a given date**, so an agent can
  ask what is new without the server keeping any state.

## 3. Bigger inputs

- **Accept an SBOM or image-scanner output**, which covers what is inside an
  image without this project becoming a scanner.
- **Accept raw workload listings**, such as `kubectl` output, so the agent
  does not have to pull image references out itself.
- **Larger batches**, with progress reported while they run.

## 4. A better MCP citizen

- **Prompts** for the common workflows: audit a cluster, plan an upgrade,
  look into a CVE.
- **Resources** for the catalog and for single advisories.
- **OAuth authorization**, as the specification describes it, alongside the
  shared token.
- **An audit log and a metrics endpoint** for the HTTP transport.
- **A listing in the MCP registry.**

## Not planned

- Scanning container images or hosts.
- Keeping an inventory, watching it on a schedule, or sending alerts.
- Tools that change anything.
