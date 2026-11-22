# Roadmap

sec1-mcp is a lookup tool: an agent passes in software, and gets back which
known advisories apply. The roadmap keeps it that. It does not grow an
inventory, a scheduler, alerting or a dashboard.

Stages are in order. Stage 1 comes first because every later stage
multiplies whatever inaccuracy is left in the answers.

## 1. Trustworthy answers

Done, and released as 0.1.0:

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
- [x] Release 0.1.0, so there are versioned container images and a stable
  install target.

Follow-ups, also done:

- [x] Several NVD product names for one product, as nginx needs.
- [x] The latest release of PostgreSQL and nginx, from lifecycle data.

- [x] The latest release of ingress-nginx, from the controller's own tags.

## 2. More signal in each answer

- [x] End-of-life status. A version that is out of support gets no fixes,
  and no advisory says so.
- [x] Public exploit availability, from the nuclei-templates and Metasploit
  indexes.
- [x] Go-based products looked up as Go modules, for exact fixed versions
  where NVD has no version data.
- [x] Vendor security feeds, for products whose vendor announces fixes
  before the databases catch up. GitLab's is the first.
- **More vendor feeds** in the catalog.
- [x] Workarounds from the advisory, as their own field, for when upgrading
  has to wait.
- [x] Advisories for a product since a given date, so an agent can ask what
  is new without the server keeping any state.
- **Lifecycle data for the AI products** in the catalog, which have none.

## 3. Bigger inputs

- [x] Accept an SBOM or image-scanner output, which covers what is inside an
  image without this project becoming a scanner (`check_sbom`). Language
  packages are checked.
- **Operating system packages from an SBOM.** They are reported as not
  checked today, because lookups for them were not reliable.
- [x] Accept raw workload listings, such as `kubectl` output, so the agent
  does not have to pull image references out itself (`check_images`).
- [x] Larger batches: 500 images a call, grouped by product and version.
- **Progress reported** while a large batch runs.

## 4. A better MCP citizen

- [x] Prompts for the common workflows: audit a cluster, plan an upgrade,
  look into a CVE.
- [x] A resource for the catalog.
- **Resources for single advisories.**
- **OAuth authorization**, as the specification describes it, alongside the
  shared token.
- **An audit log and a metrics endpoint** for the HTTP transport.
- **A listing in the MCP registry.**

## Optional, and only with an account

The server works with no account anywhere, and that stays true. These need
one, so each would be an option that is off by default:

- **A wider exploited-in-the-wild list.** The candidate source needs an
  account token.

## Not planned

- Scanning container images or hosts.
- Keeping an inventory, watching it on a schedule, or sending alerts.
- Tools that change anything.
