# How it works

## One lookup, start to finish

```
input ──▶ resolve ──▶ OSV ─────┐
                     GitHub ───┼──▶ merge ──▶ exploited? ──▶ EPSS ──▶ priority ──▶ status
                     NVD ──────┘     (CISA KEV)
```

1. **Resolve.** The input is validated, then turned into identifiers: a
   registry package, a GitHub repository, an NVD product. Names and container
   images are looked up in the built-in catalog; explicit identifiers are
   used as given.
2. **Ask the sources that can answer.** OSV needs a registry package, GitHub
   needs a repository, NVD needs a product identifier. The three are asked at
   the same time. A source with nothing to go on is recorded as skipped.
3. **Merge.** The same advisory from two sources becomes one entry. Entries
   are matched on any shared identifier, so a GHSA record and the CVE record
   for the same flaw are combined.
4. **Mark what is exploited.** Advisories whose CVE is in CISA's Known
   Exploited Vulnerabilities catalog are flagged, with the date they were
   listed.
5. **Score.** CVE identifiers are sent to EPSS for the probability of
   exploitation in the next 30 days.
6. **Set priorities and the status.**

## Sources

| Source | Needs | Matches by | Gives |
| --- | --- | --- | --- |
| OSV | `ecosystem`, `package` | Exact version | Advisories for registry packages, including malicious-release reports |
| GitHub repository advisories | `repo` | Version ranges | The upstream project's own advisories, often before they reach OSV |
| NVD | `cpe` | Version, through NVD's product data | CVEs for products that are not registry packages |
| CISA KEV | Name and aliases | Product name | Which CVEs are being exploited |
| EPSS | CVE ids | CVE id | Likelihood of exploitation |

Without a version, OSV and GitHub return a product's whole history, and NVD
returns only the last 120 days, since a product's full history there can run
to thousands of CVEs.

### Name-only matches

CISA's catalog names a product but no versions. A match on name alone would
flag old, long-fixed vulnerabilities as urgent on every check.

So when the component has a version and an NVD product identifier, the
server asks NVD which exploited CVEs it holds version data for. One that NVD
has version data for, and did not return for the running version, does not
affect that version and is dropped. The `coverage` entry for `cisa-kev` says
how many were dropped.

A match that cannot be cleared this way is kept, marked `nameOnly`, with a
note that the version was not checked. If only name-only matches remain, the
status is `possibly_affected`.

### Backported fixes

Some projects list one open-ended range per release line: `< 1.106.9` and
`< 1.108.6`. Read literally, the second says 1.106.12 is vulnerable, although
the first fixed it on that line.

The server sets an open-ended range aside when the same advisory publishes a
fix on the running version's release line (the same major and minor numbers)
at or below it. A range with a lower bound is always taken as written.

### Version comparison

Versions are compared as dotted numbers with an optional pre-release or
post-release suffix. When a version or a range cannot be parsed, the server
does not guess: the advisory is kept, with a note that the range could not
be compared.

## Status

| Status | Given when |
| --- | --- |
| `affected` | At least one advisory was matched against the version. |
| `version_needed` | Advisories exist, but no version was given. |
| `possibly_affected` | Only name-only matches were found. |
| `unknown` | A source that applies failed, or no source can check the component by version. |
| `no_known_advisories` | Every applicable source answered, and none lists the version. |

The rule behind `unknown`: a source that could not be asked must never look
like a source that found nothing. That covers a service being down, a rate
limit, a call running out of time, and a product the server cannot identify.

If advisories were found and a source also failed, the status is still
`affected`, and the reason says the answer is incomplete.

## Priority

Priorities come from fixed rules. There is no weighted score, so each
priority can be traced to one fact, which the advisory's `rationale` states.

| Priority | Rule |
| --- | --- |
| `urgent` | Listed as exploited in the wild, or critical severity. |
| `high` | High severity, or any lower severity with an EPSS score of 10% or more. |
| `normal` | Everything else, including advisories with no published severity. |

A malicious-release report from OSV is treated as critical.

## Caching and rate limits

Responses are cached in memory and on disk, so a short-lived server process
still benefits from earlier lookups.

| Source | Kept for |
| --- | --- |
| OSV | 15 minutes |
| GitHub, latest-release lookups | 30 minutes |
| NVD, CISA KEV | 1 hour |
| EPSS | 6 hours |

NVD allows one request every six seconds without an API key, so requests to
it are queued at that pace. GitHub allows 60 requests an hour without a
token. Setting `NVD_API_KEY` and `GITHUB_TOKEN` raises both limits.

A failed request is retried twice when the failure looks temporary: a
network error, a rate-limit response, or a server error.

## Deadlines

A single check has 50 seconds, and a batch or an upgrade suggestion has 100.
These sit below the timeouts MCP clients commonly apply. When a deadline
passes, the sources that had not answered are recorded as failed and the
status becomes `unknown`, so the caller gets a marked partial answer and not
a dropped call.

## What the server will not do

- **Scan images.** It reports a product's own advisories, not those of the
  libraries and operating system packages bundled with it.
- **Guess.** A name outside the catalog is unrecognised until identifiers
  are given.
- **Judge configuration.** Whether a vulnerable feature is switched on, or
  an endpoint is reachable, is outside what advisory data can say.
- **Change anything.** Every tool is read-only.

## Security model

See [SECURITY.md](../SECURITY.md) for what the server trusts and how to
report a problem.
