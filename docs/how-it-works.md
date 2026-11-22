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
   exploitation in the next 30 days, and looked up in two public indexes of
   scanner templates and exploit modules.
6. **Check the release line** against lifecycle data, to see whether it
   still receives fixes.
7. **Set priorities and the status.**

## Sources

| Source | Needs | Matches by | Gives |
| --- | --- | --- | --- |
| OSV | `ecosystem`, `package` | Exact version | Advisories for registry packages, including malicious-release reports |
| GitHub repository advisories | `repo` | Version ranges | The upstream project's own advisories, often before they reach OSV |
| NVD | `cpe` | Version, through NVD's product data | CVEs for products that are not registry packages |
| CISA KEV | Name and aliases | Product name | Which CVEs are being exploited |
| EPSS | CVE ids | CVE id | Likelihood of exploitation |
| nuclei-templates, Metasploit | CVE ids | CVE id | Whether a public scanner template or exploit module exists |
| endoflife.date | `lifecycle` | Release line | Whether the line still gets fixes, and the latest release |
| Vendor security feeds | `feeds` | Versions named in a title | Recent announcements, as notices to read |

Products written in Go are looked up in OSV as Go modules. That gives exact
fixed versions, and it matters most where NVD has not yet filed version data
for a CVE: for Kubernetes, OSV returns advisories that NVD cannot match to a
version at all. A Go module's path changes with its major version, so only
the module for the running version's major is asked.

endoflife.date is a community-maintained dataset. The exploit indexes are
the lists the nuclei-templates and Metasploit projects publish; presence in
one means that finding or exploiting the flaw takes no skill.

Without a version, OSV and GitHub return a product's whole history, and NVD
returns only the last 120 days, since a product's full history there can run
to thousands of CVEs.

### Name-only matches

CISA's catalog names a product but no versions. A match on name alone would
flag old, long-fixed vulnerabilities as urgent on every check.

So when a version is given, a name-only match is dropped if a source that
holds version data for that CVE has shown the version is not affected:

- the upstream repository's own advisory for the CVE excludes the version;
- OSV knows the CVE for the package and did not return it for the version;
- NVD holds version ranges for the CVE under this product and did not return
  it for the version.

The `coverage` entry for `cisa-kev` says how many were dropped.

A match that cannot be cleared this way is kept, marked `nameOnly`, with a
note that the version was not checked. If only name-only matches remain, the
status is `possibly_affected`.

### Project advisories and free-text ranges

Advisories published by a project on its own repository are free text, and
their affected ranges come in many styles:

| As written | Meaning |
| --- | --- |
| `< 1.106.9` and `< 1.108.6` | One open-ended range per release line. |
| `>= 9.2.0`, fixed in `9.2.4` | Only where the flaw starts. |
| `8.0.0 - 8.3.0` | A hyphen range, often spanning several lines. |
| `>=9.2.0 <9.2.10 >=9.3.0 <9.3.4` | Two ranges with no separator. |
| `<9.x, <8.x` | Wildcards, which cannot be compared. |

Read literally, `>= 9.2.0` covers every later release for ever, and
`< 1.108.6` says 1.106.12 is vulnerable although 1.106.9 fixed it on that
line. So the server uses the published fixes as well as the ranges, in this
order:

1. **A fix on the version's release line** (the same major and minor
   numbers): the version is fixed if it is at or above the highest such fix.
2. **A range bounded on both sides that contains the version** applies,
   unless rule 1 found a fix and the range does not start after it. A range
   that starts after the fix says the flaw came back, and is taken as
   written.
3. **No fix on its line, and the version is newer than every published
   fix:** treated as fixed. This assumes a fix is carried forward into later
   releases. It is the one assumption in the list, so the `coverage` entry
   for `github` reports how many advisories it was applied to.
4. **An open-ended range that contains the version** applies. If the
   advisory publishes no fix at all, the `note` says it may be long fixed.
5. **Otherwise** it does not apply, if every range could be read. If one
   could not, the advisory is kept with a note saying so.

### Version comparison

Versions are compared as dotted numbers with an optional pre-release or
post-release suffix. When a version or a range cannot be parsed, the server
does not guess: the advisory is kept, with a note.

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
| `high` | High severity; or any lower severity with an EPSS score of 10% or more, or with a public scanner template or exploit module. |
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
| Vendor feeds | 30 minutes |
| Lifecycle data | 12 hours |
| Exploit indexes | 24 hours |

The exploit indexes are several megabytes each, so only the CVE ids in them
are kept.

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
  are given. `find_identifiers` returns candidates and applies none.
- **Judge configuration.** Whether a vulnerable feature is switched on, or
  an endpoint is reachable, is outside what advisory data can say.
- **Change anything.** Every tool is read-only.

## Security model

See [SECURITY.md](../SECURITY.md) for what the server trusts and how to
report a problem.
