# Running sec1-mcp for several teams

[deployment.md](deployment.md) covers running the server at all. This page
covers what changes when many teams share one instance: telling callers
apart, keeping one team from starving the others, and being able to see what
the service is doing.

[`deploy/kubernetes.yaml`](../deploy/kubernetes.yaml) is a starting manifest
with everything on this page switched on.

## The short version

| Concern | Setting |
| --- | --- |
| Who is calling | A token per team, in a file: `SEC1_HTTP_TOKEN_FILE` |
| Fair use | A per-team request limit: `SEC1_HTTP_RATE` |
| What happened | A JSON audit log: `-log-format json` |
| Is it healthy | Metrics on their own port: `SEC1_METRICS_ADDR` |
| Shared upstream limits | Optional keys: `GITHUB_TOKEN`, `NVD_API_KEY` |

## A token per team

A single shared token (`SEC1_HTTP_TOKEN`) cannot say who made a call, and
revoking it cuts everyone off. A token file gives each team its own:

```
# name          token
platform        4f1c...
data-science    9be2...
```

Each line is a name, whitespace, and a token of at least 16 characters.
Blank lines and lines starting with `#` are ignored. Generate tokens with
`openssl rand -hex 32`.

- **The name is what you see.** It appears in the audit log and in the
  rate-limit metric. The token itself is never logged.
- **Changes take effect without a restart.** The file is re-read when it
  changes, within a few seconds, so adding or revoking a team is an edit to
  the file, or to the Secret it is mounted from.
- **A bad edit does not lock everyone out.** If the file becomes unreadable
  or invalid, the tokens that were in force stay in force. At start-up,
  though, an invalid file stops the server, with an error that names the
  line and never shows its contents.
- **`shared` and `anonymous` are reserved names.** `shared` is the caller's
  name when `SEC1_HTTP_TOKEN` is used; both settings can be on at once.

The teams' agents send the token as `Authorization: Bearer <token>`. For
Claude Code:

```sh
claude mcp add --transport http sec1 https://sec1.example.internal/mcp \
  --header "Authorization: Bearer $SEC1_TOKEN"
```

Tokens are shared secrets, not user logins: anyone holding a team's token is
that team. The server does not implement MCP's OAuth authorization. If you
need per-person identity or single sign-on, put the service behind a proxy
that provides it.

## A request limit per team

`SEC1_HTTP_RATE` (or `-http-rate`) is the most requests each team may make
in a minute. A team may use a minute's allowance in a burst; it then refills
evenly. A request over the limit gets `429` with a `Retry-After` header, and
one team reaching its limit does not affect another.

The limit counts every MCP request, including the ones a client makes when
it connects, not only tool calls. 120 a minute is a comfortable starting
point for interactive agents.

This protects the service from one runaway agent. It is not what protects
the upstream sources; see the next section.

## Upstream limits are shared by everyone

**The server needs no account to run, and that is still true as a shared
service.** But two of its sources limit unauthenticated callers, and now
every team draws on the same allowance:

| Source | Without a key | With a key | What the key needs |
| --- | --- | --- | --- |
| NVD | One request every six seconds, for the whole service | About ten times faster | A free API key, requested from NVD by email address |
| GitHub | 60 requests an hour, for the whole service | 5,000 an hour | A GitHub account; the token needs no scopes |

Without them the service still answers correctly; it is slower, and under
load some answers come back as `unknown` because a source could not be
reached in time. Caching absorbs much of this, since teams tend to ask about
the same products. Set `NVD_API_KEY` and `GITHUB_TOKEN` when you see
`sec1_upstream_requests_total{outcome="error"}` climbing, or tool calls
taking tens of seconds.

Use an account that belongs to the service, not to a person, for these.

## The audit log

Every tool call writes one line. With `-log-format json`:

```json
{"time":"2026-11-22T12:00:00Z","level":"INFO","msg":"tool call","client":"data-science","tool":"check_sbom","outcome":"ok","duration_ms":6467}
```

| Field | Meaning |
| --- | --- |
| `client` | The token's name; `shared` for the shared token; `anonymous` when no tokens are configured. |
| `tool` | The tool called. |
| `outcome` | `ok`, or `error` when the call returned a tool error such as invalid input. |
| `duration_ms` | How long the call took. |

**The log never contains what was looked up, or the answer.** What a team
checks says what that team runs, and a shared service should not collect
that. If you need it for an investigation, the teams' own agents hold it.

Logs go to stderr, so they reach whatever collects container logs.

## Metrics

`SEC1_METRICS_ADDR` (or `-metrics`) serves Prometheus metrics at `/metrics`
on a listener of its own. That keeps them off the address that serves MCP:
they need no token, and they include team names. Expose the metrics port to
your scraper only.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `sec1_tool_calls_total` | `tool`, `outcome` | Tool calls. |
| `sec1_tool_duration_seconds` | `tool` | Histogram of how long tool calls take. |
| `sec1_http_requests_total` | `code` | Requests to the MCP endpoint by status: 200, 401, 429. |
| `sec1_rate_limited_total` | `client` | Requests refused by the rate limit, per team. |
| `sec1_upstream_requests_total` | `source`, `outcome` | Lookups to each advisory service: `cached`, `ok` or `error`. |

Queries worth having on a dashboard:

```promql
# Tool calls per second, by tool
sum by (tool) (rate(sec1_tool_calls_total[5m]))

# 95th percentile tool latency
histogram_quantile(0.95, sum by (le, tool) (rate(sec1_tool_duration_seconds_bucket[5m])))

# Share of lookups answered from the cache
sum(rate(sec1_upstream_requests_total{outcome="cached"}[15m]))
  / sum(rate(sec1_upstream_requests_total[15m]))

# Upstream failures, by source: the sign that a key is worth setting
sum by (source) (rate(sec1_upstream_requests_total{outcome="error"}[15m]))

# Teams being rate limited
sum by (client) (rate(sec1_rate_limited_total[15m]))

# Rejected credentials: a misconfigured client, or someone guessing
rate(sec1_http_requests_total{code="401"}[15m])
```

An alert on upstream failures is the useful one: when a source is failing,
answers degrade to `unknown`, which is safe but not helpful.

## Capacity

- **Memory.** The in-memory cache holds at most 128 MB of responses, the
  most recently used first. Allow about 512 MB for the container.
- **Disk.** The disk cache is pruned of files older than two days. A few
  hundred megabytes is typical; the example manifest allows 2 GB.
- **Replicas.** One replica serves many teams, because most of the time is
  spent waiting on upstream sources. More replicas work, since there are no
  sessions, but each keeps its own cache and its own queue for NVD, so they
  use the shared upstream allowance faster. Add replicas for availability,
  and set the two upstream keys when you do.
- **Request size.** A request body may be up to 8 MB, which allows a 4 MB
  bill of materials.

## Checklist

- [ ] TLS in front of the service. The token is sent on every request.
- [ ] A token per team, in a Secret, with the file readable only by the
      service.
- [ ] `SEC1_HTTP_RATE` set.
- [ ] The metrics port reachable by the scraper and not by callers.
- [ ] Outbound HTTPS allowed to the hosts listed in
      [deployment.md](deployment.md#kubernetes).
- [ ] A pinned image version, not `latest`.
- [ ] An alert on upstream failures.
